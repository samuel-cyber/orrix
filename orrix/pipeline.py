"""Plain orchestration: record in, case view out.

Runs the stages in order and persists what a human needs to see. It holds no
judgement of its own: Facts come from the record, the policy decision comes
from policy, and the Reader's output is carried as display data only.

The Reader can never influence what gets sent to PayPal. The evidence
payload is built from Facts by the executor, and this module never passes
reader output into it.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Mapping

from pydantic import ValidationError

from .audit import AuditLog, OriginTag, hash_payload
from .claim_form import ClaimForm
from .discrepancy import Discrepancy, detect_discrepancy
from .facts import Facts, FactsIntegrityError, build_facts
from .policy import FLAG_AWAITING_BUYER, CaseState, PolicyConfig, PolicyDecision, decide
from .reader import (
    REASON_NOT_CONFIGURED,
    STATUS_NEEDS_REVIEW,
    ReaderConfig,
    ReaderResult,
    extract_buyer_text,
    read_claim,
)
from .seller_input import SellerEvidenceInput

logger = logging.getLogger("orrix.pipeline")

ACTOR = "pipeline"

STATUS_ACTION_AVAILABLE = "action_available"
STATUS_NEEDS_HUMAN_REVIEW = "needs_human_review"
STATUS_NO_ACTION = "no_action"
STATUS_AWAITING_BUYER = "evidence_submitted_waiting_for_buyer"
STATUS_FACTS_FAILED = "facts_failed"

# Failures worth retrying on the next pass rather than caching.
_TRANSIENT_READER_REASONS = frozenset(
    {"rate_limited", "http_error", "transport_error", "reader_not_configured"}
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS case_views (
    dispute_id      TEXT PRIMARY KEY,
    update_time     TEXT,
    status          TEXT NOT NULL,
    facts_json      TEXT NOT NULL,
    reader_json     TEXT NOT NULL,
    discrepancy_json TEXT,
    decision_json   TEXT NOT NULL,
    seller_input_json TEXT,
    reader_started_at  TEXT,
    reader_finished_at TEXT,
    built_at        TEXT NOT NULL
);
"""


class CaseViewStore:
    """Persisted pipeline output, one row per dispute.

    Takes its path from the caller, never the environment.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        with self._connect() as connection:
            connection.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def save(self, view: "CaseView") -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO case_views (
                    dispute_id, update_time, status, facts_json, reader_json,
                    discrepancy_json, decision_json, seller_input_json,
                    reader_started_at, reader_finished_at, built_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(dispute_id) DO UPDATE SET
                    update_time = excluded.update_time,
                    status = excluded.status,
                    facts_json = excluded.facts_json,
                    reader_json = excluded.reader_json,
                    discrepancy_json = excluded.discrepancy_json,
                    decision_json = excluded.decision_json,
                    seller_input_json = excluded.seller_input_json,
                    reader_started_at = excluded.reader_started_at,
                    reader_finished_at = excluded.reader_finished_at,
                    built_at = excluded.built_at
                """,
                view.as_row(),
            )

    def get(self, dispute_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM case_views WHERE dispute_id = ?", (dispute_id,)
            ).fetchone()
        return dict(row) if row else None

    def all(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM case_views").fetchall()
        return [dict(row) for row in rows]

    def count(self) -> int:
        with self._connect() as connection:
            return connection.execute("SELECT COUNT(*) FROM case_views").fetchone()[0]


@dataclass(frozen=True)
class CaseView:
    """What the UI shows for one dispute. Display data, not authority."""

    dispute_id: str
    update_time: str | None
    status: str
    facts: Facts | None
    reader_result: ReaderResult
    discrepancy: Discrepancy | None
    decision: PolicyDecision
    seller_input: SellerEvidenceInput | None = None
    reader_started_at: str | None = None
    reader_finished_at: str | None = None
    built_at: str = ""

    def as_row(self) -> tuple:
        return (
            self.dispute_id,
            self.update_time,
            self.status,
            json.dumps(
                json.loads(self.facts.model_dump_json()) if self.facts else {},
                sort_keys=True,
            ),
            json.dumps(
                {
                    "status": self.reader_result.status,
                    "reason": self.reader_result.reason,
                    "attempts": self.reader_result.attempts,
                    "http_status": self.reader_result.http_status,
                    "form": (
                        json.loads(self.reader_result.form.model_dump_json())
                        if self.reader_result.form
                        else None
                    ),
                },
                sort_keys=True,
            ),
            json.dumps(self.discrepancy.as_dict()) if self.discrepancy else None,
            json.dumps(
                {
                    "allowed_actions": sorted(self.decision.allowed_actions),
                    "reasons": list(self.decision.reasons),
                    "flags": sorted(self.decision.flags),
                },
                sort_keys=True,
            ),
            self.seller_input.model_dump_json() if self.seller_input else None,
            self.reader_started_at,
            self.reader_finished_at,
            self.built_at or datetime.now(timezone.utc).isoformat(),
        )


@dataclass(frozen=True)
class PipelineDeps:
    """Services the pipeline needs, built once at startup and injected."""

    audit: AuditLog
    case_views: CaseViewStore
    policy_config: PolicyConfig = field(default_factory=PolicyConfig)
    reader_config: ReaderConfig | None = None
    reader_client: Any | None = None


def _dispute_amount(facts: Facts | None) -> Decimal:
    if facts is None:
        return Decimal("0")
    value = facts.value("dispute_amount")
    return value if isinstance(value, Decimal) else Decimal("0")


#: Human-readable label per status, for the UI.
STATUS_LABELS = {
    STATUS_ACTION_AVAILABLE: "Action available",
    STATUS_NEEDS_HUMAN_REVIEW: "Needs human review",
    STATUS_AWAITING_BUYER: "Evidence submitted, waiting for buyer",
    STATUS_NO_ACTION: "No action",
    STATUS_FACTS_FAILED: "Record could not be read",
}


def status_label(status: str) -> str:
    return STATUS_LABELS.get(status, status)


def _status_for(decision: PolicyDecision) -> str:
    if decision.allowed_actions:
        return STATUS_ACTION_AVAILABLE
    # A dispute Orrix has already answered is settled, not incomplete. This
    # is checked before the review flag so it is never mislabelled.
    if FLAG_AWAITING_BUYER in decision.flags:
        return STATUS_AWAITING_BUYER
    if decision.requires_review:
        return STATUS_NEEDS_HUMAN_REVIEW
    return STATUS_NO_ACTION


def _cached_reader_result(
    deps: PipelineDeps, dispute_id: str, update_time: Any
) -> tuple[ReaderResult, str | None, str | None] | None:
    """A stored reader result for this exact dispute version, if any.

    Reused so that rendering a page, or listing the queue, does not spend a
    model call per view. A changed update_time means a changed record and
    earns a fresh read.
    """
    if not dispute_id or not isinstance(update_time, str):
        return None

    row = deps.case_views.get(dispute_id)
    if not row or row.get("update_time") != update_time:
        return None

    try:
        stored = json.loads(row["reader_json"] or "{}")
    except (ValueError, TypeError):
        return None
    if not stored:
        return None

    # A transient failure should be retried rather than cached.
    if stored.get("reason") in _TRANSIENT_READER_REASONS:
        return None

    form = None
    if stored.get("form"):
        try:
            form = ClaimForm.model_validate(stored["form"])
        except ValidationError:
            return None

    return (
        ReaderResult(
            form=form,
            status=stored.get("status", STATUS_NEEDS_REVIEW),
            reason=stored.get("reason"),
            attempts=stored.get("attempts", 0) or 0,
            http_status=stored.get("http_status"),
        ),
        row.get("reader_started_at"),
        row.get("reader_finished_at"),
    )


def process_case(
    snapshot: Mapping[str, Any],
    deps: PipelineDeps,
    seller_input: SellerEvidenceInput | None = None,
    case_state: CaseState | None = None,
    reuse_reader: bool = True,
) -> CaseView:
    """Run the pipeline over one freshly fetched dispute record.

    Called when a snapshot is stored or its update_time changes. Each stage
    is audit-logged with the origin of the data it handled; buyer text is
    logged as a hash and a length, never as text.
    """
    dispute_id = str(snapshot.get("dispute_id") or "")
    update_time = snapshot.get("update_time")
    audit = deps.audit

    # -- facts, from the record (and the seller's submission) ------------
    try:
        facts = build_facts(snapshot, seller_input=seller_input, expected_dispute_id=dispute_id or None)
    except FactsIntegrityError as error:
        audit.append(
            actor=ACTOR,
            action="pipeline.facts_failed",
            origin_tag=OriginTag.PAYPAL_RECORD,
            dispute_id=dispute_id or None,
            payload=str(error),
        )
        decision = decide(None, None, case_state or CaseState(dispute_id=dispute_id), deps.policy_config)
        view = CaseView(
            dispute_id=dispute_id,
            update_time=update_time if isinstance(update_time, str) else None,
            status=STATUS_FACTS_FAILED,
            facts=None,
            reader_result=ReaderResult(
                form=None, status=STATUS_NEEDS_REVIEW, reason="facts_failed"
            ),
            discrepancy=None,
            decision=decision,
            seller_input=seller_input,
            built_at=datetime.now(timezone.utc).isoformat(),
        )
        deps.case_views.save(view)
        return view

    audit.append(
        actor=ACTOR,
        action="pipeline.facts_built",
        origin_tag=OriginTag.PAYPAL_RECORD,
        dispute_id=dispute_id,
        payload_hash=hash_payload(json.loads(facts.model_dump_json())),
    )

    # -- buyer text, read in exactly one place ---------------------------
    buyer_text = extract_buyer_text(snapshot)
    audit.append(
        actor=ACTOR,
        action=f"pipeline.buyer_text_extracted:chars={len(buyer_text)}",
        origin_tag=OriginTag.BUYER_TEXT,
        dispute_id=dispute_id,
        payload_hash=hash_payload(buyer_text),
    )

    # -- the reader. Advisory only; its output never reaches a payload ---
    reader_started_at: str | None = None
    reader_finished_at: str | None = None

    # A model call costs money and the record has not changed, so reuse the
    # stored result rather than re-reading on every page load. Only a new
    # update_time earns a fresh read.
    cached = _cached_reader_result(deps, dispute_id, update_time) if reuse_reader else None

    if cached is not None:
        reader_result, reader_started_at, reader_finished_at = cached
    elif deps.reader_config is None:
        reader_result = ReaderResult(
            form=None, status=STATUS_NEEDS_REVIEW, reason=REASON_NOT_CONFIGURED
        )
    else:
        reader_started_at = datetime.now(timezone.utc).isoformat()
        reader_result = read_claim(
            buyer_text,
            _dispute_amount(facts),
            deps.reader_config,
            deps.reader_client,
        )
        reader_finished_at = datetime.now(timezone.utc).isoformat()

    audit.append(
        actor=ACTOR,
        action=f"pipeline.reader:{reader_result.status}:{reader_result.reason or 'ok'}",
        origin_tag=OriginTag.READER_OUTPUT,
        dispute_id=dispute_id,
        payload_hash=hash_payload(
            json.loads(reader_result.form.model_dump_json()) if reader_result.form else None
        ),
    )

    # -- discrepancy and decision, both plain code -----------------------
    discrepancy = detect_discrepancy(facts)
    if discrepancy is not None:
        audit.append(
            actor=ACTOR,
            action="pipeline.discrepancy_detected",
            origin_tag=OriginTag.SYSTEM,
            dispute_id=dispute_id,
            payload=discrepancy.as_dict(),
        )

    decision = decide(
        facts,
        reader_result,
        case_state or CaseState(dispute_id=dispute_id),
        deps.policy_config,
    )
    audit.append(
        actor=ACTOR,
        action=f"pipeline.decided:{','.join(sorted(decision.allowed_actions)) or 'none'}",
        origin_tag=OriginTag.SYSTEM,
        dispute_id=dispute_id,
        payload={"reasons": list(decision.reasons), "flags": sorted(decision.flags)},
    )

    view = CaseView(
        dispute_id=dispute_id,
        update_time=update_time if isinstance(update_time, str) else None,
        status=_status_for(decision),
        facts=facts,
        reader_result=reader_result,
        discrepancy=discrepancy,
        decision=decision,
        seller_input=seller_input,
        reader_started_at=reader_started_at,
        reader_finished_at=reader_finished_at,
        built_at=datetime.now(timezone.utc).isoformat(),
    )
    deps.case_views.save(view)

    logger.info(
        "pipeline dispute_id=%s status=%s actions=%s flags=%s",
        dispute_id,
        view.status,
        sorted(decision.allowed_actions),
        sorted(decision.flags),
    )
    return view
