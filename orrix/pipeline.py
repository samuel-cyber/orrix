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
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Mapping

from pydantic import ValidationError

from .audit import AuditLog, OriginTag, hash_payload
from .claim_form import ClaimForm
from .discrepancy import Discrepancy, FactReference, detect_discrepancy
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
#: Synced from PayPal but the Reader has not run on it yet. Sync is
#: deliberately Reader-free so a poll costs no model credits; the Reader
#: runs once, lazily, when someone opens the case.
STATUS_AWAITING_READER = "awaiting_reader"

#: The reader "reason" recorded by a sync. Listed as transient below so the
#: first case open actually runs the model instead of reusing this.
REASON_AWAITING_READER = "awaiting_reader"

# Failures worth retrying on the next pass rather than caching.
_TRANSIENT_READER_REASONS = frozenset(
    {
        "rate_limited",
        "http_error",
        "transport_error",
        "reader_not_configured",
        REASON_AWAITING_READER,
    }
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
    built_at        TEXT NOT NULL,
    reader_pending  INTEGER NOT NULL DEFAULT 0
);
"""

#: Columns added after the table first shipped. A deployment upgrading in
#: place has the old table, so each one is added if missing rather than
#: requiring the database to be thrown away.
_MIGRATIONS = (("reader_pending", "INTEGER NOT NULL DEFAULT 0"),)


def _hydrate_discrepancy(payload: Mapping[str, Any]) -> Discrepancy | None:
    """Rebuild a Discrepancy from its stored dict form."""
    facts = payload.get("facts")
    if not isinstance(facts, list) or len(facts) != 2:
        return None
    reason, delivery = facts
    return Discrepancy(
        message=str(payload.get("message") or ""),
        dispute_reason=FactReference(
            name=str(reason.get("name", "")),
            value=reason.get("value"),
            source=str(reason.get("source", "")),
            status=str(reason.get("status", "")),
        ),
        delivery_status=FactReference(
            name=str(delivery.get("name", "")),
            value=delivery.get("value"),
            source=str(delivery.get("source", "")),
            status=str(delivery.get("status", "")),
        ),
    )


class CaseViewStore:
    """Persisted pipeline output, one row per dispute.

    Takes its path from the caller, never the environment.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        with closing(self._connect()) as connection, connection:
            connection.executescript(_SCHEMA)
            existing = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(case_views)").fetchall()
            }
            for column, definition in _MIGRATIONS:
                if column not in existing:
                    connection.execute(
                        f"ALTER TABLE case_views ADD COLUMN {column} {definition}"
                    )
                    logger.info("case_views: added missing column %s", column)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def save(self, view: "CaseView") -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                INSERT INTO case_views (
                    dispute_id, update_time, status, facts_json, reader_json,
                    discrepancy_json, decision_json, seller_input_json,
                    reader_started_at, reader_finished_at, built_at,
                    reader_pending
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    built_at = excluded.built_at,
                    reader_pending = excluded.reader_pending
                """,
                view.as_row(),
            )

    def get(self, dispute_id: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT * FROM case_views WHERE dispute_id = ?", (dispute_id,)
            ).fetchone()
        return dict(row) if row else None

    def all(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection, connection:
            rows = connection.execute("SELECT * FROM case_views").fetchall()
        return [dict(row) for row in rows]

    def count(self) -> int:
        with closing(self._connect()) as connection, connection:
            return connection.execute("SELECT COUNT(*) FROM case_views").fetchone()[0]

    def hydrate(self, row: Mapping[str, Any]) -> "CaseView | None":
        """Rebuild a CaseView from a stored row, or None if unreadable.

        Reading a row must never run the Reader or touch PayPal, so the
        queue is served entirely from here. A row that cannot be parsed
        returns None and says so, rather than throwing on a page load.
        """
        dispute_id = str(row.get("dispute_id") or "")
        try:
            facts_payload = json.loads(row.get("facts_json") or "{}")
            facts = Facts.model_validate(facts_payload) if facts_payload else None

            reader_payload = json.loads(row.get("reader_json") or "{}")
            form = None
            if reader_payload.get("form"):
                form = ClaimForm.model_validate(reader_payload["form"])
            reader_result = ReaderResult(
                form=form,
                status=reader_payload.get("status", STATUS_NEEDS_REVIEW),
                reason=reader_payload.get("reason"),
                attempts=reader_payload.get("attempts", 0) or 0,
                http_status=reader_payload.get("http_status"),
            )

            decision_payload = json.loads(row.get("decision_json") or "{}")
            decision = PolicyDecision(
                allowed_actions=frozenset(decision_payload.get("allowed_actions") or ()),
                reasons=tuple(decision_payload.get("reasons") or ()),
                flags=frozenset(decision_payload.get("flags") or ()),
            )

            discrepancy = None
            raw_discrepancy = row.get("discrepancy_json")
            if raw_discrepancy:
                discrepancy = _hydrate_discrepancy(json.loads(raw_discrepancy))

            seller_input = None
            raw_seller = row.get("seller_input_json")
            if raw_seller:
                seller_input = SellerEvidenceInput.model_validate_json(raw_seller)
        except (ValueError, TypeError, ValidationError) as error:
            logger.warning(
                "pipeline step failed dispute_id=%s step=hydrate_case_view "
                "exception=%s message=%s",
                dispute_id or "<unknown>",
                type(error).__name__,
                error,
            )
            return None

        return CaseView(
            dispute_id=dispute_id,
            update_time=row.get("update_time"),
            status=str(row.get("status") or STATUS_NO_ACTION),
            facts=facts,
            reader_result=reader_result,
            discrepancy=discrepancy,
            decision=decision,
            seller_input=seller_input,
            reader_started_at=row.get("reader_started_at"),
            reader_finished_at=row.get("reader_finished_at"),
            built_at=str(row.get("built_at") or ""),
            reader_pending=bool(row.get("reader_pending")),
        )


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
    #: True when this view was built without running the Reader, so the UI
    #: can say so and a case open knows to run it.
    reader_pending: bool = False

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
            1 if self.reader_pending else 0,
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
    STATUS_AWAITING_READER: "Awaiting reader",
    STATUS_NO_ACTION: "No action",
    STATUS_FACTS_FAILED: "Record could not be read",
}


def status_label(status: str) -> str:
    return STATUS_LABELS.get(status, status)


def _status_for(decision: PolicyDecision, reader_pending: bool = False) -> str:
    """The label an operator sees for this case.

    Order matters. An already-answered dispute is settled whatever else is
    true. An action that policy permits is worth showing even before the
    Reader has run, since the evidence path never depended on it. Only then
    does a pending Reader outrank a generic review flag, because "awaiting
    reader" tells the operator something "needs review" does not.
    """
    if FLAG_AWAITING_BUYER in decision.flags:
        return STATUS_AWAITING_BUYER
    if decision.allowed_actions:
        return STATUS_ACTION_AVAILABLE
    if reader_pending:
        return STATUS_AWAITING_READER
    if decision.requires_review:
        return STATUS_NEEDS_HUMAN_REVIEW
    return STATUS_NO_ACTION


def _failed_view(
    dispute_id: str,
    update_time: Any,
    step: str,
    error: BaseException,
    seller_input: SellerEvidenceInput | None,
    deps: PipelineDeps,
    policy_config: PolicyConfig,
) -> CaseView:
    """Record a step failure as a visible, persisted case view.

    Never swallowed: the dispute id, the step and the exception class go to
    the log at WARNING, and the case shows up in the queue as unreadable
    rather than quietly vanishing from it.
    """
    logger.warning(
        "pipeline step failed dispute_id=%s step=%s exception=%s message=%s",
        dispute_id or "<unknown>",
        step,
        type(error).__name__,
        error,
    )
    deps.audit.append(
        actor=ACTOR,
        action=f"pipeline.failed:{step}:{type(error).__name__}",
        origin_tag=OriginTag.SYSTEM,
        dispute_id=dispute_id or None,
        payload=step,
    )
    decision = decide(None, None, CaseState(dispute_id=dispute_id), policy_config)
    view = CaseView(
        dispute_id=dispute_id,
        update_time=update_time if isinstance(update_time, str) else None,
        status=STATUS_FACTS_FAILED,
        facts=None,
        reader_result=ReaderResult(
            form=None, status=STATUS_NEEDS_REVIEW, reason=f"{step}_failed"
        ),
        discrepancy=None,
        decision=decision,
        seller_input=seller_input,
        built_at=datetime.now(timezone.utc).isoformat(),
    )
    deps.case_views.save(view)
    return view


def sync_case(
    snapshot: Mapping[str, Any],
    deps: PipelineDeps,
    seller_input: SellerEvidenceInput | None = None,
    case_state: CaseState | None = None,
) -> CaseView:
    """Build and persist a case view WITHOUT running the Reader.

    This is what a poll or a webhook calls. It gives the queue everything it
    needs -- facts, policy, the discrepancy -- at no model cost, which is
    the point: a 60-second poll over five disputes must not spend credits.
    The Reader runs later, once, when someone opens the case.
    """
    dispute_id = str(snapshot.get("dispute_id") or "")
    update_time = snapshot.get("update_time")
    policy_config = deps.policy_config

    try:
        facts = build_facts(
            snapshot, seller_input=seller_input, expected_dispute_id=dispute_id or None
        )
    except Exception as error:
        return _failed_view(
            dispute_id, update_time, "build_facts", error, seller_input, deps, policy_config
        )

    try:
        discrepancy = detect_discrepancy(facts)
        decision = decide(
            facts, None, case_state or CaseState(dispute_id=dispute_id), policy_config
        )
    except Exception as error:
        return _failed_view(
            dispute_id, update_time, "decide", error, seller_input, deps, policy_config
        )

    view = CaseView(
        dispute_id=dispute_id,
        update_time=update_time if isinstance(update_time, str) else None,
        status=_status_for(decision, reader_pending=True),
        facts=facts,
        # Recorded as pending rather than as a reader failure, and listed as
        # transient so the first case open really does call the model.
        reader_result=ReaderResult(
            form=None, status=STATUS_NEEDS_REVIEW, reason=REASON_AWAITING_READER
        ),
        discrepancy=discrepancy,
        decision=decision,
        seller_input=seller_input,
        built_at=datetime.now(timezone.utc).isoformat(),
        reader_pending=True,
    )

    try:
        deps.case_views.save(view)
    except Exception as error:
        return _failed_view(
            dispute_id, update_time, "save_case_view", error, seller_input, deps, policy_config
        )

    deps.audit.append(
        actor=ACTOR,
        action="pipeline.synced",
        origin_tag=OriginTag.PAYPAL_RECORD,
        dispute_id=dispute_id,
        payload_hash=hash_payload(json.loads(facts.model_dump_json())),
    )
    logger.info(
        "pipeline synced dispute_id=%s status=%s reader=pending flags=%s",
        dispute_id,
        view.status,
        sorted(decision.flags),
    )
    return view


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
