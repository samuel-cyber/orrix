"""The only module allowed PayPal write calls."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from .approval import Approval, DisputeVersion
from .audit import AuditLog, OriginTag, hash_payload
from .facts import Facts, FactsIntegrityError, FactStatus, build_facts
from .paypal_write import PayPalWriteError, SandboxPayPalWriter
from .policy import PROVIDE_EVIDENCE, CaseState, PolicyConfig, decide

ACTOR = "executor"

# Fixed template. Every value comes from a confirmed Fact; there is no
# parameter here a reader, a model or a buyer could reach.
EVIDENCE_NOTE = "Tracking information submitted from the merchant's PayPal transaction record."

STATUS_EXECUTED = "executed"
STATUS_REFUSED = "refused"
STATUS_UNCONFIRMED = "unconfirmed"
STATUS_WRITE_FAILED = "write_failed"

REASON_DISPUTE_ID_MISMATCH = "dispute_id_mismatch"
REASON_STALE_APPROVAL = "stale_approval"
REASON_ACTION_NOT_ALLOWED = "action_not_allowed"
REASON_ALREADY_EXECUTED = "already_executed"
REASON_PAYLOAD_MISMATCH = "payload_mismatch"
REASON_APPROVAL_TAMPERED = "approval_tampered"
REASON_UNSUPPORTED_ACTION = "unsupported_action"
REASON_FETCH_FAILED = "fetch_failed"
REASON_FACTS_FAILED = "facts_failed"
REASON_EVIDENCE_NOT_RECORDED = "evidence_not_recorded"
REASON_WRITE_FAILED = "write_failed"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS executed_approvals (
    approval_id TEXT PRIMARY KEY,
    dispute_id  TEXT NOT NULL,
    action      TEXT NOT NULL,
    claimed_at  TEXT NOT NULL
);
"""


class ExecutedApprovals:
    """Which approvals have been acted on. Claimed before the write.

    Claiming first means a crash between claim and write can leave an
    approval unexecuted, which a human can see and re-approve. The opposite
    order could produce a second write, which is unrecoverable.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        with self._connect() as connection:
            connection.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def claim(self, approval_id: str, dispute_id: str, action: str) -> bool:
        """Atomically claim an approval. False means it was already claimed."""
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO executed_approvals
                    (approval_id, dispute_id, action, claimed_at)
                VALUES (?, ?, ?, ?)
                """,
                (approval_id, dispute_id, action, datetime.now(timezone.utc).isoformat()),
            )
            return cursor.rowcount == 1

    def was_executed(self, approval_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM executed_approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            return row is not None

    def count(self) -> int:
        with self._connect() as connection:
            return connection.execute("SELECT COUNT(*) FROM executed_approvals").fetchone()[0]


@dataclass(frozen=True)
class ExecutorDeps:
    """Services the executor needs, supplied by the caller.

    No environment is read here: the reader client, the writer, the audit log
    and the executed-approval store are all constructed outside and injected.
    """

    paypal_reader: Any
    writer: SandboxPayPalWriter
    audit: AuditLog
    executed: ExecutedApprovals
    policy_config: PolicyConfig = field(default_factory=PolicyConfig)


@dataclass(frozen=True)
class ExecutionResult:
    status: str
    reason: str | None = None
    approval_id: str | None = None
    writes_attempted: int = 0
    requires_review: bool = False
    debug_id: str | None = None

    @property
    def executed(self) -> bool:
        return self.status == STATUS_EXECUTED


def build_evidence_payload(facts: Facts) -> dict[str, Any]:
    """Build the evidence body from Facts alone, via a fixed template.

    Only the tracking carrier and number are interpolated, and only when both
    are confirmed facts drawn from the PayPal record. No claim form, no model
    output and no buyer text has a path into this function.
    """
    if not isinstance(facts, Facts):
        raise ValueError("evidence payload requires Facts")

    for name in ("tracking_carrier", "tracking_number"):
        if facts.status(name) is not FactStatus.CONFIRMED:
            raise ValueError(f"cannot build evidence payload: {name} is not confirmed")

    return {
        "evidences": [
            {
                "evidence_type": "PROOF_OF_FULFILLMENT",
                "evidence_info": {
                    "tracking_info": [
                        {
                            "carrier_name": facts.value("tracking_carrier"),
                            "tracking_number": facts.value("tracking_number"),
                        }
                    ]
                },
                "notes": EVIDENCE_NOTE,
            }
        ]
    }


def count_seller_evidence(snapshot: Mapping[str, Any], tracking_number: str) -> int:
    """How many seller-submitted proof entries carry this tracking number."""
    evidences = snapshot.get("evidences")
    if not isinstance(evidences, list):
        return 0

    count = 0
    for evidence in evidences:
        if not isinstance(evidence, Mapping):
            continue
        if evidence.get("evidence_type") != "PROOF_OF_FULFILLMENT":
            continue
        if evidence.get("source") != "SUBMITTED_BY_SELLER":
            continue
        tracking_info = evidence.get("evidence_info", {})
        if not isinstance(tracking_info, Mapping):
            continue
        entries = tracking_info.get("tracking_info")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, Mapping) and entry.get("tracking_number") == tracking_number:
                count += 1
    return count


def _evidence_was_added(
    before: Mapping[str, Any], after: Mapping[str, Any], tracking_number: str
) -> bool:
    """Confirm the submission actually landed. A 2xx alone is not a pass.

    Compared against the pre-write record rather than checked in isolation:
    a dispute that already carried this tracking number would otherwise
    confirm a write that never happened.
    """
    return count_seller_evidence(after, tracking_number) > count_seller_evidence(
        before, tracking_number
    )


def execute(approval: Approval, deps: ExecutorDeps) -> ExecutionResult:
    """Carry out one approved action, or refuse and say why.

    Every refusal and every step is audit-logged. The only write this
    function can make is provide_evidence, and it only makes it when the
    fresh record still matches the approved version and fresh policy still
    permits the action.
    """
    audit = deps.audit

    def log(action: str, origin: OriginTag, payload: Any = None) -> None:
        audit.append(
            actor=ACTOR,
            action=action,
            origin_tag=origin,
            dispute_id=getattr(approval, "dispute_id", None),
            payload=payload,
        )

    if not isinstance(approval, Approval):
        return ExecutionResult(status=STATUS_REFUSED, reason="not_an_approval", requires_review=True)

    log("execute.start", OriginTag.SELLER_APPROVAL, approval.approval_id)

    # The approval must still hash to its own contents.
    if not approval.is_intact():
        log("execute.refused:" + REASON_APPROVAL_TAMPERED, OriginTag.SELLER_APPROVAL)
        return ExecutionResult(
            status=STATUS_REFUSED,
            reason=REASON_APPROVAL_TAMPERED,
            approval_id=approval.approval_id,
            requires_review=True,
        )

    if approval.action != PROVIDE_EVIDENCE:
        log("execute.refused:" + REASON_UNSUPPORTED_ACTION, OriginTag.SYSTEM)
        return ExecutionResult(
            status=STATUS_REFUSED,
            reason=REASON_UNSUPPORTED_ACTION,
            approval_id=approval.approval_id,
            requires_review=True,
        )

    # (a) re-fetch
    try:
        snapshot = deps.paypal_reader.get_dispute(approval.dispute_id)
    except Exception:
        log("execute.refused:" + REASON_FETCH_FAILED, OriginTag.PAYPAL_RECORD)
        return ExecutionResult(
            status=STATUS_REFUSED,
            reason=REASON_FETCH_FAILED,
            approval_id=approval.approval_id,
            requires_review=True,
        )
    log("execute.refetched", OriginTag.PAYPAL_RECORD, snapshot.get("update_time"))

    # (b) identity and freshness
    if snapshot.get("dispute_id") != approval.dispute_id:
        log("execute.refused:" + REASON_DISPUTE_ID_MISMATCH, OriginTag.PAYPAL_RECORD)
        return ExecutionResult(
            status=STATUS_REFUSED,
            reason=REASON_DISPUTE_ID_MISMATCH,
            approval_id=approval.approval_id,
            requires_review=True,
        )

    if not approval.matches_version(snapshot):
        log("execute.refused:" + REASON_STALE_APPROVAL, OriginTag.PAYPAL_RECORD)
        return ExecutionResult(
            status=STATUS_REFUSED,
            reason=REASON_STALE_APPROVAL,
            approval_id=approval.approval_id,
            requires_review=True,
        )

    # (c) fresh policy check against the fresh record
    try:
        facts = build_facts(snapshot, expected_dispute_id=approval.dispute_id)
    except FactsIntegrityError:
        log("execute.refused:" + REASON_FACTS_FAILED, OriginTag.PAYPAL_RECORD)
        return ExecutionResult(
            status=STATUS_REFUSED,
            reason=REASON_FACTS_FAILED,
            approval_id=approval.approval_id,
            requires_review=True,
        )

    case_state = CaseState(dispute_id=approval.dispute_id)
    decision = decide(facts, None, case_state, deps.policy_config)
    if not decision.permits(approval.action):
        log("execute.refused:" + REASON_ACTION_NOT_ALLOWED, OriginTag.SYSTEM, decision.reasons)
        return ExecutionResult(
            status=STATUS_REFUSED,
            reason=REASON_ACTION_NOT_ALLOWED,
            approval_id=approval.approval_id,
            requires_review=True,
        )

    # The approved payload must be exactly what Facts produce now.
    expected_payload = build_evidence_payload(facts)
    if hash_payload(expected_payload) != hash_payload(approval.payload):
        log("execute.refused:" + REASON_PAYLOAD_MISMATCH, OriginTag.SELLER_APPROVAL)
        return ExecutionResult(
            status=STATUS_REFUSED,
            reason=REASON_PAYLOAD_MISMATCH,
            approval_id=approval.approval_id,
            requires_review=True,
        )

    # (d) idempotency: claim before writing.
    if not deps.executed.claim(approval.approval_id, approval.dispute_id, approval.action):
        log("execute.refused:" + REASON_ALREADY_EXECUTED, OriginTag.SYSTEM)
        return ExecutionResult(
            status=STATUS_REFUSED,
            reason=REASON_ALREADY_EXECUTED,
            approval_id=approval.approval_id,
        )

    # (e) the write. Payload comes from Facts, request id is the approval id.
    log("execute.write.start", OriginTag.PAYPAL_RECORD, expected_payload)
    try:
        write_result = deps.writer.provide_evidence(
            approval.dispute_id, expected_payload, approval.approval_id
        )
    except PayPalWriteError as error:
        log("execute.write.failed", OriginTag.PAYPAL_RECORD, error.status_code)
        return ExecutionResult(
            status=STATUS_WRITE_FAILED,
            reason=REASON_WRITE_FAILED,
            approval_id=approval.approval_id,
            writes_attempted=1,
            requires_review=True,
            debug_id=error.debug_id,
        )
    log("execute.write.ok", OriginTag.PAYPAL_RECORD, write_result.status_code)

    # (f) confirm it landed.
    try:
        confirmation = deps.paypal_reader.get_dispute(approval.dispute_id)
    except Exception:
        log("execute.unconfirmed:" + REASON_FETCH_FAILED, OriginTag.PAYPAL_RECORD)
        return ExecutionResult(
            status=STATUS_UNCONFIRMED,
            reason=REASON_FETCH_FAILED,
            approval_id=approval.approval_id,
            writes_attempted=1,
            requires_review=True,
            debug_id=write_result.debug_id,
        )

    tracking_number = facts.value("tracking_number")
    if not _evidence_was_added(snapshot, confirmation, tracking_number):
        log("execute.unconfirmed:" + REASON_EVIDENCE_NOT_RECORDED, OriginTag.PAYPAL_RECORD)
        return ExecutionResult(
            status=STATUS_UNCONFIRMED,
            reason=REASON_EVIDENCE_NOT_RECORDED,
            approval_id=approval.approval_id,
            writes_attempted=1,
            requires_review=True,
            debug_id=write_result.debug_id,
        )

    log("execute.confirmed", OriginTag.PAYPAL_RECORD, tracking_number)
    return ExecutionResult(
        status=STATUS_EXECUTED,
        approval_id=approval.approval_id,
        writes_attempted=1,
        debug_id=write_result.debug_id,
    )
