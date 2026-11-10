"""The only module allowed PayPal write calls."""

from __future__ import annotations

import logging
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from .approval import Approval, DisputeVersion
from .audit import AuditLog, OriginTag, hash_payload
from .facts import Facts, FactsIntegrityError, FactStatus, build_facts
from .paypal_write import (
    SANDBOX_BASE_URL,
    PayPalWriteConfig,
    PayPalWriteError,
    SandboxPayPalWriter,
)
from .orders import apply_matched
from .policy import PROVIDE_EVIDENCE, CaseState, PolicyConfig, decide
from .seller_input import SellerEvidenceInput

logger = logging.getLogger("orrix.executor")

ACTOR = "executor"

# Fixed template. The only values interpolated are the carrier and tracking
# number, both drawn from Facts. There is no parameter here a reader, a model
# or a buyer could reach.
EVIDENCE_NOTE_TEMPLATE = "Tracking supplied by seller: {carrier} {number}."

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
REASON_STALE_LEDGER = "stale_ledger"
REASON_STALE_CARRIER = "stale_carrier"
REASON_CONFIRMATION_NOT_STORED = "confirmation_not_stored"

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
        with closing(self._connect()) as connection, connection:
            connection.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def claim(self, approval_id: str, dispute_id: str, action: str) -> bool:
        """Atomically claim an approval. False means it was already claimed."""
        with closing(self._connect()) as connection, connection:
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
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT 1 FROM executed_approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            return row is not None

    def latest_for(self, dispute_id: str, action: str | None = None) -> dict[str, Any] | None:
        """The most recent claimed approval for a dispute, or None.

        A read, and the durable answer to "has Orrix already acted on this
        case". The console uses it so the page reflects what was done even
        after a restart, when the in-memory result of the last execution is
        gone.
        """
        query = "SELECT * FROM executed_approvals WHERE dispute_id = ?"
        params: list[Any] = [dispute_id]
        if action is not None:
            query += " AND action = ?"
            params.append(action)
        query += " ORDER BY claimed_at DESC, approval_id DESC LIMIT 1"

        with closing(self._connect()) as connection, connection:
            row = connection.execute(query, params).fetchone()
        return dict(row) if row else None

    def count(self) -> int:
        with closing(self._connect()) as connection, connection:
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
    #: The validated seller submission this approval was built from, when the
    #: tracking came from the seller rather than the PayPal record. Rebuilding
    #: Facts without it would change the payload and refuse the approval.
    seller_input: SellerEvidenceInput | None = None
    #: The seller's ledger. When present, a matched row is overlaid onto the
    #: freshly built Facts -- exactly as the approval endpoint did -- so the
    #: payload rebuilds. When the approval names a row and version, that row
    #: must still be at that version or the write is refused.
    order_ledger: Any | None = None
    #: The carrier reading as it stands now, as two plain strings supplied by
    #: the caller. Deliberately not a carrier object and deliberately not
    #: fetched here: the executor makes no carrier call, and this module
    #: imports nothing from orrix.carrier, so removing that module changes
    #: neither this file nor an approval id. Both None whenever the connector
    #: is off, which matches every approval created with it off.
    carrier_status: str | None = None
    carrier_checked_at: str | None = None
    #: Where the confirming re-fetch is persisted. Called with
    #: (dispute_id, snapshot) once the write is confirmed, and expected to
    #: store the snapshot and rebuild the case view.
    #:
    #: Injected rather than reached for: this module must not resolve a
    #: database path of its own. orrix/store.py once read the environment
    #: directly and the poller wrote one file while the console read
    #: another; a writer that picks its own path would reintroduce exactly
    #: that. The web layer passes Services.persist_confirmed_snapshot.
    persist_confirmation: Callable[[str, Mapping[str, Any]], Any] | None = None


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


def build_writer(
    token_provider: Callable[[], str],
    base_url: str = SANDBOX_BASE_URL,
    timeout: float = 60.0,
    session: Any | None = None,
) -> SandboxPayPalWriter:
    """Construct the writer. The only factory for write capability.

    Callers that need a writer go through here rather than importing
    orrix.paypal_write, which keeps write capability in exactly one module.
    tests/test_boundaries.py enforces that.
    """
    return SandboxPayPalWriter(
        config=PayPalWriteConfig(base_url=base_url, timeout=timeout),
        token_provider=token_provider,
        session=session,
    )


def build_evidence_payload(facts: Facts) -> dict[str, Any]:
    """Build the evidence body from Facts alone, via a fixed template.

    Only the carrier, the tracking number and an asserted delivery date are
    interpolated, each from a usable Fact — confirmed by the PayPal record or
    asserted by the seller through the validated SellerEvidenceInput schema.
    No claim form, no model output and no buyer text has a path in here.
    """
    if not isinstance(facts, Facts):
        raise ValueError("evidence payload requires Facts")

    for name in ("tracking_carrier", "tracking_number"):
        if not facts.get(name).is_usable:
            raise ValueError(f"cannot build evidence payload: {name} is not usable")

    carrier = facts.value("tracking_carrier")
    number = facts.value("tracking_number")

    tracking_entry: dict[str, Any] = {"carrier_name": carrier, "tracking_number": number}

    # The seller's delivery date, when asserted. Nothing else from the
    # seller's submission reaches the payload.
    delivered_on = facts.value("delivered_on")
    if delivered_on:
        tracking_entry["delivered_date"] = delivered_on

    return {
        "evidences": [
            {
                "evidence_type": "PROOF_OF_FULFILLMENT",
                "evidence_info": {"tracking_info": [tracking_entry]},
                "notes": EVIDENCE_NOTE_TEMPLATE.format(carrier=carrier, number=number),
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


def _persist_confirmation(
    deps: ExecutorDeps, dispute_id: str, confirmation: Mapping[str, Any]
) -> bool:
    """Store the confirming re-fetch as the case's record. True on success.

    No sink injected means nothing to persist against -- a replay harness or
    a one-off script -- which is reported as success because there is no
    console to leave stale. Production always has one; there is a test that
    Services.executor_deps supplies it.
    """
    sink = deps.persist_confirmation
    if sink is None:
        return True

    try:
        sink(dispute_id, confirmation)
    except Exception as error:  # noqa: BLE001 - the write already landed
        logger.warning(
            "could not store the confirmed record dispute_id=%s exception=%s message=%s",
            dispute_id,
            type(error).__name__,
            error,
        )
        return False
    return True


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
        facts = build_facts(
            snapshot,
            seller_input=deps.seller_input,
            expected_dispute_id=approval.dispute_id,
        )
    except FactsIntegrityError:
        log("execute.refused:" + REASON_FACTS_FAILED, OriginTag.PAYPAL_RECORD)
        return ExecutionResult(
            status=STATUS_REFUSED,
            reason=REASON_FACTS_FAILED,
            approval_id=approval.approval_id,
            requires_review=True,
        )

    # The seller's ledger, overlaid exactly as the approval endpoint overlaid
    # it. When the approval named a row and version, that row must still be
    # present at that version: a moved or removed row refuses the write
    # rather than silently authorising a different shipment.
    matched_row = None
    if deps.order_ledger is not None:
        facts, matched_row = apply_matched(deps.order_ledger, facts)

    if approval.ledger_row_id is not None:
        if (
            matched_row is None
            or matched_row.row_id != approval.ledger_row_id
            or matched_row.version != approval.ledger_row_version
        ):
            log("execute.refused:" + REASON_STALE_LEDGER, OriginTag.SYSTEM)
            return ExecutionResult(
                status=STATUS_REFUSED,
                reason=REASON_STALE_LEDGER,
                approval_id=approval.approval_id,
                requires_review=True,
            )

    # The carrier reading the seller approved against must still be the
    # reading on hand. An approval with no carrier binding skips this
    # entirely, so nothing changes for a deployment with the connector off.
    if approval.carrier_status is not None:
        if (
            approval.carrier_status != deps.carrier_status
            or approval.carrier_checked_at != deps.carrier_checked_at
        ):
            log("execute.refused:" + REASON_STALE_CARRIER, OriginTag.SYSTEM)
            return ExecutionResult(
                status=STATUS_REFUSED,
                reason=REASON_STALE_CARRIER,
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

    # (g) the confirmed record becomes the case's record.
    #
    # This re-fetch is the newest truth Orrix has about the dispute: it is
    # the one that proved the evidence landed. Discarding it left the console
    # showing the pre-execution record -- evidence_submitted false, the old
    # status, the Approve button still live -- immediately after reporting a
    # confirmed submission.
    #
    # Persisted before the confirming audit entry is appended, so there is no
    # ordering in which the chain says "confirmed" while the stored record
    # still predates the write.
    persisted = _persist_confirmation(deps, approval.dispute_id, confirmation)
    if not persisted:
        # The write happened and is confirmed; only the console's copy is
        # behind. Say so loudly rather than reporting a clean success.
        log("execute.confirmed_unpersisted", OriginTag.PAYPAL_RECORD, tracking_number)
        return ExecutionResult(
            status=STATUS_EXECUTED,
            reason=REASON_CONFIRMATION_NOT_STORED,
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
