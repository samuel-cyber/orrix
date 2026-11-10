"""Explicit seller approval: the only thing that authorises a write.

Nothing in this module may be reached from the Reader or the Investigator.
Those paths handle untrusted text and model output; granting authority is a
human act. tests/test_boundaries.py enforces that statically.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from .audit import canonical_json, sha256_hex
from .policy import ALLOWED_ACTION_UNIVERSE

APPROVAL_ACTOR_SELLER = "seller"


class ApprovalError(ValueError):
    """An approval could not be created as asked."""


@dataclass(frozen=True)
class DisputeVersion:
    """The dispute as it stood when the seller approved.

    update_time and status together pin the version. If either has moved by
    execution time the approval is stale and must be re-reviewed.
    """

    update_time: str
    status: str

    def as_tuple(self) -> tuple[str, str]:
        return (self.update_time, self.status)

    @classmethod
    def from_snapshot(cls, snapshot: Mapping[str, Any]) -> "DisputeVersion":
        if not isinstance(snapshot, Mapping):
            raise ApprovalError("snapshot must be a mapping")
        update_time = snapshot.get("update_time")
        status = snapshot.get("status")
        if not isinstance(update_time, str) or not isinstance(status, str):
            raise ApprovalError("snapshot has no usable update_time and status")
        return cls(update_time=update_time, status=status)


@dataclass(frozen=True)
class Approval:
    """Immutable authorisation for exactly one action on one dispute version.

    The payload is held as canonical JSON, so the object cannot be mutated
    and the approval_id always matches what it authorises.
    """

    approval_id: str
    dispute_id: str
    action: str
    payload_json: str = field(repr=False)
    dispute_version: DisputeVersion
    approved_by: str
    created_at: str
    # Which ledger row, at which version, this approval was granted against.
    # None when the case had no ledger match. Folded into the approval id, so
    # an approval cannot be retargeted at a different row or a later version.
    ledger_row_id: int | None = None
    ledger_row_version: int | None = None
    # The carrier reading the seller was looking at, when one was on the
    # page. Folded into the approval id, so an approval granted while the
    # carrier said one thing does not survive the carrier saying another.
    # Both None when no carrier fact was present, which is every case with
    # CARRIER_ENABLED off -- such an approval keeps its original id.
    carrier_status: str | None = None
    carrier_checked_at: str | None = None

    @property
    def payload(self) -> dict[str, Any]:
        """A fresh copy each time; mutating it changes nothing."""
        return json.loads(self.payload_json)

    @property
    def payload_hash(self) -> str:
        return sha256_hex(self.payload_json)

    def matches_version(self, snapshot: Mapping[str, Any]) -> bool:
        try:
            return DisputeVersion.from_snapshot(snapshot) == self.dispute_version
        except ApprovalError:
            return False

    def recompute_id(self) -> str:
        return compute_approval_id(
            self.dispute_id,
            self.action,
            json.loads(self.payload_json),
            self.dispute_version,
            ledger_row_id=self.ledger_row_id,
            ledger_row_version=self.ledger_row_version,
            carrier_status=self.carrier_status,
            carrier_checked_at=self.carrier_checked_at,
        )

    def is_intact(self) -> bool:
        return self.approval_id == self.recompute_id()


def compute_approval_id(
    dispute_id: str,
    action: str,
    payload: Any,
    dispute_version: DisputeVersion,
    ledger_row_id: int | None = None,
    ledger_row_version: int | None = None,
    carrier_status: str | None = None,
    carrier_checked_at: str | None = None,
) -> str:
    """Hash of the canonical JSON of what is being approved.

    Changing the payload, the action, the dispute or the version produces a
    different id, so an approval cannot be retargeted or quietly edited. The
    ledger row id and version are folded in the same way when present: an
    approval granted against one ledger row, at one version, does not survive
    a change to either. Both keys are omitted when there is no ledger match,
    so an approval with no row keeps the id it has always had.

    The carrier reading is folded in on exactly the same terms. When the
    seller approved while a carrier_reported fact was on the page, the status
    and the time it was checked become part of the id, so a later or
    different reading invalidates the approval. When no carrier fact was
    present -- every case with the connector off -- both keys are absent and
    the id is unchanged from what it would have been before the connector
    existed.
    """
    material: dict[str, Any] = {
        "dispute_id": dispute_id,
        "action": action,
        "payload": payload,
        "dispute_version": list(dispute_version.as_tuple()),
    }
    if ledger_row_id is not None:
        material["ledger_row_id"] = ledger_row_id
        material["ledger_row_version"] = ledger_row_version
    if carrier_status is not None:
        material["carrier_status"] = carrier_status
        material["carrier_checked_at"] = carrier_checked_at
    return sha256_hex(canonical_json(material))


def create_approval(
    dispute_id: str,
    action: str,
    payload: Mapping[str, Any],
    dispute_version: DisputeVersion,
    approved_by: str = APPROVAL_ACTOR_SELLER,
    ledger_row_id: int | None = None,
    ledger_row_version: int | None = None,
    carrier_status: str | None = None,
    carrier_checked_at: str | None = None,
) -> Approval:
    """Record a seller's explicit approval of one action.

    Call this only from a path a human actually reached — an approval
    endpoint or an operator command. It is never called by the reader, the
    investigator, policy evaluation, or the executor.
    """
    if not isinstance(dispute_id, str) or not dispute_id.strip():
        raise ApprovalError("dispute_id is required")
    if action not in ALLOWED_ACTION_UNIVERSE:
        raise ApprovalError(
            f"{action!r} is not an approvable action; expected one of "
            f"{sorted(ALLOWED_ACTION_UNIVERSE)}"
        )
    if not isinstance(payload, Mapping):
        raise ApprovalError("payload must be a mapping")
    if not isinstance(dispute_version, DisputeVersion):
        raise ApprovalError("dispute_version must be a DisputeVersion")

    if ledger_row_id is not None and not isinstance(ledger_row_id, int):
        raise ApprovalError("ledger_row_id must be an integer when given")
    if ledger_row_version is not None and not isinstance(ledger_row_version, int):
        raise ApprovalError("ledger_row_version must be an integer when given")

    if carrier_status is not None and not isinstance(carrier_status, str):
        raise ApprovalError("carrier_status must be a string when given")
    if carrier_checked_at is not None and not isinstance(carrier_checked_at, str):
        raise ApprovalError("carrier_checked_at must be a string when given")
    if carrier_status is not None and carrier_checked_at is None:
        # Binding half the reading would let the other half drift unnoticed.
        raise ApprovalError("carrier_status requires carrier_checked_at")

    dispute_id = dispute_id.strip()
    payload_dict = json.loads(canonical_json(payload))
    approval_id = compute_approval_id(
        dispute_id,
        action,
        payload_dict,
        dispute_version,
        ledger_row_id=ledger_row_id,
        ledger_row_version=ledger_row_version,
        carrier_status=carrier_status,
        carrier_checked_at=carrier_checked_at,
    )

    return Approval(
        approval_id=approval_id,
        dispute_id=dispute_id,
        action=action,
        payload_json=canonical_json(payload_dict),
        dispute_version=dispute_version,
        approved_by=approved_by,
        created_at=datetime.now(timezone.utc).isoformat(),
        ledger_row_id=ledger_row_id,
        ledger_row_version=ledger_row_version,
        carrier_status=carrier_status,
        carrier_checked_at=carrier_checked_at,
    )
