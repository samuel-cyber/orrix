"""Compares the dispute reason with the seller's delivery assertion.

Plain code, no model. The output is one fixed sentence plus the two facts it
rests on. It deliberately cannot say who is right: a mismatch between a
buyer's claim and a seller's assertion is a reason for a human to look, not a
conclusion about anybody's honesty. Nothing here infers intent, and nothing
here carries buyer text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .facts import Facts, FactStatus

#: The only wording this module ever produces.
DISCREPANCY_MESSAGE = "Claim conflicts with available delivery evidence. Review required."

REASON_NOT_RECEIVED = "MERCHANDISE_OR_SERVICE_NOT_RECEIVED"
DELIVERY_STATUS_DELIVERED = "DELIVERED"


@dataclass(frozen=True)
class FactReference:
    """One fact as cited by a discrepancy: name, value, source, status."""

    name: str
    value: Any
    source: str
    status: str


@dataclass(frozen=True)
class Discrepancy:
    """A conflict worth a human's attention.

    `message` is fixed wording. The two references say what conflicts and
    where each side came from, so a reviewer can check both without the
    detector characterising either.
    """

    message: str
    dispute_reason: FactReference
    delivery_status: FactReference

    def as_dict(self) -> dict[str, Any]:
        return {
            "message": self.message,
            "facts": [
                {
                    "name": reference.name,
                    "value": reference.value,
                    "source": reference.source,
                    "status": reference.status,
                }
                for reference in (self.dispute_reason, self.delivery_status)
            ],
        }


def _reference(facts: Facts, name: str) -> FactReference:
    fact = facts.get(name)
    return FactReference(
        name=fact.name,
        value=fact.value,
        source=fact.source,
        status=fact.status.value if isinstance(fact.status, FactStatus) else str(fact.status),
    )


def detect_discrepancy(facts: Facts) -> Discrepancy | None:
    """Return a Discrepancy when the claim and the delivery assertion conflict.

    The single rule: PayPal records the buyer claiming the item was not
    received, while the seller asserts it was delivered. Both are recorded
    facts; which one reflects reality is not something this code can know.
    """
    if not isinstance(facts, Facts):
        return None

    try:
        reason_fact = facts.get("reason")
        delivery_fact = facts.get("delivery_status")
    except KeyError:
        return None

    # The reason must be corroborated by the record, not merely asserted.
    if reason_fact.status is not FactStatus.CONFIRMED:
        return None
    if reason_fact.value != REASON_NOT_RECEIVED:
        return None

    # The delivery claim must actually be a seller assertion.
    if delivery_fact.status is not FactStatus.SELLER_ASSERTED:
        return None
    if delivery_fact.value != DELIVERY_STATUS_DELIVERED:
        return None

    return Discrepancy(
        message=DISCREPANCY_MESSAGE,
        dispute_reason=_reference(facts, "reason"),
        delivery_status=_reference(facts, "delivery_status"),
    )
