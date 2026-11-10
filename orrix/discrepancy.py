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

from .facts import CARRIER_STATUS, Facts, FactStatus

#: The only wording this module ever produces. It does not change when a
#: carrier is the source of the conflict: a carrier reading is one more piece
#: of delivery evidence, not a stronger accusation.
DISCREPANCY_MESSAGE = "Claim conflicts with available delivery evidence. Review required."

REASON_NOT_RECEIVED = "MERCHANDISE_OR_SERVICE_NOT_RECEIVED"
DELIVERY_STATUS_DELIVERED = "DELIVERED"
#: The carrier_status fact value that counts as delivery evidence.
CARRIER_DELIVERED = "DELIVERED"


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

    `message` is fixed wording. The references say what conflicts and where
    each side came from, so a reviewer can check both without the detector
    characterising either.

    `carrier_status` is present only when a carrier reading is part of the
    conflict. When it is absent the object is exactly what it was before the
    connector existed, so a seller-asserted discrepancy serialises
    unchanged.
    """

    message: str
    dispute_reason: FactReference
    delivery_status: FactReference
    carrier_status: FactReference | None = None

    def as_dict(self) -> dict[str, Any]:
        references = [self.dispute_reason, self.delivery_status]
        if self.carrier_status is not None:
            references.append(self.carrier_status)
        return {
            "message": self.message,
            "facts": [
                {
                    "name": reference.name,
                    "value": reference.value,
                    "source": reference.source,
                    "status": reference.status,
                }
                for reference in references
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
    """Return a Discrepancy when the claim and the delivery evidence conflict.

    The rule: PayPal records the buyer claiming the item was not received,
    while the delivery evidence says it arrived. The evidence may be the
    seller's own assertion, a carrier API's reading, or both. All are
    recorded facts; which one reflects reality is not something this code
    can know, and the wording does not get sharper because a carrier agrees
    with the seller.

    A carrier reading is never promoted: it triggers the same review flag,
    carries the same sentence, and does not block the seller from putting
    their evidence in front of PayPal.
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

    seller_says_delivered = (
        delivery_fact.status is FactStatus.SELLER_ASSERTED
        and delivery_fact.value == DELIVERY_STATUS_DELIVERED
    )

    # The carrier fact exists only when a lookup actually ran, so this is a
    # no-op whenever the connector is off.
    carrier_fact = facts.facts.get(CARRIER_STATUS)
    carrier_says_delivered = (
        carrier_fact is not None
        and carrier_fact.status is FactStatus.CARRIER_REPORTED
        and carrier_fact.value == CARRIER_DELIVERED
    )

    if not seller_says_delivered and not carrier_says_delivered:
        return None

    return Discrepancy(
        message=DISCREPANCY_MESSAGE,
        dispute_reason=_reference(facts, "reason"),
        delivery_status=_reference(facts, "delivery_status"),
        carrier_status=_reference(facts, CARRIER_STATUS) if carrier_says_delivered else None,
    )
