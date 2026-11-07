"""Trusted facts from PayPal records; free text dropped."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, field_validator

from .seller_input import SellerEvidenceInput

SOURCE_PAYPAL_RECORD = "paypal_record"
SOURCE_SELLER_INPUT = "seller_input"

# Shapes a trusted value is allowed to take. Anything failing its pattern
# becomes unavailable rather than being passed through as text.
_CODE_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9_]{0,63}$")
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_CURRENCY_PATTERN = re.compile(r"^[A-Z]{3}$")
_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$")
# Carrier names and tracking numbers are seller-typed, so they are held to a
# conservative charset. Prose in a tracking field is not a tracking number.
_TRACKING_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-/]{0,63}$")
_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Every fact Orrix is willing to hold. Nothing outside this list is read, so
# a new PayPal field is dropped by construction rather than by rule.
FACT_NAMES: tuple[str, ...] = (
    "dispute_id",
    "status",
    "dispute_state",
    "stage",
    "reason",
    "dispute_amount",
    "dispute_currency",
    "created",
    "seller_response_due_date",
    "buyer_transaction_id",
    "seller_transaction_id",
    "transaction_status",
    "gross_amount",
    "gross_currency",
    "seller_protection_eligible",
    "tracking_carrier",
    "tracking_number",
    "requested_evidence_types",
    "delivery_status",
    "delivered_on",
    "evidence_submitted",
)


class FactStatus(str, Enum):
    CONFIRMED = "confirmed"
    #: Asserted by the seller, not corroborated by the PayPal record. Usable
    #: for building evidence, but never treated as proof of anything.
    SELLER_ASSERTED = "seller_asserted"
    CONFLICTING = "conflicting"
    UNAVAILABLE = "unavailable"


#: Statuses whose value may be read and acted on.
USABLE_STATUSES = frozenset({FactStatus.CONFIRMED, FactStatus.SELLER_ASSERTED})


class FactsIntegrityError(ValueError):
    """The record is internally inconsistent. Fail closed; build no Facts."""


class Fact(BaseModel):
    """One allowlisted value plus its provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    value: str | bool | Decimal | tuple[str, ...] | None
    status: FactStatus
    source: str = SOURCE_PAYPAL_RECORD
    entity_id: str | None = None
    retrieved_at: datetime

    @field_validator("value")
    @classmethod
    def _scalar_only(cls, value: Any) -> Any:
        # A dict or a nested list is how a blob of free text would arrive.
        if isinstance(value, (dict, list, set)):
            raise ValueError("fact values must be scalars or a tuple of codes")
        return value

    @property
    def is_confirmed(self) -> bool:
        """Corroborated by the PayPal record. Seller assertions are not."""
        return self.status is FactStatus.CONFIRMED

    @property
    def is_usable(self) -> bool:
        """Confirmed, or asserted by the seller. Either may be acted on."""
        return self.status in USABLE_STATUSES


class Facts(BaseModel):
    """The complete, closed set of facts an investigator may see.

    Construction is allowlist-driven, so a field PayPal adds tomorrow is
    absent here until someone adds it to FACT_NAMES on purpose.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    dispute_id: str
    retrieved_at: datetime
    facts: dict[str, Fact]

    def get(self, name: str) -> Fact:
        if name not in self.facts:
            raise KeyError(f"{name} is not an Orrix fact")
        return self.facts[name]

    def value(self, name: str) -> Any:
        """The value, or None when the fact is neither confirmed nor asserted."""
        fact = self.get(name)
        return fact.value if fact.is_usable else None

    def source(self, name: str) -> str:
        return self.get(name).source

    def status(self, name: str) -> FactStatus:
        return self.get(name).status

    def unavailable(self) -> tuple[str, ...]:
        return tuple(
            name for name, fact in self.facts.items() if fact.status is FactStatus.UNAVAILABLE
        )


def _dig(source: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(source, Mapping):
            return None
        source = source.get(key)
    return source


class _FactBuilder:
    def __init__(self, retrieved_at: datetime):
        self.retrieved_at = retrieved_at
        self.facts: dict[str, Fact] = {}

    def _add(
        self,
        name: str,
        value: Any,
        status: FactStatus,
        entity_id: str | None,
        source: str = SOURCE_PAYPAL_RECORD,
    ) -> None:
        self.facts[name] = Fact(
            name=name,
            value=value,
            status=status,
            source=source,
            entity_id=entity_id,
            retrieved_at=self.retrieved_at,
        )

    def unavailable(
        self, name: str, entity_id: str | None = None, source: str = SOURCE_PAYPAL_RECORD
    ) -> None:
        """Absent or unusable data. Never recorded as a negative fact."""
        self._add(name, None, FactStatus.UNAVAILABLE, entity_id, source)

    def conflicting(
        self, name: str, entity_id: str | None = None, source: str = SOURCE_PAYPAL_RECORD
    ) -> None:
        self._add(name, None, FactStatus.CONFLICTING, entity_id, source)

    def pattern(
        self,
        name: str,
        raw: Any,
        pattern: re.Pattern[str],
        entity_id: str | None = None,
        source: str = SOURCE_PAYPAL_RECORD,
        status: FactStatus = FactStatus.CONFIRMED,
    ) -> None:
        if isinstance(raw, str) and pattern.match(raw.strip()):
            self._add(name, raw.strip(), status, entity_id, source)
        else:
            self.unavailable(name, entity_id, source)

    def boolean(self, name: str, raw: Any, entity_id: str | None = None) -> None:
        if isinstance(raw, bool):
            self._add(name, raw, FactStatus.CONFIRMED, entity_id)
        else:
            self.unavailable(name, entity_id)

    def money(self, name: str, raw: Any, entity_id: str | None = None) -> None:
        if isinstance(raw, bool) or not isinstance(raw, (str, int, float, Decimal)):
            self.unavailable(name, entity_id)
            return
        try:
            amount = Decimal(str(raw))
        except InvalidOperation:
            self.unavailable(name, entity_id)
            return
        if amount < 0 or not amount.is_finite():
            self.unavailable(name, entity_id)
            return
        self._add(name, amount, FactStatus.CONFIRMED, entity_id)

    def codes(self, name: str, raw: Any, entity_id: str | None = None) -> None:
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
            self.unavailable(name, entity_id)
            return
        accepted = tuple(
            item.strip()
            for item in raw
            if isinstance(item, str) and _CODE_PATTERN.match(item.strip())
        )
        if not accepted:
            self.unavailable(name, entity_id)
            return
        self._add(name, accepted, FactStatus.CONFIRMED, entity_id)


def _select_transaction(
    transactions: Any, expected_transaction_id: str | None
) -> tuple[Mapping[str, Any] | None, bool]:
    """Pick the disputed transaction to read, and say whether they conflict."""
    if not isinstance(transactions, list):
        return None, False
    usable = [item for item in transactions if isinstance(item, Mapping)]
    if not usable:
        return None, False

    if expected_transaction_id is not None:
        for item in usable:
            ids = {item.get("seller_transaction_id"), item.get("buyer_transaction_id")}
            if expected_transaction_id in ids:
                return item, False
        return None, True

    # More than one disputed transaction: no single transaction-level truth.
    return usable[0], len(usable) > 1


def _tracking_info(evidences: Any) -> Mapping[str, Any] | None:
    """Carrier and number from seller-submitted proof of fulfilment."""
    if not isinstance(evidences, list):
        return None
    for evidence in evidences:
        if not isinstance(evidence, Mapping):
            continue
        if evidence.get("evidence_type") != "PROOF_OF_FULFILLMENT":
            continue
        tracking = _dig(evidence, "evidence_info", "tracking_info")
        if isinstance(tracking, list):
            for entry in tracking:
                if isinstance(entry, Mapping):
                    return entry
    return None


def _resolve_tracking(
    builder: "_FactBuilder",
    name: str,
    paypal_raw: Any,
    seller_raw: Any,
    entity_id: str | None,
) -> None:
    """Settle one tracking field between the PayPal record and the seller.

    The record wins when both agree, because it is corroborated. When they
    disagree the fact is conflicting and carries no value, so no action can
    be taken on either version. A seller value alone is usable but only ever
    seller_asserted. Prose in either source fails the pattern and becomes
    unavailable, exactly as before.
    """
    paypal_value = (
        paypal_raw.strip()
        if isinstance(paypal_raw, str) and _TRACKING_PATTERN.match(paypal_raw.strip())
        else None
    )
    seller_value = (
        seller_raw.strip()
        if isinstance(seller_raw, str) and _TRACKING_PATTERN.match(seller_raw.strip())
        else None
    )

    if paypal_value is not None and seller_value is not None:
        if paypal_value.casefold() == seller_value.casefold():
            builder.pattern(name, paypal_value, _TRACKING_PATTERN, entity_id)
        else:
            builder.conflicting(name, entity_id)
        return

    if paypal_value is not None:
        builder.pattern(name, paypal_value, _TRACKING_PATTERN, entity_id)
        return

    if seller_value is not None:
        builder.pattern(
            name,
            seller_value,
            _TRACKING_PATTERN,
            entity_id,
            SOURCE_SELLER_INPUT,
            FactStatus.SELLER_ASSERTED,
        )
        return

    # Neither source offered a usable value. Unavailable, not a denial.
    source = SOURCE_SELLER_INPUT if seller_raw is not None else SOURCE_PAYPAL_RECORD
    builder.unavailable(name, entity_id, source)


def _seller_has_submitted_evidence(evidences: Any) -> bool:
    """True when the record already carries seller-submitted proof.

    Read from the record, so it reflects what PayPal holds rather than what
    Orrix believes it sent.
    """
    if not isinstance(evidences, list):
        return False
    for evidence in evidences:
        if not isinstance(evidence, Mapping):
            continue
        if evidence.get("evidence_type") != "PROOF_OF_FULFILLMENT":
            continue
        if evidence.get("source") == "SUBMITTED_BY_SELLER":
            return True
    return False


def _requested_evidence_types(evidences: Any) -> list[str]:
    if not isinstance(evidences, list):
        return []
    requested: list[str] = []
    for evidence in evidences:
        if not isinstance(evidence, Mapping):
            continue
        if evidence.get("source") != "REQUESTED_FROM_SELLER":
            continue
        evidence_type = evidence.get("evidence_type")
        if isinstance(evidence_type, str):
            requested.append(evidence_type)
    return requested


def build_facts(
    dispute_snapshot: Mapping[str, Any],
    seller_input: SellerEvidenceInput | None = None,
    expected_dispute_id: str | None = None,
    expected_transaction_id: str | None = None,
    retrieved_at: datetime | None = None,
) -> Facts:
    """Turn a dispute record into the closed set of facts Orrix will reason on.

    Reads only the paths named here. Buyer and seller names and emails,
    messages, evidence notes, item names and descriptions, and every other
    free-text field are never visited, so they cannot leak downstream.

    Fails closed when the record contradicts what the caller expected: a
    snapshot for a different dispute, or one whose disputed transaction is
    not the transaction under consideration, produces no Facts at all.
    """
    if not isinstance(dispute_snapshot, Mapping):
        raise FactsIntegrityError("dispute snapshot must be a mapping")

    # Fail closed on anything claiming to be seller input but not validated.
    if seller_input is not None and not isinstance(seller_input, SellerEvidenceInput):
        raise FactsIntegrityError(
            "seller_input must be a SellerEvidenceInput; parse it with parse_seller_input first"
        )

    retrieved_at = retrieved_at or datetime.now(timezone.utc)

    dispute_id = dispute_snapshot.get("dispute_id")
    if not isinstance(dispute_id, str) or not _ID_PATTERN.match(dispute_id.strip()):
        raise FactsIntegrityError("dispute snapshot has no usable dispute_id")
    dispute_id = dispute_id.strip()

    if expected_dispute_id is not None and expected_dispute_id != dispute_id:
        raise FactsIntegrityError(
            f"dispute id mismatch: snapshot is {dispute_id}, expected {expected_dispute_id}"
        )

    transactions = dispute_snapshot.get("disputed_transactions")
    transaction, conflicted = _select_transaction(transactions, expected_transaction_id)

    if expected_transaction_id is not None and transaction is None:
        raise FactsIntegrityError(
            f"transaction id mismatch: {expected_transaction_id} is not a disputed "
            f"transaction on {dispute_id}"
        )

    builder = _FactBuilder(retrieved_at)

    # -- dispute level ---------------------------------------------------
    builder.pattern("dispute_id", dispute_id, _ID_PATTERN, dispute_id)
    builder.pattern("status", dispute_snapshot.get("status"), _CODE_PATTERN, dispute_id)
    builder.pattern("dispute_state", dispute_snapshot.get("dispute_state"), _CODE_PATTERN, dispute_id)
    builder.pattern(
        "stage", dispute_snapshot.get("dispute_life_cycle_stage"), _CODE_PATTERN, dispute_id
    )
    builder.pattern("reason", dispute_snapshot.get("reason"), _CODE_PATTERN, dispute_id)
    builder.money("dispute_amount", _dig(dispute_snapshot, "dispute_amount", "value"), dispute_id)
    builder.pattern(
        "dispute_currency",
        _dig(dispute_snapshot, "dispute_amount", "currency_code"),
        _CURRENCY_PATTERN,
        dispute_id,
    )
    builder.pattern("created", dispute_snapshot.get("create_time"), _TIMESTAMP_PATTERN, dispute_id)
    builder.pattern(
        "seller_response_due_date",
        dispute_snapshot.get("seller_response_due_date"),
        _TIMESTAMP_PATTERN,
        dispute_id,
    )

    # -- transaction level -----------------------------------------------
    transaction_entity = None
    if transaction is not None:
        seller_id = transaction.get("seller_transaction_id")
        transaction_entity = seller_id.strip() if isinstance(seller_id, str) else None

    if transaction is None or conflicted:
        for name in (
            "buyer_transaction_id",
            "seller_transaction_id",
            "transaction_status",
            "gross_amount",
            "gross_currency",
            "seller_protection_eligible",
        ):
            if conflicted:
                builder.conflicting(name, transaction_entity)
            else:
                builder.unavailable(name, transaction_entity)
    else:
        builder.pattern(
            "buyer_transaction_id",
            transaction.get("buyer_transaction_id"),
            _ID_PATTERN,
            transaction_entity,
        )
        builder.pattern(
            "seller_transaction_id",
            transaction.get("seller_transaction_id"),
            _ID_PATTERN,
            transaction_entity,
        )
        builder.pattern(
            "transaction_status",
            transaction.get("transaction_status"),
            _CODE_PATTERN,
            transaction_entity,
        )
        builder.money(
            "gross_amount", _dig(transaction, "gross_amount", "value"), transaction_entity
        )
        builder.pattern(
            "gross_currency",
            _dig(transaction, "gross_amount", "currency_code"),
            _CURRENCY_PATTERN,
            transaction_entity,
        )
        builder.boolean(
            "seller_protection_eligible",
            transaction.get("seller_protection_eligible"),
            transaction_entity,
        )

    # -- tracking, from the record and from the seller -------------------
    tracking = _tracking_info(dispute_snapshot.get("evidences")) or {}
    _resolve_tracking(
        builder,
        "tracking_carrier",
        paypal_raw=tracking.get("carrier_name"),
        seller_raw=getattr(seller_input, "carrier", None),
        entity_id=dispute_id,
    )
    _resolve_tracking(
        builder,
        "tracking_number",
        paypal_raw=tracking.get("tracking_number"),
        seller_raw=getattr(seller_input, "tracking_number", None),
        entity_id=dispute_id,
    )

    # -- seller assertions about delivery --------------------------------
    if seller_input is None:
        builder.unavailable("delivery_status", dispute_id, SOURCE_SELLER_INPUT)
        builder.unavailable("delivered_on", dispute_id, SOURCE_SELLER_INPUT)
    else:
        builder.pattern(
            "delivery_status",
            getattr(seller_input.delivery_status, "value", seller_input.delivery_status),
            _CODE_PATTERN,
            dispute_id,
            SOURCE_SELLER_INPUT,
            FactStatus.SELLER_ASSERTED,
        )
        delivered_on = seller_input.delivered_on
        if delivered_on is None:
            builder.unavailable("delivered_on", dispute_id, SOURCE_SELLER_INPUT)
        else:
            builder.pattern(
                "delivered_on",
                delivered_on.isoformat(),
                _DATE_PATTERN,
                dispute_id,
                SOURCE_SELLER_INPUT,
                FactStatus.SELLER_ASSERTED,
            )

    builder.boolean(
        "evidence_submitted",
        _seller_has_submitted_evidence(dispute_snapshot.get("evidences")),
        dispute_id,
    )

    builder.codes(
        "requested_evidence_types",
        _requested_evidence_types(dispute_snapshot.get("evidences")),
        dispute_id,
    )

    missing = set(FACT_NAMES) - set(builder.facts)
    if missing:  # pragma: no cover - guards against an incomplete edit
        raise FactsIntegrityError(f"fact builder did not populate: {sorted(missing)}")

    return Facts(dispute_id=dispute_id, retrieved_at=retrieved_at, facts=builder.facts)
