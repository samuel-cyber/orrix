"""The only schema buyer text can fill."""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Language tag: ISO 639-1 with an optional ISO 3166-1 region ("en", "pt-BR").
_LANGUAGE_PATTERN = re.compile(r"^[a-z]{2}(-[A-Z]{2})?$")

SELLER_SUMMARY_MAX_LENGTH = 300

# Fields a decision may read. seller_summary is deliberately absent: it is
# buyer-authored prose and exists only to be shown to a human.
DECISION_FIELDS = frozenset({"claim_type", "claimed_amount"})


class ClaimType(str, Enum):
    NOT_RECEIVED = "NOT_RECEIVED"
    NOT_AS_DESCRIBED = "NOT_AS_DESCRIBED"
    UNAUTHORIZED = "UNAUTHORIZED"
    OTHER = "OTHER"


class ClaimForm(BaseModel):
    """The single structure buyer text is allowed to become.

    Untrusted prose enters the system only as values in these four fields,
    and only `claim_type` and `claimed_amount` are readable by a decision.
    Unknown keys are a hard error: a reader that invents a field is a reader
    that has gone off-script, and silently dropping it would hide that.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    claim_type: ClaimType
    claimed_amount: Decimal = Field(ge=0, decimal_places=2)
    language: str
    seller_summary: str = Field(
        default="",
        max_length=SELLER_SUMMARY_MAX_LENGTH,
        description="Display only. Never read by policy, executor, or any decision.",
    )
    amount_was_clamped: bool = Field(
        default=False,
        description="Set by build_claim_form when the stated amount was out of range.",
    )

    @field_validator("language")
    @classmethod
    def _validate_language(cls, value: str) -> str:
        if not _LANGUAGE_PATTERN.match(value):
            raise ValueError("language must be an ISO 639-1 code, optionally with a region")
        return value

    @field_validator("seller_summary")
    @classmethod
    def _reject_control_characters(cls, value: str) -> str:
        # Newlines and control bytes are how prose smuggles structure into a
        # prompt or a log line. The summary is one line of display text.
        if any(character in value for character in "\r\n\t\x00"):
            raise ValueError("seller_summary must be a single line of plain text")
        return value

    def decision_inputs(self) -> dict[str, Any]:
        """The only part of a claim form a decision may consult."""
        return {field: getattr(self, field) for field in sorted(DECISION_FIELDS)}


class ClaimFormError(ValueError):
    """The reader's output could not be turned into a claim form."""


def _to_decimal(value: Any) -> Decimal:
    if isinstance(value, Decimal):
        return value
    if isinstance(value, bool):
        raise ClaimFormError("claimed_amount must be a number")
    if isinstance(value, (int, float, str)):
        try:
            return Decimal(str(value))
        except InvalidOperation as error:
            raise ClaimFormError("claimed_amount must be a number") from error
    raise ClaimFormError("claimed_amount must be a number")


def build_claim_form(
    raw: Mapping[str, Any], dispute_amount: Decimal | str | int | float
) -> ClaimForm:
    """Validate reader output into a ClaimForm, clamping the amount.

    `dispute_amount` is passed in separately and comes from the dispute
    record, never from the buyer: it is the ceiling the claimed amount is
    clamped to. Clamping rather than rejecting keeps an inflated claim from
    being a denial-of-service on the whole case, and the clamp is recorded
    so a reviewer can see it happened.
    """
    if not isinstance(raw, Mapping):
        raise ClaimFormError("reader output must be a mapping")

    ceiling = _to_decimal(dispute_amount)
    if ceiling < 0:
        raise ClaimFormError("dispute_amount cannot be negative")

    data = dict(raw)
    # Only the builder may set this; a reader claiming it is overreach.
    if "amount_was_clamped" in data:
        raise ClaimFormError("amount_was_clamped is not a reader field")

    clamped = False
    if "claimed_amount" in data:
        amount = _to_decimal(data["claimed_amount"])
        if amount < 0:
            amount, clamped = Decimal("0.00"), True
        elif amount > ceiling:
            amount, clamped = ceiling, True
        data["claimed_amount"] = amount.quantize(Decimal("0.01"))

    data["amount_was_clamped"] = clamped
    return ClaimForm(**data)
