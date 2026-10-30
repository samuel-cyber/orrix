"""The only structure seller-supplied shipment data may take.

Seller input is first-party but still untrusted as text: it is typed by a
human into a form. Every field here is a code or a date held to a
conservative pattern, and there is no free-text field at all, so nothing
typed here can carry prose into a payload, a prompt, or a log line.
"""

from __future__ import annotations

import re
from datetime import date
from enum import Enum
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator

CARRIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 \-]{0,39}$")
TRACKING_NUMBER_PATTERN = re.compile(r"^[A-Za-z0-9-]{6,40}$")

CARRIER_MAX_LENGTH = 40


class DeliveryStatus(str, Enum):
    SHIPPED = "SHIPPED"
    DELIVERED = "DELIVERED"
    UNKNOWN = "UNKNOWN"


class SellerInputError(ValueError):
    """The submitted shipment data could not be accepted."""


class SellerEvidenceInput(BaseModel):
    """Shipment data a seller asserts about a dispute.

    Frozen and extra="forbid": a form that sends an unexpected key is a form
    that has been tampered with, and dropping the key silently would hide it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    carrier: str = Field(max_length=CARRIER_MAX_LENGTH)
    tracking_number: str
    delivery_status: DeliveryStatus = DeliveryStatus.UNKNOWN
    delivered_on: date | None = None

    @field_validator("carrier")
    @classmethod
    def _validate_carrier(cls, value: str) -> str:
        if not CARRIER_PATTERN.match(value):
            raise ValueError(
                "carrier must be letters, digits, spaces or hyphens, at most "
                f"{CARRIER_MAX_LENGTH} characters"
            )
        return value

    @field_validator("tracking_number")
    @classmethod
    def _validate_tracking_number(cls, value: str) -> str:
        if not TRACKING_NUMBER_PATTERN.match(value):
            raise ValueError("tracking_number must be 6-40 characters of letters, digits or hyphens")
        return value

    @field_validator("delivered_on")
    @classmethod
    def _validate_delivered_on(cls, value: date | None) -> date | None:
        return value


def parse_seller_input(raw: Mapping[str, Any]) -> SellerEvidenceInput:
    """Validate a submitted form into a SellerEvidenceInput.

    Rejects anything that is not exactly this schema: unknown keys, prose in
    a carrier or tracking field, an unrecognised delivery status.
    """
    if not isinstance(raw, Mapping):
        raise SellerInputError("seller input must be a mapping")
    return SellerEvidenceInput(**raw)
