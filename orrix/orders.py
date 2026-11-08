"""The seller's own order ledger, and how it matches a dispute.

A ledger row is the seller's assertion about a shipment: an order reference,
a carrier, a tracking number and a delivery date. It is first-party but still
untrusted as text -- typed by a human or imported from a CSV -- so every
field is held to a conservative pattern and there is no free-text field at
all. Nothing typed here can carry prose into a payload, a prompt or a log.

This module holds no write capability and reads no environment. It matches a
row to a dispute by the seller's transaction id, which comes from the PayPal
record (Facts), never from the row itself. Matching never adds a new fact and
never overwrites a confirmed one: it only fills a fact that was unavailable,
or records a conflict when a seller assertion disagrees with the ledger.
"""

from __future__ import annotations

import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, ValidationError

from .facts import Facts, FactStatus
from .seller_input import CARRIER_MAX_LENGTH, CARRIER_PATTERN, TRACKING_NUMBER_PATTERN

#: Origin code for a value that came from the seller's own ledger. It is a
#: product origin, not a fact source: apply_ledger stamps it only onto facts
#: it actually fills, and never invents a fact outside the closed set. Kept
#: token-shaped (no spaces) so it is safe as a CSS class and a JSON value.
SOURCE_SELLER_LEDGER = "seller_ledger"

#: Same code, named for the UI. Matches the CSS rule .origin-seller_ledger.
LEDGER_ORIGIN_CODE = "seller_ledger"

#: Human label for the ledger origin, shown by the UI's origin legend.
LEDGER_ORIGIN_LABEL = "Seller ledger"

#: How a row got into the ledger. Closed set; anything else is refused.
ORDER_SOURCES = ("api", "csv", "manual", "demo_seed")

ITEM_LABEL_MAX_LENGTH = 80

# Shapes a trusted value may take. Anything failing its pattern is refused
# outright, never passed through as text.
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_CURRENCY_PATTERN = re.compile(r"^[A-Z]{3}$")
_ORDER_REF_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-/]{0,63}$")
_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")

STATUS_INSERTED = "inserted"
STATUS_UPDATED = "updated"
STATUS_UNCHANGED = "unchanged"


class OrderLedgerError(ValueError):
    """The submitted order could not be accepted.

    Carries `errors`: one "field: reason" string per failed check, built with
    the offending value left out. A rejected value is never repeated back, so
    a form or a CSV cannot be used to echo text into the page.
    """

    def __init__(self, message: str, errors: list[str] | None = None):
        super().__init__(message)
        self.errors: list[str] | None = list(errors) if errors else None


class OrderInput(BaseModel):
    """One order a seller asserts. Frozen and extra="forbid".

    A form or CSV that sends an unexpected key is one that has been tampered
    with; dropping the key silently would hide that. Every field is a code, a
    date or a short label held to a conservative pattern.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    seller_transaction_id: str
    order_ref: str
    carrier: str = Field(max_length=CARRIER_MAX_LENGTH)
    tracking_number: str
    shipped_at: str = ""
    delivered_at: str = ""
    amount: str = ""
    currency: str = ""
    item_label: str = Field(default="", max_length=ITEM_LABEL_MAX_LENGTH)

    @field_validator("seller_transaction_id")
    @classmethod
    def _validate_transaction_id(cls, value: str) -> str:
        if not _ID_PATTERN.match(value):
            raise ValueError(
                "seller_transaction_id must start alphanumeric and be letters, "
                "digits, underscores or hyphens, at most 64 characters"
            )
        return value

    @field_validator("order_ref")
    @classmethod
    def _validate_order_ref(cls, value: str) -> str:
        if not _ORDER_REF_PATTERN.match(value):
            raise ValueError(
                "order_ref must start alphanumeric and be letters, digits, spaces, "
                "underscores, dots, slashes or hyphens, at most 64 characters"
            )
        return value

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
            raise ValueError(
                "tracking_number must be 6-40 characters of letters, digits or hyphens"
            )
        return value

    @field_validator("shipped_at", "delivered_at")
    @classmethod
    def _validate_date(cls, value: str) -> str:
        if value == "":
            return value
        if not _DATE_PATTERN.match(value):
            raise ValueError("dates must be YYYY-MM-DD")
        return value

    @field_validator("amount")
    @classmethod
    def _validate_amount(cls, value: str) -> str:
        if value == "":
            return value
        try:
            amount = Decimal(value)
        except (InvalidOperation, ValueError) as error:
            raise ValueError("amount must be a decimal number") from error
        if amount < 0 or not amount.is_finite():
            raise ValueError("amount must be zero or greater")
        return value

    @field_validator("currency")
    @classmethod
    def _validate_currency(cls, value: str) -> str:
        if value == "":
            return value
        if not _CURRENCY_PATTERN.match(value):
            raise ValueError("currency must be a three-letter uppercase code")
        return value


@dataclass(frozen=True)
class OrderRecord:
    """A stored ledger row. Server-set recorded_at; a monotonic version."""

    row_id: int
    seller_transaction_id: str
    order_ref: str
    carrier: str
    tracking_number: str
    shipped_at: str
    delivered_at: str
    amount: str
    currency: str
    item_label: str
    source: str
    recorded_at: str
    version: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "row_id": self.row_id,
            "seller_transaction_id": self.seller_transaction_id,
            "order_ref": self.order_ref,
            "carrier": self.carrier,
            "tracking_number": self.tracking_number,
            "shipped_at": self.shipped_at,
            "delivered_at": self.delivered_at,
            "amount": self.amount,
            "currency": self.currency,
            "item_label": self.item_label,
            "source": self.source,
            "recorded_at": self.recorded_at,
            "version": self.version,
        }


_SCHEMA = """
CREATE TABLE IF NOT EXISTS orders (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    seller_transaction_id TEXT NOT NULL UNIQUE,
    order_ref             TEXT NOT NULL,
    carrier               TEXT NOT NULL,
    tracking_number       TEXT NOT NULL,
    shipped_at            TEXT,
    delivered_at          TEXT,
    amount                TEXT,
    currency              TEXT,
    item_label            TEXT,
    source                TEXT NOT NULL,
    recorded_at           TEXT NOT NULL,
    version               INTEGER NOT NULL DEFAULT 1
);
"""


def _row_to_record(row: sqlite3.Row) -> OrderRecord:
    return OrderRecord(
        row_id=int(row["id"]),
        seller_transaction_id=row["seller_transaction_id"],
        order_ref=row["order_ref"],
        carrier=row["carrier"],
        tracking_number=row["tracking_number"],
        shipped_at=row["shipped_at"] or "",
        delivered_at=row["delivered_at"] or "",
        amount=row["amount"] or "",
        currency=row["currency"] or "",
        item_label=row["item_label"] or "",
        source=row["source"],
        recorded_at=row["recorded_at"],
        version=int(row["version"]),
    )


class OrderLedger:
    """The ledger table. Takes its path from the caller, never the env."""

    def __init__(self, db_path: str, now: Any | None = None):
        self.db_path = db_path
        self._now = now or (lambda: datetime.now(timezone.utc))
        self.init()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def init(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.executescript(_SCHEMA)

    @staticmethod
    def _same(existing: OrderRecord, submitted: OrderInput) -> bool:
        return (
            existing.order_ref == submitted.order_ref
            and existing.carrier == submitted.carrier
            and existing.tracking_number == submitted.tracking_number
            and existing.shipped_at == submitted.shipped_at
            and existing.delivered_at == submitted.delivered_at
            and existing.amount == submitted.amount
            and existing.currency == submitted.currency
            and existing.item_label == submitted.item_label
        )

    def get(self, row_id: int) -> OrderRecord | None:
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT * FROM orders WHERE id = ?", (row_id,)
            ).fetchone()
        return _row_to_record(row) if row else None

    def get_by_transaction(self, seller_transaction_id: str) -> OrderRecord | None:
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT * FROM orders WHERE seller_transaction_id = ?",
                (seller_transaction_id,),
            ).fetchone()
        return _row_to_record(row) if row else None

    def all(self) -> list[OrderRecord]:
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                "SELECT * FROM orders ORDER BY recorded_at DESC, id DESC"
            ).fetchall()
        return [_row_to_record(row) for row in rows]

    def count(self) -> int:
        with closing(self._connect()) as connection, connection:
            return connection.execute("SELECT COUNT(*) FROM orders").fetchone()[0]

    def upsert(self, order: OrderInput, source: str) -> tuple[OrderRecord, str]:
        """Insert or update one row, idempotently.

        A second submission that changes nothing returns the existing row
        with the version unchanged and action "unchanged", so a repeated API
        call or CSV re-import is a no-op rather than a new version. A
        submission that changes any asserted field bumps the version and
        re-stamps recorded_at from the server clock.
        """
        if source not in ORDER_SOURCES:
            raise OrderLedgerError(f"{source!r} is not a known order source")

        recorded_at = self._now().isoformat()

        with closing(self._connect()) as connection, connection:
            existing_row = connection.execute(
                "SELECT * FROM orders WHERE seller_transaction_id = ?",
                (order.seller_transaction_id,),
            ).fetchone()

            if existing_row is None:
                cursor = connection.execute(
                    """
                    INSERT INTO orders (
                        seller_transaction_id, order_ref, carrier, tracking_number,
                        shipped_at, delivered_at, amount, currency, item_label,
                        source, recorded_at, version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                    """,
                    (
                        order.seller_transaction_id,
                        order.order_ref,
                        order.carrier,
                        order.tracking_number,
                        order.shipped_at or None,
                        order.delivered_at or None,
                        order.amount or None,
                        order.currency or None,
                        order.item_label or None,
                        source,
                        recorded_at,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM orders WHERE id = ?", (cursor.lastrowid,)
                ).fetchone()
                return _row_to_record(row), STATUS_INSERTED

            existing = _row_to_record(existing_row)
            if self._same(existing, order):
                return existing, STATUS_UNCHANGED

            connection.execute(
                """
                UPDATE orders SET
                    order_ref = ?, carrier = ?, tracking_number = ?,
                    shipped_at = ?, delivered_at = ?, amount = ?, currency = ?,
                    item_label = ?, source = ?, recorded_at = ?,
                    version = version + 1
                WHERE id = ?
                """,
                (
                    order.order_ref,
                    order.carrier,
                    order.tracking_number,
                    order.shipped_at or None,
                    order.delivered_at or None,
                    order.amount or None,
                    order.currency or None,
                    order.item_label or None,
                    source,
                    recorded_at,
                    existing.row_id,
                ),
            )
            row = connection.execute(
                "SELECT * FROM orders WHERE id = ?", (existing.row_id,)
            ).fetchone()
            return _row_to_record(row), STATUS_UPDATED


def parse_order(raw: Mapping[str, Any]) -> OrderInput:
    """Validate one submitted order into an OrderInput.

    Rejects anything that is not exactly this schema: unknown keys, prose in
    a carrier or tracking field, a malformed date, amount or currency. The
    raised error names the field and the rule, never the value: pydantic's
    default rendering quotes the input, which would echo it back.
    """
    if not isinstance(raw, Mapping):
        raise OrderLedgerError("order must be a mapping")
    try:
        return OrderInput(**raw)
    except ValidationError as error:
        messages = [
            f"{'.'.join(str(part) for part in item.get('loc', ())) or 'input'}: "
            f"{item.get('msg', 'invalid')}"
            for item in error.errors()
        ]
        raise OrderLedgerError("; ".join(messages), errors=messages) from error


def recorded_before_dispute(recorded_at: str | None, dispute_created: str | None) -> bool:
    """Whether the ledger row was written before the dispute was opened.

    Computed from stored timestamps, never asserted by a person. Anything
    missing or unparseable is False: a claim Orrix cannot verify is not made.
    """
    if not recorded_at or not dispute_created:
        return False

    def _parse(value: str) -> datetime | None:
        try:
            stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return stamp

    row_stamp = _parse(recorded_at)
    dispute_stamp = _parse(dispute_created)
    if row_stamp is None or dispute_stamp is None:
        return False
    return row_stamp < dispute_stamp


def match_for_facts(ledger: OrderLedger | None, facts: Facts | None) -> OrderRecord | None:
    """The ledger row for the dispute's seller transaction, if one exists.

    The transaction id comes from Facts (read from the PayPal record), never
    from a ledger row, so a row cannot match itself onto a dispute by
    claiming an id.
    """
    if ledger is None or facts is None:
        return None
    transaction_id = facts.value("seller_transaction_id")
    if not isinstance(transaction_id, str):
        return None
    return ledger.get_by_transaction(transaction_id)


def apply_ledger(facts: Facts, order: OrderRecord) -> Facts:
    """Overlay a matched ledger row onto the facts, without adding any.

    Only tracking_carrier, tracking_number and delivered_on are touched, and
    only where the fact was unavailable or a same-value seller assertion. A
    confirmed fact is never overwritten with a seller assertion, and two
    disagreeing seller values become conflicting rather than one winning.
    Returns a new Facts, or the input unchanged when nothing moved.
    """
    if facts is None or order is None:
        return facts

    new_facts = dict(facts.facts)
    changed = False

    overlays = (
        ("tracking_carrier", order.carrier),
        ("tracking_number", order.tracking_number),
        ("delivered_on", order.delivered_at),
    )

    for name, asserted in overlays:
        if asserted == "" or name not in new_facts:
            continue
        fact = new_facts[name]

        if fact.status is FactStatus.CONFIRMED:
            # The PayPal record already confirms this. Do not downgrade it.
            continue
        if fact.status is FactStatus.CONFLICTING:
            continue
        if fact.status is FactStatus.SELLER_ASSERTED:
            if str(fact.value).casefold() != str(asserted).casefold():
                new_facts[name] = fact.model_copy(
                    update={"status": FactStatus.CONFLICTING, "value": None}
                )
                changed = True
            continue

        # Unavailable: fill it, sourced from the seller's ledger.
        new_facts[name] = fact.model_copy(
            update={
                "value": asserted,
                "status": FactStatus.SELLER_ASSERTED,
                "source": SOURCE_SELLER_LEDGER,
            }
        )
        changed = True

    if not changed:
        return facts
    return facts.model_copy(update={"facts": new_facts})


def apply_matched(
    ledger: OrderLedger | None, facts: Facts | None
) -> tuple[Facts | None, OrderRecord | None]:
    """Match a dispute's seller transaction to the ledger and overlay it.

    Returns (facts, matched_row). When there is no ledger, no match or no
    change, the facts are returned unchanged; the row is the matched record
    when one exists, else None.
    """
    if facts is None:
        return facts, None
    order = match_for_facts(ledger, facts)
    if order is None:
        return facts, None
    return apply_ledger(facts, order), order


def evidence_checklist(
    facts: Facts, order: OrderRecord | None, dispute_created: str | None
) -> dict[str, Any]:
    """A display-only view of what the ledger contributes to this case.

    Pure and read-only: it explains, and never participates in a decision.
    """
    matched = order is not None
    return {
        "matched": matched,
        "order_ref": order.order_ref if order else None,
        "tracking_number": order.tracking_number if order else None,
        "carrier": order.carrier if order else None,
        "recorded_at": order.recorded_at if order else None,
        "version": order.version if order else None,
        "recorded_before_dispute": (
            recorded_before_dispute(order.recorded_at, dispute_created) if order else False
        ),
        "source": LEDGER_ORIGIN_CODE,
        "label": LEDGER_ORIGIN_LABEL,
    }
