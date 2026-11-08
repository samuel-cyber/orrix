"""Seed a few ledger rows for a local demo.

Run it as ``orrix-seed`` (or ``python -m orrix.demo_seed``). It writes only to
the order ledger, through the same validated ingest the web app uses, with the
source ``demo_seed`` so a seeded row is never mistaken for a real import.

This module reads no environment variable of its own: the database path comes
from ``load_config()``, which is the one place the environment is read.
"""

from __future__ import annotations

import argparse
from typing import Any, Sequence

from .config import load_config
from .orders import OrderInput, OrderLedger, parse_order

# Fixed rows so a re-run is idempotent: the same transaction ids, so the
# second run reports them unchanged rather than duplicating them.
DEMO_ORDERS: tuple[dict[str, Any], ...] = (
    {
        "seller_transaction_id": "DEMO-TXN-0001",
        "order_ref": "ORD-1001",
        "carrier": "UPS",
        "tracking_number": "1ZDEMO000100000001",
        "shipped_at": "2026-01-04",
        "delivered_at": "2026-01-07",
        "amount": "129.00",
        "currency": "USD",
        "item_label": "Wireless headphones",
    },
    {
        "seller_transaction_id": "DEMO-TXN-0002",
        "order_ref": "ORD-1002",
        "carrier": "FedEx",
        "tracking_number": "DEMO200000000002",
        "shipped_at": "2026-01-05",
        "delivered_at": "2026-01-09",
        "amount": "54.50",
        "currency": "USD",
        "item_label": "Mechanical keyboard",
    },
)


def seed(db_path: str) -> dict[str, int]:
    """Upsert the demo rows. Returns counts keyed by insert/update/unchanged."""
    ledger = OrderLedger(db_path)
    counts = {"inserted": 0, "updated": 0, "unchanged": 0}
    for raw in DEMO_ORDERS:
        order: OrderInput = parse_order(raw)
        _record, status = ledger.upsert(order, "demo_seed")
        counts[status] = counts.get(status, 0) + 1
    return counts


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="orrix-seed",
        description="Seed a few demo order-ledger rows into the Orrix database.",
    )
    parser.add_argument(
        "--db",
        default=None,
        help="Database path. Defaults to the configured ORRIX_DB path.",
    )
    args = parser.parse_args(argv)

    db_path = args.db or load_config().db_path
    counts = seed(db_path)
    print(
        f"Seeded {len(DEMO_ORDERS)} demo order(s) into {db_path}: "
        f"{counts['inserted']} inserted, {counts['updated']} updated, "
        f"{counts['unchanged']} unchanged."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via the console script
    raise SystemExit(main())
