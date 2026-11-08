"""SQLite persistence for received events and fetched dispute snapshots."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any

DEFAULT_DB_PATH = "orrix.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id    TEXT PRIMARY KEY,
    event_type  TEXT,
    dispute_id  TEXT,
    received_at TEXT NOT NULL,
    status      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    dispute_id    TEXT PRIMARY KEY,
    snapshot_json TEXT NOT NULL,
    fetched_at    TEXT NOT NULL
);
"""


def db_path() -> str:
    """Resolved at call time, through the one resolver the config uses.

    This module used to read ORRIX_DB_PATH on its own, which silently split
    the deployment in two: the poller wrote one file and the console read
    another. Delegating keeps a single answer.
    """
    from .config import resolve_db_path

    return resolve_db_path()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(db_path(), timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


def init_db() -> None:
    with closing(connect()) as connection, connection:
        connection.executescript(_SCHEMA)


def insert_event_if_absent(
    event_id: str, event_type: str | None, dispute_id: str | None, status: str = "received"
) -> bool:
    """Insert the event, returning True if it is new and False if already seen.

    The INSERT OR IGNORE plus changes() runs inside one transaction, so two
    concurrent deliveries of the same event_id cannot both see themselves as
    new. This is the only duplicate check in the pipeline.
    """
    with closing(connect()) as connection, connection:
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO events (event_id, event_type, dispute_id, received_at, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (event_id, event_type, dispute_id, _now(), status),
        )
        return cursor.rowcount == 1


def set_event_status(event_id: str, status: str) -> None:
    with closing(connect()) as connection, connection:
        connection.execute("UPDATE events SET status = ? WHERE event_id = ?", (status, event_id))


def get_event(event_id: str) -> dict[str, Any] | None:
    with closing(connect()) as connection, connection:
        row = connection.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        return dict(row) if row else None


def count_events() -> int:
    with closing(connect()) as connection, connection:
        return connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def save_case_snapshot(dispute_id: str, snapshot: dict[str, Any]) -> None:
    """Store a freshly fetched dispute. Last fetch wins.

    Only ever called with the response from get_dispute, never with anything
    lifted out of a webhook payload, which is what makes out-of-order
    deliveries safe.
    """
    with closing(connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO cases (dispute_id, snapshot_json, fetched_at)
            VALUES (?, ?, ?)
            ON CONFLICT(dispute_id) DO UPDATE SET
                snapshot_json = excluded.snapshot_json,
                fetched_at    = excluded.fetched_at
            """,
            (dispute_id, json.dumps(snapshot, sort_keys=True), _now()),
        )


def get_case(dispute_id: str) -> dict[str, Any] | None:
    with closing(connect()) as connection, connection:
        row = connection.execute(
            "SELECT * FROM cases WHERE dispute_id = ?", (dispute_id,)
        ).fetchone()
        if not row:
            return None
        return {
            "dispute_id": row["dispute_id"],
            "snapshot": json.loads(row["snapshot_json"]),
            "snapshot_json": row["snapshot_json"],
            "fetched_at": row["fetched_at"],
        }


def all_dispute_ids() -> list[str]:
    """Every dispute with a stored snapshot, in a stable order."""
    with closing(connect()) as connection, connection:
        rows = connection.execute(
            "SELECT dispute_id FROM cases ORDER BY dispute_id"
        ).fetchall()
    return [row["dispute_id"] for row in rows]


def count_cases() -> int:
    with closing(connect()) as connection, connection:
        return connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0]


def latest_event_at(event_type: str | None = None) -> str | None:
    """When the most recent event of a type arrived, or None if never.

    The poller records one POLL.DISPUTE.SYNC event per dispute it refreshes.
    The newest of those timestamps is what the console's "polled Ns ago"
    indicator reads. It is a stored timestamp, never a live network call.
    """
    with closing(connect()) as connection, connection:
        if event_type is None:
            row = connection.execute("SELECT MAX(received_at) AS ts FROM events").fetchone()
        else:
            row = connection.execute(
                "SELECT MAX(received_at) AS ts FROM events WHERE event_type = ?",
                (event_type,),
            ).fetchone()
    return row["ts"] if row and row["ts"] else None
