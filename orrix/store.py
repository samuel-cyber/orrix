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
    """Resolved at call time so tests and deployments can repoint it."""
    return os.environ.get("ORRIX_DB_PATH", DEFAULT_DB_PATH)


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


def count_cases() -> int:
    with closing(connect()) as connection, connection:
        return connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
