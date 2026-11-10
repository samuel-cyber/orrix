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

-- When the poller last completed a pass. One row, overwritten each time.
--
-- This exists because "when did we last poll" and "when did a dispute last
-- change" are different questions, and the console was asking the second
-- one. Poll events are keyed poll:<dispute>:<update_time>, so an unchanged
-- dispute inserts no new row and MAX(received_at) stops moving: the header
-- read "polled 139000s ago" on a deployment polling every 60 seconds.
CREATE TABLE IF NOT EXISTS poll_runs (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    completed_at TEXT NOT NULL
);
"""

# Repeated on its own so record_poll_completed can create the table against a
# database that predates it, without re-running the whole schema.
_POLL_RUNS_SCHEMA = """
CREATE TABLE IF NOT EXISTS poll_runs (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    completed_at TEXT NOT NULL
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


def record_poll_completed(when: str | None = None) -> None:
    """Mark a completed polling pass. Called once per pass, always.

    Recorded whether or not the pass found anything to do, which is the
    whole point: it answers "is the poller alive", not "did a dispute
    change". The table is created lazily so a database written by an older
    build starts recording without a migration step.
    """
    timestamp = when or _now()
    with closing(connect()) as connection, connection:
        connection.executescript(_POLL_RUNS_SCHEMA)
        connection.execute(
            """
            INSERT INTO poll_runs (id, completed_at) VALUES (1, ?)
            ON CONFLICT(id) DO UPDATE SET completed_at = excluded.completed_at
            """,
            (timestamp,),
        )


def last_poll_completed_at() -> str | None:
    """When the poller last finished a pass, or None if it never has."""
    with closing(connect()) as connection, connection:
        try:
            row = connection.execute(
                "SELECT completed_at FROM poll_runs WHERE id = 1"
            ).fetchone()
        except sqlite3.OperationalError:
            # The table has not been created yet: no pass has completed.
            return None
    return row["completed_at"] if row and row["completed_at"] else None


def latest_event_at(event_type: str | None = None) -> str | None:
    """When the most recent event of a type arrived, or None if never.

    This is "when did a dispute of this type last change", NOT "when did we
    last poll": poll events are keyed by dispute and update_time, so an
    unchanged dispute inserts nothing. Use last_poll_completed_at for the
    liveness question. It is a stored timestamp, never a live network call.
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
