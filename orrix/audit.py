"""Hash-chained log with origin tags."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

GENESIS_HASH = "0" * 64


class OriginTag(str, Enum):
    """Where the information behind an entry came from."""

    PAYPAL_RECORD = "paypal_record"
    BUYER_TEXT = "buyer_text"
    READER_OUTPUT = "reader_output"
    SYSTEM = "system"
    SELLER_APPROVAL = "seller_approval"


ORIGIN_TAGS = frozenset(tag.value for tag in OriginTag)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    dispute_id   TEXT,
    origin_tag   TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    entry_hash   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_head (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    seq        INTEGER NOT NULL,
    entry_hash TEXT NOT NULL,
    entries    INTEGER NOT NULL
);
"""


def canonical_json(value: Any) -> str:
    """Stable serialization used everywhere a hash must be reproducible."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def chain_digest(text: str, hmac_key: str | None = None) -> str:
    """Chain digest: plain SHA-256, or HMAC-SHA256 when a key is configured.

    Without a key the chain is tamper-evident only against someone who
    cannot recompute it — which is nobody, since SHA-256 needs no secret.
    With a key, forging an entry requires the key as well as table access.
    See docs/THREAT_MODEL.md for what this does and does not buy.
    """
    if not hmac_key:
        return sha256_hex(text)
    return hmac.new(hmac_key.encode("utf-8"), text.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_payload(payload: Any) -> str:
    """Hash of a payload. The payload itself is never stored."""
    return sha256_hex(canonical_json(payload))


@dataclass(frozen=True)
class AuditConfig:
    """Passed in by the caller. No environment is read here.

    hmac_key is optional. When set, the chain is keyed, so an attacker with
    write access to the database still cannot forge a consistent entry
    without the key. The caller is responsible for sourcing it (an env var,
    a secret manager) and for keeping it off the same disk as the log.
    """

    db_path: str
    hmac_key: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts: str
    actor: str
    action: str
    dispute_id: str | None
    origin_tag: str
    payload_hash: str
    prev_hash: str
    entry_hash: str

    def recompute_hash(self, hmac_key: str | None = None) -> str:
        return chain_digest(
            canonical_json(
                [
                    self.seq,
                    self.ts,
                    self.actor,
                    self.action,
                    self.dispute_id,
                    self.origin_tag,
                    self.payload_hash,
                    self.prev_hash,
                ]
            ),
            hmac_key,
        )


class AuditLog:
    """Append-only hash chain.

    Each entry hashes its own fields plus the previous entry's hash, so
    altering, deleting or reordering a row breaks the chain at that point.
    A separate head row records the expected tip, which catches a row
    appended straight into the table.

    Only hashes and short structured fields are stored. Raw buyer text,
    model output and credentials never reach this table.
    """

    def __init__(self, config: AuditConfig):
        self.config = config
        self.init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.config.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def init_db(self) -> None:
        with self._connect() as connection:
            connection.executescript(_SCHEMA)

    def append(
        self,
        actor: str,
        action: str,
        origin_tag: OriginTag | str,
        dispute_id: str | None = None,
        payload: Any = None,
        payload_hash: str | None = None,
    ) -> AuditEntry:
        """Add one entry. Pass `payload` to hash it, or a precomputed hash."""
        tag = origin_tag.value if isinstance(origin_tag, OriginTag) else str(origin_tag)
        if tag not in ORIGIN_TAGS:
            raise ValueError(f"unknown origin_tag {tag!r}; expected one of {sorted(ORIGIN_TAGS)}")

        if payload_hash is None:
            payload_hash = hash_payload(payload)

        timestamp = datetime.now(timezone.utc).isoformat()

        with self._connect() as connection:
            row = connection.execute(
                "SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev_hash = row["entry_hash"] if row else GENESIS_HASH
            next_seq = (row["seq"] + 1) if row else 1

            entry = AuditEntry(
                seq=next_seq,
                ts=timestamp,
                actor=actor,
                action=action,
                dispute_id=dispute_id,
                origin_tag=tag,
                payload_hash=payload_hash,
                prev_hash=prev_hash,
                entry_hash="",
            )
            entry_hash = entry.recompute_hash(self.config.hmac_key)

            connection.execute(
                """
                INSERT INTO audit_log
                    (seq, ts, actor, action, dispute_id, origin_tag, payload_hash,
                     prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    next_seq,
                    timestamp,
                    actor,
                    action,
                    dispute_id,
                    tag,
                    payload_hash,
                    prev_hash,
                    entry_hash,
                ),
            )
            count = connection.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            connection.execute(
                """
                INSERT INTO audit_head (id, seq, entry_hash, entries) VALUES (1, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    seq = excluded.seq,
                    entry_hash = excluded.entry_hash,
                    entries = excluded.entries
                """,
                (next_seq, entry_hash, count),
            )

        return AuditEntry(**{**entry.__dict__, "entry_hash": entry_hash})

    def entries(self) -> list[AuditEntry]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM audit_log ORDER BY seq ASC").fetchall()
        return [
            AuditEntry(
                seq=row["seq"],
                ts=row["ts"],
                actor=row["actor"],
                action=row["action"],
                dispute_id=row["dispute_id"],
                origin_tag=row["origin_tag"],
                payload_hash=row["payload_hash"],
                prev_hash=row["prev_hash"],
                entry_hash=row["entry_hash"],
            )
            for row in rows
        ]

    def verify_chain(self) -> int | None:
        """Return the seq of the first bad entry, or None if the chain holds."""
        rows = self.entries()

        expected_prev = GENESIS_HASH
        expected_seq = 1
        for entry in rows:
            # A gap or a repeat means a row was removed or reordered.
            if entry.seq != expected_seq:
                return entry.seq
            if entry.prev_hash != expected_prev:
                return entry.seq
            if entry.entry_hash != entry.recompute_hash(self.config.hmac_key):
                return entry.seq
            if entry.origin_tag not in ORIGIN_TAGS:
                return entry.seq
            expected_prev = entry.entry_hash
            expected_seq += 1

        # The head anchor catches a row appended directly into the table,
        # including one whose own hashes were recomputed correctly.
        with self._connect() as connection:
            head = connection.execute("SELECT seq, entry_hash, entries FROM audit_head").fetchone()

        if head is None:
            return rows[0].seq if rows else None
        if not rows:
            return head["seq"]
        tip = rows[-1]
        if head["seq"] != tip.seq or head["entry_hash"] != tip.entry_hash:
            return tip.seq
        if head["entries"] != len(rows):
            return tip.seq
        return None
