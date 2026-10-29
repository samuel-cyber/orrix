"""Polling fallback: picks up disputes whose webhook never arrived."""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Mapping

from . import store
from .paypal import PayPalError
from .webhooks import get_client, refresh_case

logger = logging.getLogger("orrix.poller")

DEFAULT_POLL_INTERVAL_SECONDS = 60
POLL_EVENT_TYPE = "POLL.DISPUTE.SYNC"

# Field names update_time has been seen under in list responses.
_UPDATE_TIME_FIELDS = ("update_time", "updated_time")


def poll_interval_seconds() -> float:
    raw = os.environ.get("POLL_INTERVAL_SECONDS")
    if not raw:
        return float(DEFAULT_POLL_INTERVAL_SECONDS)
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "POLL_INTERVAL_SECONDS is not a number; using %s", DEFAULT_POLL_INTERVAL_SECONDS
        )
        return float(DEFAULT_POLL_INTERVAL_SECONDS)
    if value <= 0:
        logger.warning(
            "POLL_INTERVAL_SECONDS must be positive; using %s", DEFAULT_POLL_INTERVAL_SECONDS
        )
        return float(DEFAULT_POLL_INTERVAL_SECONDS)
    return value


def poller_enabled() -> bool:
    raw = os.environ.get("POLLER_ENABLED")
    if raw is None:
        return True
    return raw.strip().lower() not in {"0", "false", "no", "off", ""}


def _field(item: Mapping[str, Any], names: tuple[str, ...]) -> str | None:
    for name in names:
        value = item.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _stored_update_time(dispute_id: str) -> str | None:
    """update_time of the snapshot we already hold, from the fetched state."""
    case = store.get_case(dispute_id)
    if not case:
        return None
    snapshot = case.get("snapshot")
    if not isinstance(snapshot, dict):
        return None
    return _field(snapshot, _UPDATE_TIME_FIELDS)


def poll_once() -> dict[str, int]:
    """One polling pass. Returns counts; never raises on a PayPal failure.

    Only the dispute id and update_time are read from each list item. They
    decide whether to look closer, nothing more: the stored snapshot always
    comes from a fresh get_dispute, exactly as on the webhook path.
    """
    counts = {"listed": 0, "processed": 0, "skipped": 0, "failed": 0}

    try:
        disputes = get_client().list_disputes()
    except PayPalError as error:
        logger.warning(
            "poll status=list_failed http_status=%s debug_id=%s",
            error.status_code,
            error.debug_id,
        )
        counts["failed"] += 1
        return counts

    counts["listed"] = len(disputes)

    for item in disputes:
        dispute_id = _field(item, ("dispute_id", "id"))
        if not dispute_id:
            counts["skipped"] += 1
            continue

        update_time = _field(item, _UPDATE_TIME_FIELDS)

        # Already holding this exact version. This is what keeps a poll from
        # redoing work a webhook just did for the same dispute.
        stored = _stored_update_time(dispute_id)
        if stored is not None and stored == update_time:
            counts["skipped"] += 1
            continue

        event_id = f"poll:{dispute_id}:{update_time}"
        if not store.insert_event_if_absent(event_id, POLL_EVENT_TYPE, dispute_id):
            # Same version already claimed, by an earlier pass or a racing one.
            counts["skipped"] += 1
            continue

        if refresh_case(event_id, POLL_EVENT_TYPE, dispute_id):
            counts["processed"] += 1
        else:
            counts["failed"] += 1

    logger.info(
        "poll status=complete listed=%s processed=%s skipped=%s failed=%s",
        counts["listed"],
        counts["processed"],
        counts["skipped"],
        counts["failed"],
    )
    return counts


async def run_poller(interval: float | None = None) -> None:
    """Poll forever. A failing pass is logged and the loop continues."""
    delay = interval if interval is not None else poll_interval_seconds()
    logger.info("poller started interval=%ss", delay)
    while True:
        try:
            await asyncio.to_thread(poll_once)
        except asyncio.CancelledError:
            logger.info("poller stopped")
            raise
        except Exception:
            # Nothing a single bad pass can do should end the loop.
            logger.exception("poll status=unexpected_error")
        await asyncio.sleep(delay)
