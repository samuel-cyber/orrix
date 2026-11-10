"""Polling fallback: picks up disputes whose webhook never arrived."""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any, Mapping

from . import store
from .paypal import PayPalError
from .webhooks import get_client, get_sync_deps, refresh_case

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


def _view_update_time(dispute_id: str, case_views: Any) -> str | None:
    """update_time of the case view the console would list, if any."""
    try:
        row = case_views.get(dispute_id)
    except Exception as error:
        logger.warning(
            "could not read the case view dispute_id=%s exception=%s message=%s",
            dispute_id,
            type(error).__name__,
            error,
        )
        return None
    if not row:
        return None
    stored = row.get("update_time")
    return stored if isinstance(stored, str) and stored.strip() else None


def _as_instant(value: str | None) -> datetime | None:
    """A PayPal timestamp as a UTC instant, or None if it is unusable.

    The listing and `get_dispute` are different endpoints reporting the same
    field, and they do not have to spell it identically: one may carry
    milliseconds where the other does not, and `Z` and `+00:00` mean the
    same thing. Comparing the raw strings made such a dispute look
    permanently stale, so the poller re-fetched it on every pass forever.
    Compare instants instead; a genuinely different time still differs.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00").replace("z", "+00:00")
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        # PayPal always sends an offset. One without is ambiguous, and
        # guessing a zone here could make a stale dispute look current, so
        # assume UTC rather than refusing: the comparison still has to match.
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc)


def _same_version(left: str | None, right: str | None) -> bool:
    """Whether two PayPal timestamps name the same version of a dispute.

    Exact instants first. Then one allowance: when either side reports whole
    seconds and the other carries a fraction, they are compared at whole
    seconds -- because a listing that renders 23:40:33.803 as 23:40:33 is
    reporting the same change, and treating those as different versions is
    what makes the poller re-fetch a dispute on every pass forever.

    The allowance is deliberately narrow. Two timestamps that both carry a
    fraction are compared exactly, so real sub-second precision is never
    thrown away. The cost of the allowance is that two changes inside the
    same second could look like one; the cost of not having it is a
    permanent re-fetch loop, which is the failure actually observed.
    """
    first, second = _as_instant(left), _as_instant(right)
    if first is None or second is None:
        return False
    if first == second:
        return True
    if first.microsecond == 0 or second.microsecond == 0:
        return first.replace(microsecond=0) == second.replace(microsecond=0)
    return False


# Why a dispute is not current, as short codes for the log. None means it is
# current and the pass may skip it.
STALE_NO_LISTED_UPDATE_TIME = "listing_has_no_update_time"
STALE_UNPARSEABLE_UPDATE_TIME = "listing_update_time_unparseable"
STALE_NOT_STORED = "not_stored"
STALE_SNAPSHOT_DIFFERS = "snapshot_update_time_differs"
STALE_VIEW_MISSING_OR_STALE = "view_missing_or_stale"


def _staleness(
    dispute_id: str, update_time: str | None, case_views: Any
) -> tuple[str | None, dict[str, Any]]:
    """Why this dispute needs work, or (None, {}) when it is fully current.

    A poll may skip only when a stored dispute exists AND its recorded
    update_time is the same instant the listing reports AND the case view
    the console reads is built from that same instant. The event row is
    deliberately not part of this.

    That event row is a claim marker, and a marker can outlive what it
    stands for: after the database-path fix, poll events survived while the
    snapshots and views they referred to did not. Treating the marker as
    proof of work meant the poller skipped six disputes forever and the
    queue showed one row.

    A listing that does not say when the dispute last changed proves
    nothing, so it is never grounds to skip. It used to be: with no
    update_time and no stored snapshot, every comparison was None == None
    and a brand-new dispute was skipped silently, forever.

    The second return value carries the two values that disagreed, for the
    caller's log line. They are timestamps, never dispute content.
    """
    listed = _as_instant(update_time)
    if update_time is None:
        return STALE_NO_LISTED_UPDATE_TIME, {}
    if listed is None:
        return STALE_UNPARSEABLE_UPDATE_TIME, {"listed": update_time}

    stored_raw = _stored_update_time(dispute_id)
    if stored_raw is None:
        return STALE_NOT_STORED, {}

    if not _same_version(stored_raw, update_time):
        # The diagnostic for a dispute that is re-fetched every pass: both
        # values, so a mismatch that is not a format difference is visible
        # rather than guessed at.
        return STALE_SNAPSHOT_DIFFERS, {"listed": update_time, "stored": stored_raw}

    view_raw = _view_update_time(dispute_id, case_views)
    if not _same_version(view_raw, update_time):
        return STALE_VIEW_MISSING_OR_STALE, {"listed": update_time, "view": view_raw}

    return None, {}


def _artifacts_current(dispute_id: str, update_time: str | None, case_views: Any) -> bool:
    """Whether this dispute is fully represented at this version."""
    reason, _ = _staleness(dispute_id, update_time, case_views)
    return reason is None


def poll_once() -> dict[str, int]:
    """One polling pass. Returns counts; never raises on a PayPal failure.

    Only the dispute id and update_time are read from each list item. They
    decide whether to look closer, nothing more: the stored snapshot always
    comes from a fresh get_dispute, exactly as on the webhook path.
    """
    counts = {"listed": 0, "processed": 0, "skipped": 0, "backfilled": 0, "failed": 0}

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
    case_views = get_sync_deps().case_views

    for item in disputes:
        dispute_id = _field(item, ("dispute_id", "id"))
        if not dispute_id:
            counts["skipped"] += 1
            continue

        update_time = _field(item, _UPDATE_TIME_FIELDS)

        # Skip only when a stored dispute exists at this version and the
        # case view is built from it. Anything less and there is work to do,
        # whatever the events table says.
        reason, mismatch = _staleness(dispute_id, update_time, case_views)
        if reason is None:
            counts["skipped"] += 1
            continue

        event_id = f"poll:{dispute_id}:{update_time}"
        # The event is claimed if new and reused if not, so a rebuild never
        # writes a second row for the same version.
        is_new = store.insert_event_if_absent(event_id, POLL_EVENT_TYPE, dispute_id)
        if not is_new:
            # This is the line to read when a dispute is re-fetched on every
            # pass: it names which value disagreed with which.
            logger.info(
                "poll rebuilding dispute_id=%s update_time=%s reason=%s %s",
                dispute_id,
                update_time,
                reason,
                " ".join(f"{key}={value!r}" for key, value in sorted(mismatch.items())),
            )

        if refresh_case(event_id, POLL_EVENT_TYPE, dispute_id):
            counts["processed" if is_new else "backfilled"] += 1
        else:
            counts["failed"] += 1

    # Record the pass itself, not the disputes it touched. A pass that
    # skipped everything still proves the poller is alive, and that is what
    # the console's "polled Ns ago" indicator is asking about.
    try:
        store.record_poll_completed()
    except Exception as error:  # noqa: BLE001 - the indicator is not worth a crash
        logger.warning(
            "could not record the poll pass: %s: %s", type(error).__name__, error
        )

    logger.info(
        "poll status=complete listed=%s processed=%s skipped=%s backfilled=%s failed=%s",
        counts["listed"],
        counts["processed"],
        counts["skipped"],
        counts["backfilled"],
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
