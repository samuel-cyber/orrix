"""When the poller may skip a dispute, and when it may not.

Two failures live here. The first is a dispute skipped forever: with no
update_time in the listing and nothing stored, every comparison in
`_artifacts_current` was None == None, so a brand-new dispute looked fully
current and was never fetched.

The second is the opposite — a dispute re-fetched on every pass forever,
because the listing and `get_dispute` are different endpoints and need not
spell the same timestamp identically. Skipping must require a stored dispute
whose recorded version is the same version the listing reports.

PayPal is mocked throughout; no network call is made.
"""

from __future__ import annotations

import logging

import pytest

from orrix import poller, store, webhooks
from orrix.poller import (
    STALE_NO_LISTED_UPDATE_TIME,
    STALE_NOT_STORED,
    STALE_SNAPSHOT_DIFFERS,
    _as_instant,
    _same_version,
    _staleness,
)

from .conftest import FakePayPalClient

UPDATED = "2026-10-30T10:00:00Z"


def listed(dispute_id="PP-D-1", update_time=UPDATED, **extra):
    item = {"dispute_id": dispute_id, **extra}
    if update_time is not None:
        item["update_time"] = update_time
    return item


def fetched(dispute_id="PP-D-1", update_time=UPDATED, **extra):
    return {
        "dispute_id": dispute_id,
        "update_time": update_time,
        "status": "WAITING_FOR_SELLER_RESPONSE",
        **extra,
    }


# -- (a) a listing with no update_time must not be skipped ----------------


def test_a_new_dispute_with_no_listed_update_time_is_fetched_and_stored():
    """The bug: None == None made this dispute look current forever."""
    fake = FakePayPalClient(
        listings=[[listed(update_time=None)]], snapshots=[fetched()]
    )
    webhooks.set_client(fake)

    counts = poller.poll_once()

    assert fake.fetch_calls == ["PP-D-1"], "the dispute was skipped, not fetched"
    assert counts["skipped"] == 0
    assert counts["processed"] == 1

    case = store.get_case("PP-D-1")
    assert case is not None
    assert case["snapshot"]["dispute_id"] == "PP-D-1"


def test_a_missing_listed_update_time_is_never_grounds_to_skip():
    """Stated at the unit level, stored or not."""
    reason, _ = _staleness("PP-D-NOTHING", None, _views({}))
    assert reason == STALE_NO_LISTED_UPDATE_TIME

    store.save_case_snapshot("PP-D-1", fetched())
    reason, _ = _staleness("PP-D-1", None, _views({"PP-D-1": UPDATED}))
    assert reason == STALE_NO_LISTED_UPDATE_TIME


def test_an_unparseable_listed_update_time_is_not_grounds_to_skip():
    store.save_case_snapshot("PP-D-1", fetched())

    reason, detail = _staleness(
        "PP-D-1", "whenever it was", _views({"PP-D-1": UPDATED})
    )

    assert reason == "listing_update_time_unparseable"
    assert detail["listed"] == "whenever it was"


def test_a_dispute_with_no_listed_update_time_is_not_refetched_forever():
    """Fetched once, then skipped: the fix must not create the other bug.

    With no update_time the event id is the same every pass, so the dispute
    is rebuilt rather than reprocessed -- but it is only fetched again
    because nothing can confirm its version. That is the honest outcome: a
    listing that reports no version cannot prove the stored one is current.
    """
    fake = FakePayPalClient(
        listings=[[listed(update_time=None)]],
        snapshots=[fetched(), fetched(), fetched()],
    )
    webhooks.set_client(fake)

    poller.poll_once()
    second = poller.poll_once()

    assert len(fake.fetch_calls) == 2
    # The second pass reuses the event row rather than claiming a new one.
    assert second["backfilled"] == 1
    assert second["processed"] == 0


# -- (b) an unchanged stored dispute is still skipped ---------------------


def test_an_unchanged_stored_dispute_is_skipped():
    fake = FakePayPalClient(listings=[[listed()]], snapshots=[fetched(), fetched()])
    webhooks.set_client(fake)

    poller.poll_once()
    second = poller.poll_once()

    assert fake.fetch_calls == ["PP-D-1"]
    assert second["skipped"] == 1
    assert second["processed"] == 0


def test_an_unchanged_dispute_stays_skipped_over_many_passes():
    fake = FakePayPalClient(
        listings=[[listed()]], snapshots=[fetched() for _ in range(8)]
    )
    webhooks.set_client(fake)

    poller.poll_once()
    for _ in range(5):
        counts = poller.poll_once()
        assert counts["skipped"] == 1

    assert fake.fetch_calls == ["PP-D-1"]


# -- (c) a changed update_time is re-fetched ------------------------------


def test_a_changed_listed_update_time_is_refetched():
    moved = "2026-10-31T11:30:00Z"
    fake = FakePayPalClient(
        listings=[[listed()], [listed(update_time=moved)]],
        snapshots=[fetched(), fetched(update_time=moved)],
    )
    webhooks.set_client(fake)

    poller.poll_once()
    second = poller.poll_once()

    assert fake.fetch_calls == ["PP-D-1", "PP-D-1"]
    assert second["processed"] == 1
    assert store.get_case("PP-D-1")["snapshot"]["update_time"] == moved


def test_a_dispute_not_stored_yet_is_never_skipped():
    reason, _ = _staleness("PP-D-UNSEEN", UPDATED, _views({}))
    assert reason == STALE_NOT_STORED


# -- the version comparison ----------------------------------------------


def _views(mapping):
    """A stand-in for the case-view store: dispute id -> update_time."""

    class Views:
        def get(self, dispute_id):
            if dispute_id not in mapping:
                return None
            return {"update_time": mapping[dispute_id]}

    return Views()


@pytest.mark.parametrize(
    "left,right",
    [
        # Identical.
        ("2026-10-29T23:40:33.803Z", "2026-10-29T23:40:33.803Z"),
        # Z against an explicit zero offset.
        ("2026-10-29T23:40:33Z", "2026-10-29T23:40:33+00:00"),
        # A non-UTC offset naming the same instant.
        ("2026-10-30T00:40:33+01:00", "2026-10-29T23:40:33Z"),
        # A zero fraction against none at all.
        ("2026-10-29T23:40:33.000Z", "2026-10-29T23:40:33Z"),
        # Whole seconds one side, a fraction the other: the same change,
        # rendered at two precisions. This is the pairing that caused the
        # permanent re-fetch loop.
        ("2026-10-29T23:40:33Z", "2026-10-29T23:40:33.803Z"),
        ("2026-10-29T23:40:33.803Z", "2026-10-29T23:40:33Z"),
        # Surrounding whitespace.
        (" 2026-10-29T23:40:33Z ", "2026-10-29T23:40:33Z"),
    ],
)
def test_the_same_version_spelled_differently_compares_equal(left, right):
    assert _same_version(left, right) is True


@pytest.mark.parametrize(
    "left,right",
    [
        # A different second.
        ("2026-10-29T23:40:34Z", "2026-10-29T23:40:33Z"),
        # Both carry a fraction and they differ: real precision is kept.
        ("2026-10-29T23:40:33.803Z", "2026-10-29T23:40:33.412Z"),
        # A different day.
        ("2026-10-30T23:40:33Z", "2026-10-29T23:40:33Z"),
        # Unusable input is never "the same version".
        (None, "2026-10-29T23:40:33Z"),
        ("2026-10-29T23:40:33Z", None),
        ("not a timestamp", "2026-10-29T23:40:33Z"),
        ("", "2026-10-29T23:40:33Z"),
    ],
)
def test_a_different_or_unusable_version_compares_unequal(left, right):
    assert _same_version(left, right) is False


def test_an_instant_is_normalised_to_utc():
    assert _as_instant("2026-10-30T00:40:33+01:00") == _as_instant(
        "2026-10-29T23:40:33Z"
    )
    assert _as_instant("junk") is None
    assert _as_instant(None) is None


# -- the production churn ------------------------------------------------


def test_a_listing_at_second_precision_no_longer_refetches_every_pass():
    """The churn, reproduced and fixed.

    The listing reports whole seconds; `get_dispute` reports milliseconds.
    Comparing the raw strings made this dispute permanently stale, so it was
    fetched on every pass -- one get_dispute per dispute per minute, and
    before the audit fix one chain entry too.
    """
    detailed = "2026-10-30T10:00:00.803Z"
    coarse = "2026-10-30T10:00:00Z"

    fake = FakePayPalClient(
        listings=[[listed(update_time=coarse)]],
        snapshots=[fetched(update_time=detailed) for _ in range(6)],
    )
    webhooks.set_client(fake)

    poller.poll_once()
    assert fake.fetch_calls == ["PP-D-1"]

    for _ in range(4):
        counts = poller.poll_once()
        assert counts["skipped"] == 1

    assert fake.fetch_calls == ["PP-D-1"], "the dispute is still being re-fetched"


def test_a_genuine_mismatch_is_named_in_the_log(caplog):
    """If it is not a format difference, the log says which values differ."""
    store.save_case_snapshot("PP-D-1", fetched(update_time="2026-10-01T00:00:00Z"))

    reason, detail = _staleness("PP-D-1", UPDATED, _views({"PP-D-1": UPDATED}))

    assert reason == STALE_SNAPSHOT_DIFFERS
    assert detail == {"listed": UPDATED, "stored": "2026-10-01T00:00:00Z"}


def test_the_rebuild_log_line_carries_the_reason_and_the_values(caplog):
    detailed = "2026-10-30T10:00:00Z"
    fake = FakePayPalClient(
        listings=[[listed(update_time=None)]],
        snapshots=[fetched(update_time=detailed) for _ in range(4)],
    )
    webhooks.set_client(fake)

    poller.poll_once()
    with caplog.at_level(logging.INFO, logger="orrix.poller"):
        poller.poll_once()

    assert "poll rebuilding" in caplog.text
    assert STALE_NO_LISTED_UPDATE_TIME in caplog.text


def test_a_stale_case_view_still_forces_a_rebuild():
    """The existing guarantee: the view must match too, not just the snapshot."""
    store.save_case_snapshot("PP-D-1", fetched())

    reason, detail = _staleness("PP-D-1", UPDATED, _views({}))

    assert reason == "view_missing_or_stale"
    assert detail["view"] is None
