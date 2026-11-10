"""The header's "polled Ns ago" must measure the poller, not the disputes.

It used to read MAX(received_at) over POLL.DISPUTE.SYNC events. Those rows
are keyed poll:<dispute>:<update_time>, so a pass over disputes that have not
changed inserts nothing and the maximum stops moving. A deployment polling
every 60 seconds showed "polled 139000s ago" -- the age of the last dispute
change, which is a different question.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from orrix import poller, store, webhooks
from orrix.web.services import poll_age_label

from .conftest import FakePayPalClient, actionable_snapshot, build_app_config


@pytest.fixture
def polled_db(tmp_path, monkeypatch):
    monkeypatch.setenv("ORRIX_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("POLLER_ENABLED", "true")
    store.init_db()
    yield tmp_path
    webhooks.set_client(None)
    webhooks.set_sync_deps(None)


def services_for(tmp_path):
    from orrix.web.services import Services

    return Services(build_app_config(tmp_path))


# -- the store records the pass ------------------------------------------


def test_no_pass_recorded_reads_as_never(polled_db):
    assert store.last_poll_completed_at() is None


def test_a_recorded_pass_is_readable(polled_db):
    store.record_poll_completed()
    assert store.last_poll_completed_at() is not None


def test_a_later_pass_overwrites_the_earlier_one(polled_db):
    store.record_poll_completed("2026-11-09T00:00:00+00:00")
    store.record_poll_completed("2026-11-10T00:00:00+00:00")

    assert store.last_poll_completed_at() == "2026-11-10T00:00:00+00:00"
    # One row, not a growing table.
    import sqlite3

    connection = sqlite3.connect(store.db_path())
    try:
        count = connection.execute("SELECT COUNT(*) FROM poll_runs").fetchone()[0]
    finally:
        connection.close()
    assert count == 1


# -- the poller records every pass ---------------------------------------


def test_a_pass_that_changed_nothing_still_records_the_poll(polled_db):
    """The bug, stated directly: an unchanged dispute must still tick."""
    snapshot = actionable_snapshot()
    listing = [
        {"dispute_id": snapshot["dispute_id"], "update_time": snapshot["update_time"]}
    ]
    client = FakePayPalClient(snapshots=[copy.deepcopy(snapshot) for _ in range(6)])
    client._listings = [listing]
    webhooks.set_client(client)

    poller.poll_once()
    first = store.last_poll_completed_at()
    assert first is not None

    store.record_poll_completed("2026-11-09T00:00:00+00:00")
    poller.poll_once()
    second = store.last_poll_completed_at()

    # Nothing changed between the two passes, and the marker still moved.
    assert second != "2026-11-09T00:00:00+00:00"
    assert poller.poll_once() is not None


def test_a_pass_over_no_disputes_at_all_still_records_the_poll(polled_db):
    client = FakePayPalClient()
    client._listings = [[]]
    webhooks.set_client(client)

    poller.poll_once()

    assert store.last_poll_completed_at() is not None


def test_a_failed_listing_does_not_claim_a_fresh_poll(polled_db):
    """PayPal unreachable is not a successful pass."""
    from orrix.paypal import PayPalError

    client = FakePayPalClient()
    client.list_error = PayPalError("boom", status_code=503)
    webhooks.set_client(client)

    poller.poll_once()

    assert store.last_poll_completed_at() is None


# -- the indicator reads the pass ----------------------------------------


def test_the_indicator_reports_seconds_since_the_pass_not_since_a_change(polled_db):
    long_ago = datetime.now(timezone.utc) - timedelta(seconds=139000)
    # An old dispute change ...
    store.insert_event_if_absent(
        "poll:PP-D-1:2026-11-01T00:00:00Z", poller.POLL_EVENT_TYPE, "PP-D-1"
    )
    import sqlite3

    connection = sqlite3.connect(store.db_path())
    try:
        with connection:
            connection.execute(
                "UPDATE events SET received_at = ?", (long_ago.isoformat(),)
            )
    finally:
        connection.close()

    # ... and a poll that completed a moment ago.
    store.record_poll_completed()

    status = services_for(polled_db).poll_status()

    assert status["seconds_ago"] is not None
    assert status["seconds_ago"] < 60, "the indicator read the dispute change, not the poll"
    assert "139000" not in status["label"]


def test_the_indicator_says_not_yet_before_the_first_pass(polled_db):
    status = services_for(polled_db).poll_status()

    assert status["seconds_ago"] is None
    assert status["label"] == "not yet"


def test_an_older_database_falls_back_to_the_event_timestamp(polled_db):
    """No recorded pass yet, but poll events exist: better than "not yet"."""
    store.insert_event_if_absent(
        "poll:PP-D-1:2026-11-01T00:00:00Z", poller.POLL_EVENT_TYPE, "PP-D-1"
    )

    status = services_for(polled_db).poll_status()

    assert status["seconds_ago"] is not None
    assert status["label"].startswith("polled ")


def test_the_units_are_seconds(polled_db):
    """A wrong unit is the other way this indicator goes wrong."""
    store.record_poll_completed(
        (datetime.now(timezone.utc) - timedelta(seconds=90)).isoformat()
    )

    status = services_for(polled_db).poll_status()

    assert 88 <= status["seconds_ago"] <= 95


# -- the label -----------------------------------------------------------


@pytest.mark.parametrize(
    "seconds,expected",
    [
        (0, "0s"),
        (1, "1s"),
        (59, "59s"),
        (60, "1m"),
        (119, "1m"),
        (3599, "59m"),
        (3600, "1h"),
        (86399, "23h"),
        (86400, "1d"),
        (139000, "1d"),
    ],
)
def test_the_age_label_is_readable(seconds, expected):
    assert poll_age_label(seconds) == expected


def test_a_large_age_never_renders_as_raw_seconds(polled_db):
    store.record_poll_completed(
        (datetime.now(timezone.utc) - timedelta(seconds=139000)).isoformat()
    )

    status = services_for(polled_db).poll_status()

    assert status["label"] == "polled 1d ago"
    assert "139000s" not in status["label"]
