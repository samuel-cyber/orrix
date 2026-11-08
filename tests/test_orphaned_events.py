"""Events that outlived their artifacts must not strand a dispute.

After the database-path fix, the events table carried poll markers from an
earlier deploy while the snapshots and case views those markers stood for
were gone. The poller treated the marker as proof the work was done, so it
skipped all six disputes forever and the queue showed one row.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

import pytest

from orrix import poller, store, webhooks
from orrix.config import AppConfig
from orrix.pipeline import STATUS_AWAITING_READER, sync_case
from orrix.web.services import Services

from .conftest import load_fixture

DISPUTE_IDS = (
    "PP-R-TAX-10197055",
    "PP-R-JAF-10195217",
    "PP-R-TWZ-10195219",
    "PP-R-DEK-10195221",
    "PP-R-PXL-10195222",
    "PP-R-DSM-10194429",
)
UPDATE_TIME = "2026-11-08T09:00:00.000Z"


def snapshot_for(dispute_id: str, update_time: str = UPDATE_TIME) -> dict:
    snapshot = load_fixture()
    snapshot["dispute_id"] = dispute_id
    snapshot["update_time"] = update_time
    return snapshot


class FakePayPal:
    """Lists and fetches the six disputes. Counts every call."""

    def __init__(self, update_time: str = UPDATE_TIME, missing: tuple[str, ...] = ()):
        self.update_time = update_time
        self.missing = set(missing)
        self.list_calls = 0
        self.fetches: list[str] = []

    def list_disputes(self, page_size=50, max_pages=20):
        self.list_calls += 1
        return [
            {"dispute_id": d, "update_time": self.update_time}
            for d in DISPUTE_IDS
        ]

    def get_dispute(self, dispute_id):
        self.fetches.append(dispute_id)
        if dispute_id in self.missing:
            from orrix.paypal import PayPalError

            raise PayPalError(
                f"get_dispute({dispute_id}) failed", status_code=404, debug_id="dbg-404"
            )
        return snapshot_for(dispute_id, self.update_time)


class NeverCalledReader:
    """Fails the test if the Reader is invoked on any of these paths."""

    def __init__(self):
        self.posts = 0

    def post(self, url, **kwargs):
        self.posts += 1
        raise AssertionError("the Reader must not be called by a sync or backfill")


@pytest.fixture
def deployment(monkeypatch, tmp_path):
    """One database, the way the fixed resolver gives it."""
    db = tmp_path / "var-data" / "deployment.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("ORRIX_DB", str(db))
    monkeypatch.delenv("ORRIX_DB_PATH", raising=False)

    config = AppConfig(
        db_path=str(db),
        admin_password="a-long-enough-password",
        session_secret="test-secret",
        poller_enabled=False,
        reader_api_key="sk-must-not-be-used",
    )
    store.init_db()
    webhooks.set_sync_deps(None)
    return config, db


def strand_the_events(update_time: str = UPDATE_TIME) -> None:
    """The state the deployment was actually in.

    Poll events for every dispute, and nothing else: no snapshots, no case
    views. Exactly what an earlier deploy left behind.
    """
    for dispute_id in DISPUTE_IDS:
        store.insert_event_if_absent(
            f"poll:{dispute_id}:{update_time}",
            "POLL.DISPUTE.SYNC",
            dispute_id,
            status="processed",
        )


def listed(config, paypal):
    services = Services(config, paypal_reader=paypal, reader_client=NeverCalledReader())
    return [services.case_view(d) for d in services.list_dispute_ids()]


# -- the reproduction ----------------------------------------------------


def test_orphaned_events_do_not_strand_the_queue(deployment):
    """Six events, no artifacts. One poll must rebuild all six."""
    config, _ = deployment
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    strand_the_events()

    assert store.count_events() == 6, "the markers are there"
    assert store.count_cases() == 0, "but nothing they stand for is"

    counts = poller.poll_once()

    assert counts["skipped"] == 0, (
        f"an event with no snapshot is not work already done: {counts}"
    )
    assert counts["backfilled"] == 6
    assert store.count_cases() == 6

    views = listed(config, paypal)
    assert len(views) == 6
    assert sorted(v.dispute_id for v in views) == sorted(DISPUTE_IDS)


def test_the_stranded_dispute_opens(deployment):
    """PP-R-TAX-10197055 said "No such case"."""
    config, _ = deployment
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    strand_the_events()

    poller.poll_once()

    services = Services(config, paypal_reader=paypal, reader_client=NeverCalledReader())
    assert services.case_snapshot("PP-R-TAX-10197055") is not None
    assert services.case_view("PP-R-TAX-10197055") is not None


def test_rebuilding_reuses_the_existing_event_row(deployment):
    """No duplicate event: the marker is reused, not re-created."""
    config, _ = deployment
    webhooks.set_client(FakePayPal())
    strand_the_events()

    before = store.count_events()
    poller.poll_once()

    assert store.count_events() == before == 6
    event = store.get_event(f"poll:{DISPUTE_IDS[0]}:{UPDATE_TIME}")
    assert event is not None
    assert event["status"] == "processed"


# -- a healthy second poll still skips -----------------------------------


def test_a_second_poll_skips_everything_without_refetching(deployment):
    config, _ = deployment
    paypal = FakePayPal()
    webhooks.set_client(paypal)

    first = poller.poll_once()
    fetches_after_first = len(paypal.fetches)
    second = poller.poll_once()

    assert first["processed"] == 6
    assert second == {
        "listed": 6,
        "processed": 0,
        "skipped": 6,
        "backfilled": 0,
        "failed": 0,
    }
    assert len(paypal.fetches) == fetches_after_first == 6, "no refetch"


def test_the_poll_log_reports_every_count(deployment, caplog):
    config, _ = deployment
    webhooks.set_client(FakePayPal())

    with caplog.at_level(logging.INFO, logger="orrix.poller"):
        poller.poll_once()

    assert "status=complete" in caplog.text
    for field in ("listed=", "processed=", "skipped=", "backfilled=", "failed="):
        assert field in caplog.text, field


# -- missing artifacts are rebuilt ---------------------------------------


def delete_case_view(db: Path, dispute_id: str) -> None:
    with sqlite3.connect(str(db)) as connection:
        connection.execute("DELETE FROM case_views WHERE dispute_id = ?", (dispute_id,))


def test_a_deleted_case_view_is_rebuilt_on_the_next_poll(deployment):
    config, db = deployment
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    poller.poll_once()

    target = DISPUTE_IDS[2]
    delete_case_view(db, target)
    services = Services(config, paypal_reader=paypal, reader_client=NeverCalledReader())
    assert services.case_views.get(target) is None

    counts = poller.poll_once()

    assert counts["backfilled"] == 1, f"only the broken one is rebuilt: {counts}"
    assert counts["skipped"] == 5
    assert services.case_views.get(target) is not None


def test_a_deleted_snapshot_is_rebuilt_on_the_next_poll(deployment):
    config, db = deployment
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    poller.poll_once()

    target = DISPUTE_IDS[3]
    with sqlite3.connect(str(db)) as connection:
        connection.execute("DELETE FROM cases WHERE dispute_id = ?", (target,))
    assert store.get_case(target) is None

    counts = poller.poll_once()

    assert counts["backfilled"] == 1
    assert counts["skipped"] == 5
    assert store.get_case(target) is not None


def test_a_stale_case_view_is_rebuilt(deployment):
    """A view left at an older update_time is not current."""
    config, db = deployment
    webhooks.set_client(FakePayPal())
    poller.poll_once()

    target = DISPUTE_IDS[1]
    with sqlite3.connect(str(db)) as connection:
        connection.execute(
            "UPDATE case_views SET update_time = ? WHERE dispute_id = ?",
            ("2020-01-01T00:00:00.000Z", target),
        )

    counts = poller.poll_once()

    assert counts["backfilled"] == 1
    services = Services(config, reader_client=NeverCalledReader())
    assert services.case_views.get(target)["update_time"] == UPDATE_TIME


# -- the startup backfill ------------------------------------------------


def test_the_startup_backfill_builds_missing_views(deployment, caplog):
    from orrix.pipeline import backfill_missing_views

    config, db = deployment
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    poller.poll_once()

    # Snapshots survive; the views do not.
    for dispute_id in DISPUTE_IDS[:4]:
        delete_case_view(db, dispute_id)

    services = Services(config, paypal_reader=paypal, reader_client=NeverCalledReader())
    with caplog.at_level(logging.INFO, logger="orrix.pipeline"):
        counts = backfill_missing_views(
            services.sync_deps(),
            store.all_dispute_ids(),
            lambda d: (store.get_case(d) or {}).get("snapshot"),
        )

    assert counts == {"checked": 6, "backfilled": 4, "failed": 0}
    assert "backfill complete" in caplog.text
    assert "backfilled=4" in caplog.text
    assert services.case_views.count() == 6
    # No PayPal call either: the backfill works from stored snapshots.
    assert len(paypal.fetches) == 6, "only the original poll fetched"


def test_the_backfill_leaves_existing_views_alone(deployment):
    from orrix.pipeline import backfill_missing_views

    config, _ = deployment
    webhooks.set_client(FakePayPal())
    poller.poll_once()

    services = Services(config, reader_client=NeverCalledReader())
    counts = backfill_missing_views(
        services.sync_deps(),
        store.all_dispute_ids(),
        lambda d: (store.get_case(d) or {}).get("snapshot"),
    )

    assert counts == {"checked": 6, "backfilled": 0, "failed": 0}


def test_the_backfill_reports_a_snapshot_it_cannot_read(deployment, caplog):
    from orrix.pipeline import backfill_missing_views

    config, _ = deployment
    services = Services(config, reader_client=NeverCalledReader())

    with caplog.at_level(logging.WARNING, logger="orrix.pipeline"):
        counts = backfill_missing_views(
            services.sync_deps(), ["PP-R-GONE"], lambda d: None
        )

    assert counts == {"checked": 1, "backfilled": 0, "failed": 1}
    assert "step=load_snapshot" in caplog.text


def test_the_app_backfills_at_startup(deployment, caplog):
    """End to end through create_app's lifespan."""
    from fastapi.testclient import TestClient
    from orrix.main import create_app

    config, db = deployment
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    poller.poll_once()
    for dispute_id in DISPUTE_IDS[:3]:
        delete_case_view(db, dispute_id)

    app = create_app(config=config, paypal_reader=paypal, reader_client=NeverCalledReader())
    with caplog.at_level(logging.INFO, logger="orrix.pipeline"):
        with TestClient(app, follow_redirects=False) as client:
            assert client.get("/health").status_code == 200

    assert "backfilled=3" in caplog.text
    assert app.state.services.case_views.count() == 6


# -- opening a case Orrix has not synced ---------------------------------


def test_opening_an_unsynced_case_fetches_it_once(deployment):
    config, _ = deployment
    paypal = FakePayPal()
    services = Services(config, paypal_reader=paypal, reader_client=NeverCalledReader())
    dispute_id = "PP-R-TAX-10197055"

    assert services.case_snapshot(dispute_id) is None

    snapshot = services.fetch_and_store(dispute_id)

    assert snapshot is not None
    assert paypal.fetches == [dispute_id]
    assert services.case_snapshot(dispute_id) is not None
    view = services.case_view(dispute_id)
    assert view is not None
    assert view.status == STATUS_AWAITING_READER, "still no Reader call"


def test_a_paypal_404_still_reports_no_such_case(deployment):
    config, _ = deployment
    paypal = FakePayPal(missing=("PP-R-NOT-A-DISPUTE",))
    services = Services(config, paypal_reader=paypal, reader_client=NeverCalledReader())

    assert services.fetch_and_store("PP-R-NOT-A-DISPUTE") is None
    assert services.case_snapshot("PP-R-NOT-A-DISPUTE") is None


def test_the_case_page_fetches_on_demand_and_404s_honestly(deployment):
    from fastapi.testclient import TestClient
    from orrix.main import create_app

    from .conftest import ADMIN_PASSWORD

    config, _ = deployment
    paypal = FakePayPal(missing=("PP-R-NOT-A-DISPUTE",))
    app = create_app(config=config, paypal_reader=paypal, reader_client=NeverCalledReader())

    with TestClient(app, follow_redirects=False) as client:
        client.post("/login", data={"password": "a-long-enough-password"})

        found = client.get("/cases/PP-R-TAX-10197055", follow_redirects=True)
        missing = client.get("/cases/PP-R-NOT-A-DISPUTE", follow_redirects=True)

    assert found.status_code == 200
    assert "PP-R-TAX-10197055" in found.text
    assert missing.status_code == 404
    assert "No such case" in missing.text


# -- none of this calls the Reader ---------------------------------------


def test_no_recovery_path_calls_the_reader(deployment):
    """Backfill, rebuild and on-demand fetch are all Reader-free."""
    from orrix.pipeline import backfill_missing_views

    config, db = deployment
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    reader = NeverCalledReader()
    strand_the_events()

    poller.poll_once()                      # rebuild from orphaned events
    delete_case_view(db, DISPUTE_IDS[0])
    poller.poll_once()                      # rebuild a deleted view

    services = Services(config, paypal_reader=paypal, reader_client=reader)
    backfill_missing_views(
        services.sync_deps(),
        store.all_dispute_ids(),
        lambda d: (store.get_case(d) or {}).get("snapshot"),
    )
    services.fetch_and_store("PP-R-TAX-10197055")
    listed(config, paypal)

    # NeverCalledReader raises on use, so arriving here is the assertion.
    assert reader.posts == 0
    assert services.sync_deps().reader_config is None
