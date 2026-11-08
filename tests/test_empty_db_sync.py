"""The production bug: a poll fills the queue but /api/cases stays empty.

On Render the poller logged processed=5 while /api/cases returned []. The
poller and the web layer were resolving the database path differently, so
they used two different files.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

import pytest

from orrix import poller, store, webhooks
from orrix.config import AppConfig, load_config
from orrix.main import create_app
from orrix.web.services import Services

from .conftest import FIXTURES_DIR, load_fixture

# The five sandbox disputes the real poll saw.
DISPUTE_IDS = (
    "PP-R-JAF-10195217",
    "PP-R-TWZ-10195219",
    "PP-R-DEK-10195221",
    "PP-R-PXL-10195222",
    "PP-R-DSM-10194429",
)


def snapshot_for(dispute_id: str) -> dict:
    """A distinct dispute per id, built from the saved fixture."""
    snapshot = load_fixture()
    snapshot["dispute_id"] = dispute_id
    snapshot["update_time"] = "2026-11-08T09:00:00.000Z"
    return snapshot


class FakePayPal:
    """Lists and fetches the five disputes. No network."""

    def __init__(self):
        self.list_calls = 0
        self.fetches: list[str] = []

    def list_disputes(self, page_size=50, max_pages=20):
        self.list_calls += 1
        return [
            {
                "dispute_id": dispute_id,
                "update_time": "2026-11-08T09:00:00.000Z",
                "reason": "MERCHANDISE_OR_SERVICE_NOT_RECEIVED",
                "status": "WAITING_FOR_SELLER_RESPONSE",
            }
            for dispute_id in DISPUTE_IDS
        ]

    def get_dispute(self, dispute_id):
        self.fetches.append(dispute_id)
        return snapshot_for(dispute_id)


class NeverCalledReader:
    """A model session that fails the test if the Reader is invoked."""

    def __init__(self):
        self.posts = 0

    def post(self, url, **kwargs):
        self.posts += 1
        raise AssertionError(
            "the Reader was called during sync; this spends model credits "
            "on every poll"
        )


# -- the production path resolution --------------------------------------


def test_the_poller_and_the_web_layer_resolve_the_same_database(monkeypatch, tmp_path):
    """render.yaml sets ORRIX_DB only. Both sides must honour it.

    This is the bug: store.db_path() read ORRIX_DB_PATH and ignored
    ORRIX_DB, so the poller wrote ./orrix.db while the web layer read
    /var/data/orrix.db.
    """
    target = str(tmp_path / "var-data" / "orrix.db")
    monkeypatch.setenv("ORRIX_DB", target)
    monkeypatch.delenv("ORRIX_DB_PATH", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("ORRIX_ENV", "development")

    assert load_config().db_path == target, "config honours ORRIX_DB"
    assert store.db_path() == target, (
        "store must resolve the same path as the config, or the poller "
        "writes one database and the console reads another"
    )


# -- the reproduction ----------------------------------------------------


@pytest.fixture
def production_like(monkeypatch, tmp_path):
    """A fresh deployment: empty database, ORRIX_DB set the way Render does."""
    db = tmp_path / "var-data" / "orrix.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("ORRIX_DB", str(db))
    monkeypatch.delenv("ORRIX_DB_PATH", raising=False)

    config = AppConfig(
        db_path=str(db),
        admin_password="a-long-enough-password",
        session_secret="test-secret",
        poller_enabled=False,
        reader_api_key="sk-must-not-be-used",
        session_ttl_seconds=3600,
    )
    return config, db


def test_one_poll_on_an_empty_database_populates_the_queue(production_like):
    """The reported symptom, end to end: poll then list."""
    config, db = production_like
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    store.init_db()

    assert store.count_cases() == 0, "starting from empty"

    counts = poller.poll_once()

    assert counts["processed"] == 5, "the poll reports five synced"
    assert store.count_cases() == 5, "and five snapshots are stored"

    # The same call that backs GET /api/cases.
    services = Services(config, paypal_reader=paypal, reader_client=NeverCalledReader())
    ids = services.list_dispute_ids()

    assert sorted(ids) == sorted(DISPUTE_IDS), (
        f"the console sees {len(ids)} of the 5 synced disputes"
    )


def test_a_failing_list_query_is_logged_not_swallowed(production_like, caplog):
    """An unreadable cases table must say so, not quietly return []."""
    config, db = production_like
    # A database with no schema at all: the table is missing.
    sqlite3.connect(str(db)).close()
    services = Services(config)

    with caplog.at_level(logging.WARNING):
        rows = services.list_dispute_ids()

    assert rows == []
    assert "cases" in caplog.text.lower()
    assert "operationalerror" in caplog.text.lower()


# -- the queue is populated, and the Reader stays out of it --------------


def list_rows(config, paypal):
    """Exactly what GET /api/cases builds its rows from."""
    services = Services(config, paypal_reader=paypal, reader_client=NeverCalledReader())
    return [services.case_view(d) for d in services.list_dispute_ids()]


def test_one_poll_gives_every_dispute_a_listable_row(production_like):
    config, _ = production_like
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    webhooks.set_sync_deps(None)
    store.init_db()

    poller.poll_once()
    views = list_rows(config, paypal)

    assert len(views) == 5
    assert all(view is not None for view in views)
    assert sorted(v.dispute_id for v in views) == sorted(DISPUTE_IDS)


def test_every_listed_row_carries_what_the_grid_shows(production_like):
    config, _ = production_like
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    webhooks.set_sync_deps(None)
    store.init_db()

    poller.poll_once()

    for view in list_rows(config, paypal):
        facts = view.facts
        assert facts is not None, view.dispute_id
        assert facts.value("dispute_id") == view.dispute_id
        assert facts.value("reason") == "MERCHANDISE_OR_SERVICE_NOT_RECEIVED"
        assert facts.value("status") == "WAITING_FOR_SELLER_RESPONSE"
        assert facts.value("dispute_state") == "REQUIRED_ACTION"
        assert str(facts.value("dispute_amount")) == "20.00"
        assert facts.value("dispute_currency") == "USD"
        assert facts.value("seller_response_due_date")
        assert view.status, "every row has an Orrix status"


def test_a_synced_case_reports_awaiting_reader(production_like):
    """The Reader has not run, and the status says so."""
    from orrix.pipeline import STATUS_AWAITING_READER, status_label

    config, _ = production_like
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    webhooks.set_sync_deps(None)
    store.init_db()

    poller.poll_once()
    views = list_rows(config, paypal)

    assert all(view.reader_pending for view in views)
    # These fixtures have no seller tracking, so policy permits nothing and
    # the pending Reader is the most useful thing to show.
    assert {view.status for view in views} == {STATUS_AWAITING_READER}
    assert status_label(STATUS_AWAITING_READER) == "Awaiting reader"


def test_syncing_never_calls_the_reader(production_like):
    """The whole point: a 60-second poll must cost no model credits."""
    config, _ = production_like
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    webhooks.set_sync_deps(None)
    store.init_db()

    reader = NeverCalledReader()
    poller.poll_once()
    Services(config, paypal_reader=paypal, reader_client=reader)
    list_rows(config, paypal)

    # NeverCalledReader raises on use, so reaching here is the assertion.
    assert reader.posts == 0


def test_the_sync_path_has_no_model_configured(production_like):
    """Structural, not a promise: sync is handed no reader_config."""
    config, _ = production_like
    services = Services(config)

    assert config.reader_is_configured, "a key IS present in this config"
    assert services.sync_deps().reader_config is None, (
        "yet the sync path cannot call a model, because it has none"
    )


# -- a second poll changes nothing ---------------------------------------


def test_a_second_poll_adds_no_duplicate_rows(production_like):
    config, _ = production_like
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    webhooks.set_sync_deps(None)
    store.init_db()

    poller.poll_once()
    first = poller.poll_once()

    assert first["processed"] == 0, "nothing changed, so nothing to do"
    assert first["skipped"] == 5
    assert store.count_cases() == 5
    assert len(list_rows(config, paypal)) == 5

    services = Services(config, paypal_reader=paypal)
    assert services.case_views.count() == 5, "one view per dispute, not two"


def test_a_second_poll_does_not_refetch_or_read(production_like):
    config, _ = production_like
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    webhooks.set_sync_deps(None)
    store.init_db()

    poller.poll_once()
    fetches_after_first = len(paypal.fetches)
    poller.poll_once()

    assert len(paypal.fetches) == fetches_after_first == 5


# -- the Reader runs lazily, once ----------------------------------------


class CountingReader:
    """A model session that answers once and counts calls."""

    def __init__(self):
        self.posts = 0

    def post(self, url, **kwargs):
        self.posts += 1
        body = json.dumps(
            {
                "claim_type": "NOT_RECEIVED",
                "claimed_amount": "20.00",
                "language": "en",
                "seller_summary": "Buyer reports the parcel did not arrive.",
            }
        )

        class Response:
            status_code = 200
            headers: dict = {}

            def json(self_inner):
                return {"choices": [{"message": {"content": body}}]}

        return Response()


def test_opening_a_case_runs_the_reader_exactly_once(production_like):
    """Lazily, and only once per dispute version."""
    from orrix.pipeline import process_case

    config, _ = production_like
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    webhooks.set_sync_deps(None)
    store.init_db()
    poller.poll_once()

    reader = CountingReader()
    services = Services(config, paypal_reader=paypal, reader_client=reader)
    dispute_id = DISPUTE_IDS[0]
    snapshot = services.case_snapshot(dispute_id)

    # Listing the queue first: still no model call.
    list_rows(config, paypal)
    assert reader.posts == 0

    first = process_case(snapshot, services.pipeline_deps)
    assert reader.posts == 1, "opening the case runs the Reader"
    assert first.reader_result.ok
    assert first.reader_pending is False

    # Opening it again reuses the stored result.
    second = process_case(snapshot, services.pipeline_deps)
    assert reader.posts == 1, "a second open must not spend another call"
    assert second.reader_result.ok
    assert second.reader_result.form.claim_type == first.reader_result.form.claim_type


def test_after_the_reader_runs_the_row_is_no_longer_pending(production_like):
    from orrix.pipeline import process_case

    config, _ = production_like
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    webhooks.set_sync_deps(None)
    store.init_db()
    poller.poll_once()

    services = Services(config, paypal_reader=paypal, reader_client=CountingReader())
    dispute_id = DISPUTE_IDS[0]
    process_case(services.case_snapshot(dispute_id), services.pipeline_deps)

    refreshed = services.case_view(dispute_id)

    assert refreshed.reader_pending is False
    assert refreshed.status != "awaiting_reader"


# -- an already-answered dispute -----------------------------------------


def answered_snapshot(dispute_id: str) -> dict:
    """Evidence already submitted; the dispute sits with the buyer."""
    snapshot = snapshot_for(dispute_id)
    snapshot["status"] = "WAITING_FOR_BUYER_RESPONSE"
    snapshot["dispute_state"] = "REQUIRED_OTHER_PARTY_ACTION"
    snapshot.pop("seller_response_due_date", None)
    snapshot["evidences"].append(
        {
            "evidence_type": "PROOF_OF_FULFILLMENT",
            "source": "SUBMITTED_BY_SELLER",
            "date": "2026-11-01T10:00:00.000Z",
            "evidence_info": {
                "tracking_info": [{"carrier_name": "FEDEX", "tracking_number": "123456789"}]
            },
        }
    )
    return snapshot


def test_an_already_answered_dispute_shows_its_state_and_offers_no_action(production_like):
    from orrix.pipeline import STATUS_AWAITING_BUYER, status_label, sync_case

    config, _ = production_like
    dispute_id = DISPUTE_IDS[4]
    store.init_db()
    store.save_case_snapshot(dispute_id, answered_snapshot(dispute_id))

    services = Services(config, reader_client=NeverCalledReader())
    view = sync_case(answered_snapshot(dispute_id), services.sync_deps())

    # The settled state wins over "awaiting reader".
    assert view.status == STATUS_AWAITING_BUYER
    assert status_label(view.status) == "Evidence submitted, waiting for buyer"
    # And no approval is offered.
    assert view.decision.allowed_actions == frozenset()
    assert "evidence_submitted_awaiting_buyer" in view.decision.reasons
    # A missing seller deadline is not treated as a defect in this state.
    assert "facts_incomplete" not in view.decision.flags
    assert view.facts.value("status") == "WAITING_FOR_BUYER_RESPONSE"


# -- failures are visible ------------------------------------------------


def test_a_pipeline_step_failure_is_logged_with_dispute_step_and_exception(
    production_like, caplog
):
    from orrix.pipeline import sync_case

    config, _ = production_like
    services = Services(config)

    broken = snapshot_for("PP-R-BROKEN-1")
    broken["dispute_id"] = "not a valid id!!"

    with caplog.at_level(logging.WARNING):
        view = sync_case(broken, services.sync_deps())

    assert view.status == "facts_failed"
    assert "step=build_facts" in caplog.text
    assert "exception=FactsIntegrityError" in caplog.text
    assert "dispute_id=" in caplog.text


def test_an_indexing_failure_during_sync_is_logged_not_swallowed(production_like, caplog):
    config, _ = production_like
    paypal = FakePayPal()
    webhooks.set_client(paypal)
    store.init_db()

    class ExplodingDeps:
        def __getattr__(self, name):
            raise RuntimeError("case view store is unavailable")

    webhooks.set_sync_deps(ExplodingDeps())

    with caplog.at_level(logging.WARNING):
        webhooks.refresh_case("poll:x", "POLL.DISPUTE.SYNC", DISPUTE_IDS[0])

    assert "step=sync_case" in caplog.text
    assert "exception=RuntimeError" in caplog.text
    # The snapshot was still stored, so nothing is lost.
    assert store.get_case(DISPUTE_IDS[0]) is not None
    webhooks.set_sync_deps(None)
