"""After a confirmed execution, the case must show the post-write record.

The hosted app reported "Evidence submitted and confirmed on the re-fetched
dispute" and then went on showing the pre-execution record: old status,
evidence_submitted false, the Approve button still live. The executor already
re-fetched the dispute to confirm the write; that record was simply thrown
away.

Two things are tested here: the confirming re-fetch becomes the case's
record, and a later poll carrying an older view of the same dispute cannot
undo it.

PayPal is mocked throughout. Nothing here touches write capability or the
approval binding.
"""

from __future__ import annotations

import copy
import re

import pytest
from fastapi.testclient import TestClient

from orrix import poller, store, webhooks
from orrix.executor import (
    REASON_CONFIRMATION_NOT_STORED,
    ExecutorDeps,
    build_evidence_payload,
    execute,
)
from orrix.facts import build_facts
from orrix.main import create_app
from orrix.policy import PROVIDE_EVIDENCE, CaseState, decide
from orrix.web.security import CSRF_FIELD

from .conftest import (
    ADMIN_PASSWORD,
    FakePayPalClient,
    FakeWriter,
    actionable_snapshot,
    approve_from,
    build_app_config,
    recorded_snapshot,
)


def submitted_snapshot(base=None):
    """The record as PayPal reports it after the evidence has landed.

    Carries the seller's proof and has moved on: the dispute is with the
    buyer now, and update_time is later than the pre-write record's.
    """
    snapshot = recorded_snapshot(base or actionable_snapshot())
    snapshot["status"] = "WAITING_FOR_BUYER_RESPONSE"
    snapshot["dispute_state"] = "REQUIRED_OTHER_PARTY_ACTION"
    snapshot["update_time"] = "2026-11-10T12:00:00.000Z"
    return snapshot


@pytest.fixture
def executed_app(tmp_path, monkeypatch):
    """An app whose one case has been executed against, end to end."""
    monkeypatch.setenv("ORRIX_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("POLLER_ENABLED", "false")
    store.init_db()

    before = actionable_snapshot()
    after = submitted_snapshot(before)
    dispute_id = before["dispute_id"]
    store.save_case_snapshot(dispute_id, before)

    reader = FakePayPalClient(snapshots=[copy.deepcopy(before), copy.deepcopy(after)])
    writer = FakeWriter()
    config = build_app_config(tmp_path)

    client = TestClient(create_app(config=config, paypal_reader=reader, writer=writer))
    with client:
        client.post("/login", data={"password": ADMIN_PASSWORD}, follow_redirects=False)
        page = client.get(f"/cases/{dispute_id}")
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)

        client.post(
            f"/cases/{dispute_id}/approve",
            data={
                CSRF_FIELD: token,
                "dispute_update_time": before["update_time"],
                "dispute_status": before["status"],
            },
            follow_redirects=False,
        )
        yield client, dispute_id, before, after, writer


# -- (a) the confirming re-fetch becomes the record -----------------------


def test_the_stored_snapshot_is_the_refetched_record(executed_app):
    client, dispute_id, before, after, writer = executed_app

    assert writer.calls, "the write never happened; the rest proves nothing"

    stored = store.get_case(dispute_id)["snapshot"]

    assert stored["update_time"] == after["update_time"]
    assert stored["status"] == after["status"]
    assert stored != before


def test_the_facts_show_the_post_write_record(executed_app):
    client, dispute_id, _, after, _ = executed_app

    stored = store.get_case(dispute_id)["snapshot"]
    facts = build_facts(stored, expected_dispute_id=dispute_id)

    assert facts.value("evidence_submitted") is True
    assert facts.value("status") == "WAITING_FOR_BUYER_RESPONSE"


def test_the_policy_allows_nothing_once_the_evidence_is_in(executed_app):
    client, dispute_id, _, _, _ = executed_app

    stored = store.get_case(dispute_id)["snapshot"]
    facts = build_facts(stored, expected_dispute_id=dispute_id)
    decision = decide(
        facts,
        None,
        CaseState(dispute_id=dispute_id, executed_actions=frozenset({PROVIDE_EVIDENCE})),
        None,
    )

    assert PROVIDE_EVIDENCE not in decision.allowed_actions
    assert decision.allowed_actions == frozenset()


def test_the_case_page_has_no_enabled_approve_button(executed_app):
    client, dispute_id, _, _, _ = executed_app

    page = client.get(f"/cases/{dispute_id}")

    assert page.status_code == 200
    # No live approve form at all.
    assert f"/cases/{dispute_id}/approve" not in page.text
    # And nothing that could be clicked to submit again.
    enabled = re.findall(r"<button[^>]*>\s*Approve and submit evidence", page.text)
    assert enabled == []


def test_the_case_page_shows_the_submitted_state_with_the_approval_id(executed_app):
    client, dispute_id, _, _, _ = executed_app

    page = client.get(f"/cases/{dispute_id}")

    assert "Evidence submitted" in page.text
    assert "data-evidence-submitted" in page.text

    executed = client.app.state.services.executed_approval_for(dispute_id)
    assert executed is not None
    assert executed["approval_id"][:16] in page.text


def test_the_case_page_shows_the_new_status_and_evidence_submitted(executed_app):
    client, dispute_id, _, _, _ = executed_app

    page = client.get(f"/cases/{dispute_id}")

    assert "WAITING_FOR_BUYER_RESPONSE" in page.text
    # The facts table carries evidence_submitted as a true value.
    assert re.search(r"evidence_submitted</td>\s*<td[^>]*>True", page.text)


def test_reopening_the_page_does_not_offer_the_button_again(executed_app):
    """Durable: driven by the executed-approval ledger, not by memory."""
    client, dispute_id, _, _, _ = executed_app

    for _ in range(3):
        page = client.get(f"/cases/{dispute_id}")
        assert f"/cases/{dispute_id}/approve" not in page.text


def test_a_fresh_process_still_shows_the_submitted_state(executed_app, tmp_path):
    """A restart loses the in-memory result; the ledger survives it."""
    client, dispute_id, _, _, _ = executed_app

    config = build_app_config(tmp_path)
    reader = FakePayPalClient(snapshots=[store.get_case(dispute_id)["snapshot"]])
    with TestClient(create_app(config=config, paypal_reader=reader)) as fresh:
        fresh.post("/login", data={"password": ADMIN_PASSWORD}, follow_redirects=False)
        page = fresh.get(f"/cases/{dispute_id}")

    assert "Evidence submitted" in page.text
    assert f"/cases/{dispute_id}/approve" not in page.text


def test_the_case_view_was_reindexed_not_left_stale(executed_app):
    """The queue reads the stored view, so it must move too."""
    client, dispute_id, _, after, _ = executed_app

    row = client.app.state.services.case_views.get(dispute_id)

    assert row is not None
    assert row["update_time"] == after["update_time"]


# -- the executor reports a persistence failure honestly ------------------


def test_a_sink_that_raises_is_reported_rather_than_claimed_as_clean(
    tmp_path, audit_log, executed, policy_config
):
    snapshot = actionable_snapshot()
    payload = build_evidence_payload(
        build_facts(snapshot, expected_dispute_id=snapshot["dispute_id"])
    )
    approval = approve_from(snapshot, payload=payload)

    def exploding_sink(dispute_id, confirmation):
        raise RuntimeError("disk full")

    result = execute(
        approval,
        ExecutorDeps(
            paypal_reader=FakePayPalClient(
                snapshots=[snapshot, recorded_snapshot(snapshot)]
            ),
            writer=FakeWriter(),
            audit=audit_log,
            executed=executed,
            policy_config=policy_config,
            persist_confirmation=exploding_sink,
        ),
    )

    # The write landed and is confirmed, so it is still "executed" -- but the
    # operator is told the console's copy is behind.
    assert result.status == "executed"
    assert result.reason == REASON_CONFIRMATION_NOT_STORED
    assert result.requires_review is True
    assert result.writes_attempted == 1


def test_no_sink_still_executes(tmp_path, audit_log, executed, policy_config):
    """A replay harness or a script has no console to leave stale."""
    snapshot = actionable_snapshot()
    payload = build_evidence_payload(
        build_facts(snapshot, expected_dispute_id=snapshot["dispute_id"])
    )
    approval = approve_from(snapshot, payload=payload)

    result = execute(
        approval,
        ExecutorDeps(
            paypal_reader=FakePayPalClient(
                snapshots=[snapshot, recorded_snapshot(snapshot)]
            ),
            writer=FakeWriter(),
            audit=audit_log,
            executed=executed,
            policy_config=policy_config,
        ),
    )

    assert result.status == "executed"
    assert result.reason is None


def test_the_web_layer_always_supplies_a_sink(tmp_path, monkeypatch):
    """Production must never execute without somewhere to put the record."""
    monkeypatch.setenv("ORRIX_DB_PATH", str(tmp_path / "test.db"))
    store.init_db()

    from orrix.web.services import Services

    deps = Services(build_app_config(tmp_path)).executor_deps(dispute_id="PP-D-1")

    assert deps.persist_confirmation is not None


# -- (b) a stale poll cannot regress it -----------------------------------


def test_a_stale_poll_cannot_regress_the_confirmed_record(executed_app):
    """The whole point of the update_time comparison."""
    client, dispute_id, before, after, _ = executed_app

    # A poll returns the pre-write view of the same dispute.
    stale = FakePayPalClient(
        listings=[[{"dispute_id": dispute_id, "update_time": before["update_time"]}]],
        snapshots=[copy.deepcopy(before) for _ in range(4)],
    )
    webhooks.set_client(stale)
    try:
        poller.poll_once()
        poller.poll_once()
    finally:
        webhooks.set_client(None)

    stored = store.get_case(dispute_id)["snapshot"]

    assert stored["update_time"] == after["update_time"]
    assert stored["status"] == after["status"]

    page = client.get(f"/cases/{dispute_id}")
    assert f"/cases/{dispute_id}/approve" not in page.text


def test_the_store_refuses_an_older_record(tmp_path, monkeypatch):
    monkeypatch.setenv("ORRIX_DB_PATH", str(tmp_path / "test.db"))
    store.init_db()

    newer = submitted_snapshot()
    older = actionable_snapshot()
    dispute_id = newer["dispute_id"]

    assert store.save_case_snapshot_if_not_older(dispute_id, newer) is True
    assert store.save_case_snapshot_if_not_older(dispute_id, older) is False

    assert store.get_case(dispute_id)["snapshot"]["update_time"] == newer["update_time"]


def test_the_store_accepts_an_equal_or_newer_record(tmp_path, monkeypatch):
    monkeypatch.setenv("ORRIX_DB_PATH", str(tmp_path / "test.db"))
    store.init_db()

    first = actionable_snapshot()
    dispute_id = first["dispute_id"]
    store.save_case_snapshot_if_not_older(dispute_id, first)

    same = copy.deepcopy(first)
    same["status"] = "UNDER_REVIEW"
    assert store.save_case_snapshot_if_not_older(dispute_id, same) is True

    later = submitted_snapshot(first)
    assert store.save_case_snapshot_if_not_older(dispute_id, later) is True
    assert store.get_case(dispute_id)["snapshot"]["update_time"] == later["update_time"]


def test_a_record_with_no_update_time_is_not_treated_as_older(tmp_path, monkeypatch):
    """Unknown is not old. Refusing it would strand a dispute instead."""
    monkeypatch.setenv("ORRIX_DB_PATH", str(tmp_path / "test.db"))
    store.init_db()

    stored = submitted_snapshot()
    dispute_id = stored["dispute_id"]
    store.save_case_snapshot_if_not_older(dispute_id, stored)

    undated = actionable_snapshot()
    undated.pop("update_time", None)

    assert store.save_case_snapshot_if_not_older(dispute_id, undated) is True


def test_a_stale_webhook_refresh_does_not_regress_the_record(tmp_path, monkeypatch):
    """The guard lives on the single ingest path, so both routes get it."""
    monkeypatch.setenv("ORRIX_DB_PATH", str(tmp_path / "test.db"))
    store.init_db()

    newer = submitted_snapshot()
    older = actionable_snapshot()
    dispute_id = newer["dispute_id"]
    store.save_case_snapshot(dispute_id, newer)

    webhooks.set_client(FakePayPalClient(snapshots=[copy.deepcopy(older)]))
    try:
        store.insert_event_if_absent("evt-stale", "DISPUTE.UPDATED", dispute_id)
        assert webhooks.refresh_case("evt-stale", "DISPUTE.UPDATED", dispute_id) is True
    finally:
        webhooks.set_client(None)

    assert store.get_case(dispute_id)["snapshot"]["update_time"] == newer["update_time"]
    assert store.get_event("evt-stale")["status"] == "processed"
