"""A poll that finds nothing new must leave no trace in the audit chain.

The poller runs over every dispute every 60 seconds. An unconditional
"synced" entry per dispute per pass is 1,440 entries per dispute per day of
"nothing happened", which is how the log reached 12k entries in two days and
made the /audit page unusable.
"""

from __future__ import annotations

import copy

import pytest

from orrix import store, webhooks
from orrix.audit import AuditConfig, AuditLog
from orrix.pipeline import CaseViewStore, PipelineDeps, facts_content_hash, sync_case
from orrix.policy import PolicyConfig

from .conftest import FakePayPalClient, actionable_snapshot

SYNC_ACTION = "pipeline.synced"


@pytest.fixture
def deps(tmp_path, monkeypatch):
    monkeypatch.setenv("ORRIX_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("POLLER_ENABLED", "false")
    store.init_db()

    audit = AuditLog(AuditConfig(db_path=str(tmp_path / "test.db")))
    return PipelineDeps(
        audit=audit,
        case_views=CaseViewStore(str(tmp_path / "test.db")),
        policy_config=PolicyConfig(),
        reader_config=None,
    )


def sync_entries(audit: AuditLog) -> list:
    return [entry for entry in audit.entries() if entry.action == SYNC_ACTION]


# -- the content hash ----------------------------------------------------


def test_the_content_hash_ignores_the_fetch_time():
    """Otherwise every poll looks like a change."""
    from datetime import datetime, timezone

    from orrix.facts import build_facts

    snapshot = actionable_snapshot()
    first = build_facts(
        snapshot,
        expected_dispute_id=snapshot["dispute_id"],
        retrieved_at=datetime(2026, 10, 30, tzinfo=timezone.utc),
    )
    later = build_facts(
        snapshot,
        expected_dispute_id=snapshot["dispute_id"],
        retrieved_at=datetime(2026, 11, 2, 9, 15, 42, tzinfo=timezone.utc),
    )

    assert first.retrieved_at != later.retrieved_at
    assert facts_content_hash(first) == facts_content_hash(later)


def test_the_content_hash_moves_when_a_fact_moves():
    from orrix.facts import build_facts

    snapshot = actionable_snapshot()
    base = build_facts(snapshot, expected_dispute_id=snapshot["dispute_id"])

    changed_snapshot = copy.deepcopy(snapshot)
    changed_snapshot["status"] = "RESOLVED"
    changed = build_facts(
        changed_snapshot, expected_dispute_id=changed_snapshot["dispute_id"]
    )

    assert facts_content_hash(base) != facts_content_hash(changed)


# -- the requirement ------------------------------------------------------


def test_two_consecutive_syncs_of_an_unchanged_dispute_add_zero_entries(deps):
    snapshot = actionable_snapshot()

    sync_case(snapshot, deps)
    after_first = len(sync_entries(deps.audit))
    assert after_first == 1, "the first sync of a new dispute must be recorded"

    sync_case(snapshot, deps)
    sync_case(snapshot, deps)

    assert len(sync_entries(deps.audit)) == after_first


def test_a_changed_dispute_adds_exactly_one_entry(deps):
    snapshot = actionable_snapshot()
    sync_case(snapshot, deps)
    baseline = len(sync_entries(deps.audit))

    changed = copy.deepcopy(snapshot)
    changed["status"] = "RESOLVED"
    changed["update_time"] = "2026-11-02T09:15:42.000Z"
    sync_case(changed, deps)

    assert len(sync_entries(deps.audit)) == baseline + 1

    # And a repeat of the changed record adds nothing further.
    sync_case(changed, deps)
    assert len(sync_entries(deps.audit)) == baseline + 1


def test_the_case_view_is_still_refreshed_when_nothing_changed(deps):
    """Skipping the audit entry must not skip the view."""
    snapshot = actionable_snapshot()
    sync_case(snapshot, deps)

    view = sync_case(snapshot, deps)

    stored = deps.case_views.get(snapshot["dispute_id"])
    assert stored is not None
    assert stored["status"] == view.status


def test_the_chain_stays_valid_across_skipped_syncs(deps):
    """A skipped append is not a gap: nothing is rewritten or removed."""
    snapshot = actionable_snapshot()

    for _ in range(5):
        sync_case(snapshot, deps)

    changed = copy.deepcopy(snapshot)
    changed["status"] = "RESOLVED"
    sync_case(changed, deps)

    for _ in range(3):
        sync_case(changed, deps)

    assert deps.audit.verify_chain() is None
    assert len(sync_entries(deps.audit)) == 2


def test_the_entry_payload_hash_is_the_stable_content_hash(deps):
    """So the recorded hash does not move with the fetch clock."""
    snapshot = actionable_snapshot()
    sync_case(snapshot, deps)

    entry = sync_entries(deps.audit)[0]
    stored = deps.case_views.get(snapshot["dispute_id"])

    from orrix.pipeline import _stored_content_hash

    assert entry.payload_hash == _stored_content_hash(stored)


# -- through the real poller ---------------------------------------------


def test_two_poller_passes_over_an_unchanged_dispute_add_zero_entries(
    deps, monkeypatch
):
    """The end-to-end path: poll_once twice, nothing new either time."""
    from orrix import poller

    snapshot = actionable_snapshot()
    listing = [
        {"dispute_id": snapshot["dispute_id"], "update_time": snapshot["update_time"]}
    ]

    client = FakePayPalClient(snapshots=[copy.deepcopy(snapshot) for _ in range(12)])
    client._listings = [listing]
    webhooks.set_client(client)
    webhooks.set_sync_deps(deps)

    try:
        poller.poll_once()
        after_first = len(sync_entries(deps.audit))

        poller.poll_once()
        poller.poll_once()

        assert len(sync_entries(deps.audit)) == after_first
        assert deps.audit.verify_chain() is None
    finally:
        webhooks.set_client(None)
        webhooks.set_sync_deps(None)


def test_a_dispute_refetched_every_pass_still_adds_zero_entries(deps):
    """The production shape of the bug.

    When the update_time a listing reports never equals the one on the
    stored snapshot, `_artifacts_current` can never match, so the poller
    re-fetches and re-indexes that dispute on every single pass. With ~4
    disputes in that state and a 60-second interval, that is the 12k
    entries in two days.

    The re-fetch itself is the poller's skip logic, not this fix, and still
    happens here. What must stop is the write to the chain.
    """
    from orrix import poller

    snapshot = actionable_snapshot()
    dispute_id = snapshot["dispute_id"]

    # The listing claims a version the fetched record never reports, which
    # is what keeps the dispute looking perpetually stale.
    listing = [{"dispute_id": dispute_id, "update_time": "2026-11-09T00:00:00Z"}]

    client = FakePayPalClient(snapshots=[copy.deepcopy(snapshot) for _ in range(24)])
    client._listings = [listing]
    webhooks.set_client(client)
    webhooks.set_sync_deps(deps)

    try:
        poller.poll_once()
        after_first = len(sync_entries(deps.audit))
        fetches_after_first = len(client.fetch_calls)

        for _ in range(4):
            poller.poll_once()

        # The dispute was re-fetched on every pass ...
        assert len(client.fetch_calls) > fetches_after_first
        # ... and still wrote nothing new to the chain after the first.
        assert after_first == 1
        assert len(sync_entries(deps.audit)) == 1
        assert deps.audit.verify_chain() is None
    finally:
        webhooks.set_client(None)
        webhooks.set_sync_deps(None)
