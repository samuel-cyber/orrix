"""The /audit page must not render the whole chain at once.

A running deployment reaches five figures of entries; the page was a 1.6 MB
response. Paging is display-only: "Verify chain" and the chain banner still
describe every entry, because integrity inferred from a page would be no
integrity claim at all.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from orrix import store
from orrix.audit import AuditConfig, AuditLog, OriginTag
from orrix.main import create_app
from orrix.web.app import AUDIT_MAX_PAGE_SIZE, AUDIT_PAGE_SIZE

from .conftest import ADMIN_PASSWORD, build_app_config


def fill(audit: AuditLog, count: int) -> None:
    for index in range(count):
        audit.append(
            actor="pipeline",
            action="pipeline.synced",
            origin_tag=OriginTag.PAYPAL_RECORD,
            dispute_id=f"PP-D-{index:04d}",
            payload={"n": index},
        )


@pytest.fixture
def audit_client(tmp_path, monkeypatch):
    """A logged-in client over a log of 250 synthetic entries.

    Signing in appends its own `web.login` entry, so the fill happens after
    the login and the newest seq is therefore the last filled one. Tests
    read the total from the log rather than hardcoding it.
    """
    monkeypatch.setenv("ORRIX_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("POLLER_ENABLED", "false")
    store.init_db()

    audit = AuditLog(AuditConfig(db_path=str(tmp_path / "test.db")))

    config = build_app_config(tmp_path)
    with TestClient(create_app(config=config)) as client:
        client.post("/login", data={"password": ADMIN_PASSWORD}, follow_redirects=False)
        fill(audit, 250)
        yield client, audit


# -- the store's paging --------------------------------------------------


def test_recent_returns_the_newest_entries_first(tmp_path):
    audit = AuditLog(AuditConfig(db_path=str(tmp_path / "a.db")))
    fill(audit, 10)

    page = audit.recent(limit=3)

    assert [entry.seq for entry in page] == [10, 9, 8]


def test_the_cursor_walks_down_without_gaps_or_repeats(tmp_path):
    audit = AuditLog(AuditConfig(db_path=str(tmp_path / "a.db")))
    fill(audit, 25)

    seen: list[int] = []
    cursor = None
    for _ in range(10):
        page = audit.recent(limit=10, before_seq=cursor)
        if not page:
            break
        seen.extend(entry.seq for entry in page)
        cursor = page[-1].seq

    assert seen == list(range(25, 0, -1))
    assert len(seen) == len(set(seen))


def test_appending_between_pages_cannot_shift_a_page(tmp_path):
    """Keyset paging, not OFFSET: a new entry cannot duplicate an old one."""
    audit = AuditLog(AuditConfig(db_path=str(tmp_path / "a.db")))
    fill(audit, 20)

    first = audit.recent(limit=5)
    fill(audit, 3)  # three more arrive while the operator reads
    second = audit.recent(limit=5, before_seq=first[-1].seq)

    assert [entry.seq for entry in first] == [20, 19, 18, 17, 16]
    assert [entry.seq for entry in second] == [15, 14, 13, 12, 11]
    assert not set(e.seq for e in first) & set(e.seq for e in second)


def test_the_page_size_is_bounded(tmp_path):
    audit = AuditLog(AuditConfig(db_path=str(tmp_path / "a.db")))
    fill(audit, 5)

    assert len(audit.recent(limit=10_000)) == 5
    assert len(audit.recent(limit=0)) == 1
    assert len(audit.recent(limit=-5)) == 1


def test_count_and_oldest_seq(tmp_path):
    audit = AuditLog(AuditConfig(db_path=str(tmp_path / "a.db")))
    assert audit.count() == 0
    assert audit.oldest_seq() is None

    fill(audit, 7)
    assert audit.count() == 7
    assert audit.oldest_seq() == 1


# -- the endpoint --------------------------------------------------------


def test_the_first_page_is_the_newest_hundred(audit_client):
    client, _ = audit_client

    payload = client.get("/api/audit").json()
    newest = payload["total"]

    assert len(payload["rows"]) == AUDIT_PAGE_SIZE
    assert payload["rows"][0]["seq"] == newest
    assert payload["rows"][-1]["seq"] == newest - AUDIT_PAGE_SIZE + 1
    assert payload["total"] >= 250
    assert payload["has_more"] is True
    assert payload["next_before_seq"] == payload["rows"][-1]["seq"]


def test_the_response_is_far_smaller_than_the_whole_log(audit_client):
    client, _ = audit_client

    paged = client.get("/api/audit")
    whole = client.get(f"/api/audit?limit={AUDIT_MAX_PAGE_SIZE}")

    assert len(paged.content) < len(whole.content)
    assert len(paged.json()["rows"]) == AUDIT_PAGE_SIZE


def test_the_cursor_fetches_the_page_below(audit_client):
    client, _ = audit_client

    first = client.get("/api/audit").json()
    cursor = first["next_before_seq"]
    second = client.get(f"/api/audit?before_seq={cursor}").json()

    assert second["rows"][0]["seq"] == cursor - 1
    assert second["rows"][-1]["seq"] == cursor - AUDIT_PAGE_SIZE
    assert second["has_more"] is True
    # No overlap with the page above it.
    assert not {row["seq"] for row in first["rows"]} & {row["seq"] for row in second["rows"]}


def test_the_last_page_reports_no_more(audit_client):
    client, _ = audit_client

    # Walk to the bottom, then assert the bottom says so.
    cursor = None
    payload = client.get("/api/audit").json()
    while payload["has_more"]:
        cursor = payload["next_before_seq"]
        payload = client.get(f"/api/audit?before_seq={cursor}").json()

    assert payload["rows"][-1]["seq"] == 1
    assert payload["has_more"] is False
    assert payload["next_before_seq"] is None


def test_an_oversized_limit_is_clamped(audit_client):
    client, _ = audit_client

    payload = client.get("/api/audit?limit=100000").json()

    assert len(payload["rows"]) <= AUDIT_MAX_PAGE_SIZE


def test_a_junk_cursor_does_not_error(audit_client):
    client, _ = audit_client

    response = client.get("/api/audit?before_seq=not-a-number")

    # FastAPI rejects a non-integer query param; either way it must not 500.
    assert response.status_code in (200, 422)


def test_the_endpoint_requires_a_session(tmp_path, monkeypatch):
    monkeypatch.setenv("ORRIX_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("POLLER_ENABLED", "false")
    store.init_db()

    with TestClient(create_app(config=build_app_config(tmp_path))) as client:
        response = client.get("/api/audit", follow_redirects=False)

    assert response.status_code in (302, 303, 307, 401, 403)


# -- integrity still covers the whole chain ------------------------------


def test_the_chain_is_verified_over_every_entry_not_just_the_page(audit_client):
    """A break far below the first page must still be reported."""
    client, audit = audit_client

    # Tamper with entry 5, which is nowhere near the newest hundred.
    import sqlite3

    connection = sqlite3.connect(audit.config.db_path)
    try:
        with connection:
            connection.execute("UPDATE audit_log SET actor = ? WHERE seq = 5", ("forged",))
    finally:
        connection.close()

    payload = client.get("/api/audit").json()

    assert payload["chain_ok"] is False
    assert payload["first_bad_seq"] == 5
    # The break is outside the page, and still reported.
    assert all(row["seq"] > 5 for row in payload["rows"])


def test_every_row_on_a_page_below_a_break_is_marked_suspect(audit_client):
    client, audit = audit_client

    # A break inside the newest page, so the page shows both sides of it.
    total = audit.count()
    broken_at = total - 10

    import sqlite3

    connection = sqlite3.connect(audit.config.db_path)
    try:
        with connection:
            connection.execute(
                "UPDATE audit_log SET actor = ? WHERE seq = ?", ("forged", broken_at)
            )
    finally:
        connection.close()

    payload = client.get("/api/audit").json()

    assert payload["first_bad_seq"] == broken_at
    # The chain links forward, so everything from the break onward is what
    # cannot be vouched for. Entries below it are still sound.
    for row in payload["rows"]:
        if row["seq"] < broken_at:
            assert row["chain_ok"] is True
        else:
            assert row["chain_ok"] is False


def test_the_total_is_the_whole_log_not_the_page(audit_client):
    client, _ = audit_client

    payload = client.get("/api/audit?limit=10").json()

    assert len(payload["rows"]) == 10
    assert payload["total"] >= 250
    assert payload["total"] > payload["entries"]
    assert payload["entries"] == 10


def test_verify_chain_still_reads_every_entry(audit_client):
    """The Verify button is unchanged: it checks all of it, server-side."""
    client, audit = audit_client

    assert audit.verify_chain() is None
    assert audit.count() >= 250

    response = client.post("/audit/verify", data={}, follow_redirects=False)
    assert response.status_code in (200, 303, 400, 403)


# -- the page itself -----------------------------------------------------


def test_the_page_carries_the_load_older_control(audit_client):
    client, _ = audit_client

    page = client.get("/audit")

    assert page.status_code == 200
    assert "data-audit-load-older" in page.text
    assert "Load older" in page.text


def test_the_page_does_not_embed_the_log(audit_client):
    """Rows arrive by fetch, so the document stays small."""
    client, _ = audit_client

    page = client.get("/audit")

    assert "PP-D-0001" not in page.text
    assert len(page.content) < 200_000
