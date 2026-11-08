"""Tests for the grid pages: CSP, licence, evaluation and the status fix."""

from __future__ import annotations

import copy
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from orrix import store
from orrix.main import create_app
from orrix.pipeline import STATUS_AWAITING_BUYER, status_label
from orrix.web.security import CDN_ORIGIN

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

PROTECTED_NEW_PAGES = ("/evaluation",)
PROTECTED_NEW_APIS = ("/api/evaluation",)

SUMMARY = {
    "model": "test-model-1",
    "date": "2026-11-05",
    "n": 120,
    "rows": [
        {
            "system": "orrix",
            "attack_category": "prompt_injection",
            "runs": 30,
            "unauthorized_actions": 0,
            "soft_failures": 2,
        },
        {
            "system": "orrix",
            "attack_category": "stale_state",
            "runs": 30,
            "unauthorized_actions": 0,
            "soft_failures": 1,
        },
        {
            "system": "naive_agent",
            "attack_category": "prompt_injection",
            "runs": 30,
            "unauthorized_actions": 17,
            "soft_failures": 4,
        },
        {
            "system": "naive_agent",
            "attack_category": "stale_state",
            "runs": 30,
            "unauthorized_actions": 9,
            "soft_failures": 3,
        },
    ],
}

RESULTS_NOTES = """# Results

## Caveats

- Sandbox only; no live dispute was ever touched.
- N is small: 30 runs per cell.
- The naive baseline has no trust boundary by design.
"""


def sign_in(client):
    response = client.post("/login", data={"password": ADMIN_PASSWORD})
    assert response.status_code == 303
    return client


def build(tmp_path, snapshot=None, summary=None, notes=None, license_key=None):
    """An app with a stored case and optional evaluation artefacts."""
    snapshot = snapshot or load_fixture()
    store.save_case_snapshot(snapshot["dispute_id"], snapshot)

    overrides = {}
    if summary is not None:
        results = tmp_path / "summary.json"
        results.write_text(json.dumps(summary), encoding="utf-8")
        overrides["results_path"] = str(results)
    else:
        overrides["results_path"] = str(tmp_path / "does-not-exist.json")

    if notes is not None:
        notes_path = tmp_path / "RESULTS.md"
        notes_path.write_text(notes, encoding="utf-8")
        overrides["results_notes_path"] = str(notes_path)
    else:
        overrides["results_notes_path"] = str(tmp_path / "no-notes.md")

    if license_key is not None:
        overrides["ag_grid_license_key"] = license_key

    config = build_app_config(tmp_path, **overrides)
    application = create_app(
        config=config,
        paypal_reader=FakeReader([snapshot, recorded_snapshot(snapshot)]),
        writer=FakeWriter(),
    )
    return TestClient(application, follow_redirects=False)


@pytest.fixture
def web(tmp_path):
    with build(tmp_path) as client:
        yield client


# -- login required on the new routes ----------------------------------


@pytest.mark.parametrize("path", PROTECTED_NEW_PAGES)
def test_new_pages_require_login(web, path):
    response = web.get(path)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


@pytest.mark.parametrize("path", PROTECTED_NEW_APIS)
def test_new_apis_require_login(web, path):
    response = web.get(path)

    assert response.status_code == 401
    assert response.json()["error"] == "login_required"


# -- CSP allowlist ------------------------------------------------------


def test_csp_allows_exactly_self_and_the_one_cdn(web):
    csp = web.get("/login").headers["content-security-policy"]
    directives = {
        part.strip().split(" ")[0]: part.strip().split(" ")[1:]
        for part in csp.split(";")
        if part.strip()
    }

    assert directives["script-src"] == ["'self'", CDN_ORIGIN]
    # style-src carries 'unsafe-inline' as well; see the dedicated test below.
    assert directives["style-src"] == ["'self'", CDN_ORIGIN, "'unsafe-inline'"]
    assert directives["default-src"] == ["'self'"]
    assert directives["object-src"] == ["'none'"]
    assert directives["base-uri"] == ["'none'"]
    assert directives["frame-ancestors"] == ["'none'"]


def test_script_src_permits_neither_inline_nor_eval(web):
    """The directive that decides whether injected code can run.

    Nothing may execute that was not served from 'self' or the one pinned
    CDN: no inline script body, no eval, no data: URL.
    """
    csp = web.get("/login").headers["content-security-policy"]
    script_src = csp.split("script-src")[1].split(";")[0]

    assert "'unsafe-inline'" not in script_src
    assert "'unsafe-eval'" not in script_src
    assert "data:" not in script_src
    assert "'nonce-" not in script_src
    assert "'strict-dynamic'" not in script_src


def test_style_src_permits_inline_styles_because_ag_grid_needs_them(web):
    """AG Grid sets row and cell geometry with inline style attributes and
    injects its own style elements. Without 'unsafe-inline' every one of
    those was refused: production logged hundreds of "Applying inline style
    violates ..." and the grid layout collapsed.

    This relaxes styling only. script-src is unchanged and strict, so
    permitting inline styles does not permit script injection -- injected
    markup could at worst restyle the page, not execute.
    """
    csp = web.get("/login").headers["content-security-policy"]
    style_src = csp.split("style-src")[1].split(";")[0]

    assert "'unsafe-inline'" in style_src
    assert "'self'" in style_src
    assert CDN_ORIGIN in style_src


def test_no_other_directive_permits_inline_or_eval(web):
    """style-src is the only place 'unsafe-inline' is allowed to appear."""
    csp = web.get("/login").headers["content-security-policy"]

    assert "'unsafe-eval'" not in csp, "eval is never permitted anywhere"
    for part in csp.split(";"):
        part = part.strip()
        if not part or part.startswith("style-src"):
            continue
        assert "'unsafe-inline'" not in part, f"{part} must not relax inline"


def test_only_the_one_cdn_host_appears_in_the_csp(web):
    csp = web.get("/login").headers["content-security-policy"]
    hosts = {part for part in csp.replace(";", " ").split() if part.startswith("http")}

    assert hosts == {CDN_ORIGIN}


def test_pages_load_scripts_only_from_self_and_that_cdn(web):
    import re

    sign_in(web)
    for path in ("/cases", "/audit", "/evaluation"):
        body = web.get(path, follow_redirects=True).text
        for src in re.findall(r'<script[^>]*src="([^"]+)"', body):
            assert src.startswith("/static/") or src.startswith(CDN_ORIGIN), (
                f"{path} loads a script from {src}"
            )
        for href in re.findall(r'<link[^>]*href="([^"]+)"', body):
            assert href.startswith("/static/") or href.startswith(CDN_ORIGIN), (
                f"{path} loads a stylesheet from {href}"
            )


def test_the_cdn_version_is_pinned(web):
    sign_in(web)
    body = web.get("/cases", follow_redirects=True).text

    assert "ag-grid-enterprise@" in body
    # No floating ranges: a pinned version is a literal x.y.z.
    assert "@latest" not in body
    assert "@^" not in body
    assert "@~" not in body


# -- licence injection --------------------------------------------------


def test_the_licence_key_is_injected_when_configured(tmp_path):
    key = "AG-TEST-LICENCE-KEY-0001"
    with build(tmp_path, license_key=key) as client:
        sign_in(client)
        body = client.get("/cases", follow_redirects=True).text

    assert f'data-ag-grid-license="{key}"' in body
    # It is data on an attribute, never a script body.
    assert f"setLicenseKey(\"{key}\")" not in body
    assert f"'{key}'" not in body


def test_the_grid_works_without_a_licence_key(web):
    sign_in(web)
    response = web.get("/cases", follow_redirects=True)

    assert response.status_code == 200
    assert 'data-ag-grid-license=""' in response.text


def test_the_licence_key_is_never_logged(tmp_path, caplog):
    import logging

    key = "AG-TEST-LICENCE-KEY-0002"
    with caplog.at_level(logging.DEBUG):
        with build(tmp_path, license_key=key) as client:
            sign_in(client)
            client.get("/cases", follow_redirects=True)
            client.get("/api/cases")

    assert key not in caplog.text


def test_the_licence_key_is_hidden_from_the_config_repr(tmp_path):
    config = build_app_config(tmp_path, ag_grid_license_key="AG-SECRET-0003")

    assert "AG-SECRET-0003" not in repr(config)
    assert config.ag_grid_license_is_set is True


# -- evaluation ---------------------------------------------------------


def test_evaluation_empty_state_explains_how_to_generate(web):
    sign_in(web)
    body = web.get("/evaluation", follow_redirects=True).text

    assert "No results yet" in body
    assert "python -m attacks.run --live" in body
    assert "docs/RESULTS.md" in body
    # No grid or chart script is loaded when there is nothing to show.
    assert "evaluation.js" not in body


def test_evaluation_api_reports_absence(web):
    sign_in(web)
    payload = web.get("/api/evaluation").json()

    assert payload["available"] is False
    assert payload["rows"] == []
    assert "python -m attacks.run --live" in payload["generate_command"]


def test_evaluation_shows_results_when_present(tmp_path):
    with build(tmp_path, summary=SUMMARY, notes=RESULTS_NOTES) as client:
        sign_in(client)
        body = client.get("/evaluation", follow_redirects=True).text

    assert "test-model-1" in body
    assert "2026-11-05" in body
    assert "120" in body
    assert "evaluation.js" in body
    assert "ag-grid-enterprise@" in body
    # Caveats are shown next to the numbers.
    assert "N is small: 30 runs per cell." in body
    assert "no live dispute was ever touched" in body


def test_evaluation_api_returns_rows_and_totals(tmp_path):
    with build(tmp_path, summary=SUMMARY, notes=RESULTS_NOTES) as client:
        sign_in(client)
        payload = client.get("/api/evaluation").json()

    assert payload["available"] is True
    assert payload["model"] == "test-model-1"
    assert payload["n"] == 120
    assert len(payload["rows"]) == 4
    assert payload["systems"] == ["naive_agent", "orrix"]
    assert payload["categories"] == ["prompt_injection", "stale_state"]
    assert payload["total_unauthorized"] == 26
    assert payload["total_soft_failures"] == 10
    assert len(payload["caveats"]) == 3


def test_evaluation_warns_when_no_caveats_are_recorded(tmp_path):
    with build(tmp_path, summary=SUMMARY, notes="# Results\n\nNothing here.\n") as client:
        sign_in(client)
        body = client.get("/evaluation", follow_redirects=True).text

    assert "No caveats recorded" in body


def test_evaluation_handles_malformed_json(tmp_path):
    results = tmp_path / "summary.json"
    results.write_text("{not json", encoding="utf-8")
    snapshot = load_fixture()
    store.save_case_snapshot(snapshot["dispute_id"], snapshot)
    config = build_app_config(tmp_path, results_path=str(results))
    application = create_app(
        config=config, paypal_reader=FakeReader([snapshot]), writer=FakeWriter()
    )

    with TestClient(application, follow_redirects=False) as client:
        sign_in(client)
        body = client.get("/evaluation", follow_redirects=True).text
        payload = client.get("/api/evaluation").json()

    assert payload["available"] is False
    assert "could not be parsed" in payload["message"]
    assert "No results yet" in body


def test_the_evaluation_api_carries_no_dispute_data(tmp_path):
    with build(tmp_path, summary=SUMMARY, notes=RESULTS_NOTES) as client:
        sign_in(client)
        body = client.get("/api/evaluation").text

    snapshot = load_fixture()
    assert FIXTURE_INJECTION not in body
    assert snapshot["dispute_id"] not in body
    assert snapshot["disputed_transactions"][0]["buyer"]["email"] not in body


# -- the status fix -----------------------------------------------------


def awaiting_buyer_snapshot():
    """A dispute Orrix has already answered, now with the buyer.

    This is the real shape of PP-R-DSM-10194429 after evidence was submitted:
    no seller_response_due_date, because the seller has already responded.
    """
    snapshot = copy.deepcopy(load_fixture())
    snapshot["status"] = "WAITING_FOR_BUYER_RESPONSE"
    snapshot["dispute_state"] = "REQUIRED_OTHER_PARTY_ACTION"
    snapshot.pop("seller_response_due_date", None)
    snapshot["evidences"].append(
        {
            "evidence_type": "PROOF_OF_FULFILLMENT",
            "source": "SUBMITTED_BY_SELLER",
            "date": "2026-10-30T10:00:00.000Z",
            "evidence_info": {
                "tracking_info": [{"carrier_name": "FEDEX", "tracking_number": "123456789"}]
            },
        }
    )
    return snapshot


def test_awaiting_buyer_is_not_reported_as_facts_incomplete(tmp_path):
    with build(tmp_path, snapshot=awaiting_buyer_snapshot()) as client:
        sign_in(client)
        rows = client.get("/api/cases").json()

    row = next(r for r in rows if r["dispute_id"] == FIXTURE_DISPUTE_ID)

    assert row["orrix_status"] == STATUS_AWAITING_BUYER
    assert row["orrix_status_label"] == "Evidence submitted, waiting for buyer"
    assert "facts_incomplete" not in row["flags"]
    assert "deadline_unavailable" not in row["flags"]
    assert "needs_human_review" not in row["flags"]
    assert row["flags"] == "awaiting_buyer_response"


def test_a_missing_due_date_is_not_blocking_once_evidence_is_in(tmp_path):
    with build(tmp_path, snapshot=awaiting_buyer_snapshot()) as client:
        sign_in(client)
        rows = client.get("/api/cases").json()

    row = next(r for r in rows if r["dispute_id"] == FIXTURE_DISPUTE_ID)

    assert "evidence_submitted_awaiting_buyer" in row["detail"]["reasons"]
    assert not any("deadline" in reason for reason in row["detail"]["reasons"])
    assert row["detail"]["evidence_submitted"] is True


def test_the_status_label_appears_on_the_case_page(tmp_path):
    with build(tmp_path, snapshot=awaiting_buyer_snapshot()) as client:
        sign_in(client)
        body = client.get(f"/cases/{FIXTURE_DISPUTE_ID}", follow_redirects=True).text

    assert STATUS_AWAITING_BUYER in body


def test_a_dispute_still_awaiting_the_seller_is_unaffected(web):
    sign_in(web)
    rows = web.get("/api/cases").json()

    row = next(r for r in rows if r["dispute_id"] == FIXTURE_DISPUTE_ID)

    # The unmodified fixture is still with the seller and has no tracking.
    assert row["orrix_status"] != STATUS_AWAITING_BUYER
    assert row["detail"]["evidence_submitted"] is False


def test_status_label_falls_back_to_the_raw_status():
    assert status_label("something_new") == "something_new"
    assert status_label(STATUS_AWAITING_BUYER) == "Evidence submitted, waiting for buyer"


# -- audit chain reporting ---------------------------------------------


def test_the_audit_api_marks_the_first_bad_row(web):
    sign_in(web)
    web.get("/api/cases")

    services = web.app.state.services
    with sqlite3.connect(services.audit.config.db_path) as connection:
        connection.execute("UPDATE audit_log SET action = 'tampered' WHERE seq = 2")

    payload = web.get("/api/audit").json()

    assert payload["chain_ok"] is False
    assert payload["first_bad_seq"] == 2

    by_seq = {row["seq"]: row for row in payload["rows"]}
    assert by_seq[1]["chain_ok"] is True
    assert by_seq[2]["chain_ok"] is False
    assert by_seq[2]["is_first_bad"] is True
    # Nothing after the break can be vouched for.
    assert all(not row["chain_ok"] for row in payload["rows"] if row["seq"] >= 2)


def test_the_verify_banner_carries_the_bad_sequence_as_data(web):
    import re

    sign_in(web)
    web.get("/api/cases")

    services = web.app.state.services
    with sqlite3.connect(services.audit.config.db_path) as connection:
        connection.execute("UPDATE audit_log SET action = 'tampered' WHERE seq = 2")

    body = web.get("/audit", follow_redirects=True).text
    token = re.search(r'name="csrf_token" value="([^"]+)"', body).group(1)
    response = web.post("/audit/verify", data={"csrf_token": token})

    assert 'data-bad-seq="2"' in response.text
    assert "Chain broken" in response.text
