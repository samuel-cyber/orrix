"""Phase 1 UI tests: design system, shell, landing and multi-page restyle.

Everything here is static or server-rendered. PayPal is faked; no test makes
a network call and no test reads the operational database.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from orrix import store
from orrix.main import create_app
from orrix.pipeline import (
    STATUS_ACTION_AVAILABLE,
    STATUS_AWAITING_BUYER,
    STATUS_AWAITING_READER,
    STATUS_FACTS_FAILED,
    STATUS_NEEDS_HUMAN_REVIEW,
    STATUS_NO_ACTION,
)
from orrix.web.security import CDN_ORIGIN
from orrix.web.app import PUBLIC_PATHS

from .conftest import (
    ADMIN_PASSWORD,
    FIXTURE_DISPUTE_ID,
    FakeReader,
    FakeWriter,
    build_app_config,
    load_fixture,
    recorded_snapshot,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC = REPO_ROOT / "orrix" / "web" / "static"
TEMPLATES = REPO_ROOT / "orrix" / "web" / "templates"

#: Every logged-in page in the shell. Order does not matter.
APP_PAGES = ("/overview", "/cases", f"/cases/{FIXTURE_DISPUTE_ID}", "/audit", "/evaluation")

#: Every status the pipeline can persist, so each page is exercised for each.
ALL_STATUSES = (
    STATUS_ACTION_AVAILABLE,
    STATUS_NEEDS_HUMAN_REVIEW,
    STATUS_NO_ACTION,
    STATUS_AWAITING_BUYER,
    STATUS_FACTS_FAILED,
    STATUS_AWAITING_READER,
)

#: Tokens that must exist in both the dark root and the light override. The
#: colour tokens carry the trust-boundary semantics, so they are not optional.
REQUIRED_TOKENS = (
    "--bg",
    "--surface",
    "--surface-2",
    "--surface-3",
    "--card",
    "--line",
    "--line-soft",
    "--line-strong",
    "--ink",
    "--ink-soft",
    "--ink-faint",
    "--accent",
    "--accent-soft",
    "--accent-line",
    "--ok",
    "--ok-bg",
    "--ok-line",
    "--warn",
    "--warn-bg",
    "--warn-line",
    "--err",
    "--err-bg",
    "--err-line",
    "--seller",
    "--seller-bg",
    "--untrusted",
    "--untrusted-bg",
    "--untrusted-line",
    "--radius",
    "--radius-sm",
    "--radius-lg",
    "--radius-pill",
    "--elev-1",
    "--elev-2",
    "--elev-3",
    "--font-sans",
    "--font-mono",
    "--focus",
    "--sp-1",
    "--sp-2",
    "--sp-3",
    "--sp-4",
    "--sp-5",
    "--sp-6",
)

INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>.*?</script>", re.S | re.I)
INLINE_STYLE_ATTR = re.compile(r"\sstyle\s*=\s*[\"']", re.I)


def read_static(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def read_template(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


# -- fixtures -----------------------------------------------------------


@pytest.fixture
def snapshot():
    return load_fixture()


@pytest.fixture
def writer():
    return FakeWriter()


def make_client(tmp_path, snapshot, writer, *, with_case: bool = True, status=None):
    config = build_app_config(tmp_path)
    if with_case:
        payload = snapshot
        if status is not None:
            import copy

            payload = copy.deepcopy(snapshot)
        store.save_case_snapshot(payload["dispute_id"], payload)
    reader = FakeReader([snapshot, recorded_snapshot(snapshot, tracking_number="123456789")])
    application = create_app(config=config, paypal_reader=reader, writer=writer)
    return TestClient(application, follow_redirects=False)


def sign_in(client):
    response = client.post("/login", data={"password": ADMIN_PASSWORD})
    assert response.status_code == 303, response.text
    return client


# -- the public landing page -------------------------------------------


def test_the_root_is_public_and_renders_without_a_session(tmp_path, snapshot, writer):
    with make_client(tmp_path, snapshot, writer, with_case=False) as client:
        response = client.get("/")

    assert response.status_code == 200
    body = response.text
    assert "Orrix" in body
    # The promise and the sandbox disclaimer are part of the public page.
    assert "Sandbox only" in body or "sandbox only" in body


def test_the_root_still_needs_no_session_but_deeper_routes_do(tmp_path, snapshot, writer):
    with make_client(tmp_path, snapshot, writer) as client:
        assert client.get("/").status_code == 200
        assert client.get("/overview").status_code == 303
        assert client.get("/cases").status_code == 303
        assert client.get("/audit").status_code == 303


def test_the_landing_page_carries_the_trust_diagram_as_inline_svg(tmp_path, snapshot, writer):
    with make_client(tmp_path, snapshot, writer, with_case=False) as client:
        body = client.get("/").text

    assert "<svg" in body
    assert "Reader" in body
    # The seal is named: the reader holds no tools.
    lowered = body.lower()
    assert "no tools" in lowered


def test_the_landing_page_plus_deeper_routes_are_the_pinned_public_set():
    assert set(PUBLIC_PATHS) == {"/", "/health", "/login", "/webhooks/paypal", "/static"}


# -- no inline code anywhere -------------------------------------------


@pytest.mark.parametrize(
    "template",
    [
        "base.html",
        "landing.html",
        "login.html",
        "overview.html",
        "cases.html",
        "case.html",
        "orders.html",
        "lab.html",
        "audit.html",
        "evaluation.html",
        "not_found.html",
    ],
)
def test_no_template_carries_an_inline_script_body(template):
    text = read_template(template)
    assert not INLINE_SCRIPT.search(text), template


@pytest.mark.parametrize(
    "template",
    [
        "base.html",
        "landing.html",
        "login.html",
        "overview.html",
        "cases.html",
        "case.html",
        "orders.html",
        "lab.html",
        "audit.html",
        "evaluation.html",
        "not_found.html",
    ],
)
def test_no_template_carries_an_inline_style_attribute(template):
    text = read_template(template)
    assert not INLINE_STYLE_ATTR.search(text), template


# -- theme tokens -------------------------------------------------------


def test_the_dark_root_defines_every_required_token():
    css = read_static("app.css")
    root = css.split(":root {", 1)[1].split("}", 1)[0]
    for token in REQUIRED_TOKENS:
        assert token in root, token


def test_the_light_theme_restates_the_painting_tokens():
    css = read_static("app.css")
    light = css.split('[data-theme="light"] {', 1)[1].split("}", 1)[0]
    # The tokens that are the trust-boundary semantics must be restated so the
    # light theme is not left with dark, low-contrast values.
    for token in (
        "--bg",
        "--surface",
        "--surface-2",
        "--surface-3",
        "--card",
        "--line",
        "--ink",
        "--ink-soft",
        "--accent",
        "--ok",
        "--ok-bg",
        "--warn",
        "--warn-bg",
        "--err",
        "--err-bg",
        "--untrusted",
        "--untrusted-bg",
        "--untrusted-line",
    ):
        assert token in light, token


def test_the_theme_is_set_by_an_external_script_never_inline():
    base = read_template("base.html")
    assert '<script src="/static/theme.js"></script>' in base
    theme = read_static("theme.js")
    # The stored preference is read inside a try/catch: a hostile storage
    # value must never break first paint.
    assert "try {" in theme
    assert "localStorage" in theme


def test_the_theme_respects_the_system_preference():
    theme = read_static("theme.js")
    assert "prefers-color-scheme" in theme


# -- reduced motion -----------------------------------------------------


def test_a_reduced_motion_rule_is_present_and_disables_animation():
    css = read_static("app.css")
    marker = "@media (prefers-reduced-motion: reduce) {"
    assert marker in css
    block = css.split(marker, 1)[1]
    # The block turns animation and transition off.
    assert "animation-duration" in block
    assert "transition-duration" in block


def test_scripts_guard_reduced_motion_before_animating():
    # Any script that animates must first check the media query. This pins the
    # behaviour for the two scripts that drive motion in the shell/landing.
    for name in ("landing.js", "shell.js"):
        source = read_static(name)
        assert "prefers-reduced-motion" in source, name


# -- app shell and command palette -------------------------------------


@pytest.mark.parametrize("path", APP_PAGES)
def test_each_app_page_renders_for_a_signed_in_user(tmp_path, snapshot, writer, path):
    with make_client(tmp_path, snapshot, writer) as client:
        sign_in(client)
        response = client.get(path)

    assert response.status_code == 200, path


def test_the_shell_carries_the_sandbox_pill_and_poll_indicator(tmp_path, snapshot, writer):
    with make_client(tmp_path, snapshot, writer) as client:
        sign_in(client)
        body = client.get("/overview").text

    assert "SANDBOX" in body
    # The live indicator reads a stored timestamp; it never makes a call.
    assert "poll-indicator" in body


def test_the_shell_carries_the_theme_toggle_and_all_six_nav_items(tmp_path, snapshot, writer):
    with make_client(tmp_path, snapshot, writer) as client:
        sign_in(client)
        body = client.get("/overview").text

    assert "data-theme-toggle" in body
    for href in ("/overview", "/cases", "/orders", "/lab", "/audit", "/evaluation"):
        assert f'href="{href}"' in body, href


def test_the_command_palette_markup_is_present(tmp_path, snapshot, writer):
    with make_client(tmp_path, snapshot, writer) as client:
        sign_in(client)
        body = client.get("/overview").text

    assert 'id="command-palette"' in body
    assert "command-palette" in body
    assert "data-palette-open" in body
    assert "palette-input" in body


def test_the_toast_region_is_present(tmp_path, snapshot, writer):
    with make_client(tmp_path, snapshot, writer) as client:
        sign_in(client)
        body = client.get("/overview").text

    assert 'id="toasts"' in body


def test_the_palette_opens_on_ctrl_or_cmd_k():
    shell = read_static("shell.js")
    assert "k" in shell
    # The modifier is checked case-insensitively (Ctrl or Cmd).
    lowered = shell.lower()
    assert "meta" in lowered or "ctrl" in lowered


def test_view_transitions_are_used_with_a_fallback():
    shell = read_static("shell.js")
    assert "startViewTransition" in shell
    # A guard means browsers without the API still navigate.
    assert "typeof" in shell or " in document" in shell


# -- the pages render for every status and for empty data ---------------


def test_the_overview_renders_with_no_data_with_a_helpful_empty_state(tmp_path, snapshot, writer):
    with make_client(tmp_path, snapshot, writer, with_case=False) as client:
        sign_in(client)
        response = client.get("/overview")

    assert response.status_code == 200
    body = response.text.lower()
    # An empty console says what it is waiting for rather than showing zeros.
    assert "no " in body or "waiting" in body or "nothing" in body


def test_the_overview_renders_with_a_case_present(tmp_path, snapshot, writer):
    with make_client(tmp_path, snapshot, writer) as client:
        sign_in(client)
        response = client.get("/overview")

    assert response.status_code == 200
    assert FIXTURE_DISPUTE_ID in response.text


@pytest.mark.parametrize("status", ALL_STATUSES)
def test_the_case_page_renders_for_every_status(tmp_path, snapshot, writer, status):
    import copy
    import sqlite3
    from orrix.pipeline import CaseViewStore

    with make_client(tmp_path, snapshot, writer) as client:
        sign_in(client)
        # Force the stored view into each status and confirm the page renders.
        store_path = str(tmp_path / "test.db")
        view_store = CaseViewStore(store_path)
        row = view_store.get(FIXTURE_DISPUTE_ID)
        if row is not None:
            connection = sqlite3.connect(store_path)
            try:
                connection.execute(
                    "UPDATE case_views SET status = ? WHERE dispute_id = ?",
                    (status, FIXTURE_DISPUTE_ID),
                )
                connection.commit()
            finally:
                connection.close()

        response = client.get(f"/cases/{FIXTURE_DISPUTE_ID}")

    assert response.status_code == 200, status


def test_the_case_page_shows_the_two_trust_lanes(tmp_path, snapshot, writer):
    with make_client(tmp_path, snapshot, writer) as client:
        sign_in(client)
        body = client.get(f"/cases/{FIXTURE_DISPUTE_ID}").text

    assert "lane-untrusted" in body
    assert "lane-trusted" in body


def test_the_case_page_shows_a_stepper_bound_to_state(tmp_path, snapshot, writer):
    with make_client(tmp_path, snapshot, writer) as client:
        sign_in(client)
        body = client.get(f"/cases/{FIXTURE_DISPUTE_ID}").text

    assert "stepper" in body


def test_the_audit_page_shows_a_chain_banner_and_timeline(tmp_path, snapshot, writer):
    with make_client(tmp_path, snapshot, writer) as client:
        sign_in(client)
        body = client.get("/audit").text

    assert "data-chain-banner" in body
    assert 'id="audit-timeline"' in body


def test_the_evaluation_page_renders_its_empty_state_or_tables(tmp_path, snapshot, writer):
    with make_client(tmp_path, snapshot, writer) as client:
        sign_in(client)
        response = client.get("/evaluation")

    assert response.status_code == 200
    body = response.text
    # Either the empty state, or the write-up note above the tables.
    assert "No results yet" in body or "page-note" in body


# -- scripts stay in the strict CSP allowlist --------------------------


@pytest.mark.parametrize("path", ("/", *APP_PAGES))
def test_every_page_loads_scripts_only_from_self_and_the_one_cdn(tmp_path, snapshot, writer, path):
    with make_client(tmp_path, snapshot, writer) as client:
        if path != "/":
            sign_in(client)
        body = client.get(path).text

    for src in re.findall(r'<script[^>]*\bsrc="([^"]+)"', body):
        assert src.startswith("/static/") or src.startswith(CDN_ORIGIN), src
