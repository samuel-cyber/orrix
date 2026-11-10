"""The carrier connector through the console, with the flag on.

Every test builds the app with a FakeCarrierClient, so nothing here makes a
network call and no provider key exists. The adversarial response used
throughout carries the injection string in every field a provider could
populate; none of it may reach the page, the Reader, the policy inputs, the
payload or the approval hash.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from orrix import store
from orrix.carrier import FakeCarrierClient
from orrix.main import create_app
from orrix.web.security import CSRF_FIELD
from orrix.web.services import CARRIER_CHECK_COOLDOWN_SECONDS

from .conftest import (
    ADMIN_PASSWORD,
    FIXTURE_CARRIER,
    FIXTURE_INJECTION,
    FIXTURE_TRACKING_NUMBER,
    actionable_snapshot,
    build_app_config,
)

CARRIER_KEY = "super-secret-carrier-key"

# The injection sentence the spec calls for, plus a sentinel. The fixture's
# buyer message carries the same sentence and is shown on the page by design,
# so the sentinel is what distinguishes "carrier text leaked" from "buyer text
# rendered in its own quoted block".
CARRIER_SENTINEL = "CARRIER-FIELD-7f3a91"
CARRIER_TEXT = f"{FIXTURE_INJECTION} {CARRIER_SENTINEL}"

# The injection string in every field a provider could hand back, including
# the status field itself.
ADVERSARIAL_RESPONSE = {
    "meta": {"code": 200, "message": CARRIER_TEXT},
    "data": {
        "tracking": {
            "tag": "Delivered",
            "subtag": CARRIER_TEXT,
            "subtag_message": CARRIER_TEXT,
            "shipment_delivery_date": "2026-10-20T10:00:00Z",
            "title": CARRIER_TEXT,
            "note": CARRIER_TEXT,
            "signed_by": CARRIER_TEXT,
            "courier_tracking_link": CARRIER_TEXT,
            "origin_country_region": CARRIER_TEXT,
            "checkpoints": [
                {
                    "message": CARRIER_TEXT,
                    "location": CARRIER_TEXT,
                    "raw_tag": CARRIER_TEXT,
                    "slug": CARRIER_TEXT,
                }
            ],
        }
    },
}


def seller_tracking_snapshot():
    """The actionable fixture, which already carries seller tracking.

    The connector only looks up a shipment the seller's ledger or the
    seller's own form supplied, so a lookup needs seller-side tracking to be
    present.
    """
    return actionable_snapshot()


@pytest.fixture
def carrier_app(tmp_path, monkeypatch):
    """An app with the connector on and a fake client, plus a stored case."""
    monkeypatch.setenv("ORRIX_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("POLLER_ENABLED", "false")
    store.init_db()

    snapshot = seller_tracking_snapshot()
    store.save_case_snapshot(snapshot["dispute_id"], snapshot)

    def build(response=None, **overrides):
        client_double = FakeCarrierClient(
            response if response is not None else ADVERSARIAL_RESPONSE
        )
        config = build_app_config(
            tmp_path,
            carrier_enabled=True,
            carrier_api_provider="aftership",
            carrier_api_key=CARRIER_KEY,
            **overrides,
        )
        test_client = TestClient(create_app(config=config, carrier_client=client_double))
        return test_client, client_double, snapshot["dispute_id"]

    return build


def login(client):
    client.post("/login", data={"password": ADMIN_PASSWORD}, follow_redirects=False)


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None, "no CSRF token on the page"
    return match.group(1)


def seller_input_form(client, dispute_id, token):
    """Enter seller tracking, so there is something to look up."""
    return client.post(
        f"/cases/{dispute_id}/seller-input",
        data={
            CSRF_FIELD: token,
            "carrier": FIXTURE_CARRIER,
            "tracking_number": FIXTURE_TRACKING_NUMBER,
            "delivery_status": "DELIVERED",
        },
        follow_redirects=False,
    )


# -- the card ------------------------------------------------------------


def test_the_card_appears_with_the_flag_on(carrier_app):
    client, _, dispute_id = carrier_app()

    with client:
        login(client)
        page = client.get(f"/cases/{dispute_id}")

    assert page.status_code == 200
    assert "Carrier check" in page.text
    assert "Check carrier" in page.text
    # The provider name is displayed; here it is the injected double.
    assert "fake" in page.text


def test_opening_the_case_looks_up_once_and_caches(carrier_app):
    client, double, dispute_id = carrier_app()

    with client:
        login(client)
        token = csrf_from(client.get(f"/cases/{dispute_id}").text)
        seller_input_form(client, dispute_id, token)

        client.get(f"/cases/{dispute_id}")
        first = double.call_count
        client.get(f"/cases/{dispute_id}")
        second = double.call_count

    assert first >= 1
    # Re-opening the page spends nothing: the stored reading is shown.
    assert second == first


def test_the_reading_is_shown_as_carrier_reported_and_never_verified(carrier_app):
    client, _, dispute_id = carrier_app()

    with client:
        login(client)
        token = csrf_from(client.get(f"/cases/{dispute_id}").text)
        seller_input_form(client, dispute_id, token)
        page = client.get(f"/cases/{dispute_id}")

    assert "carrier_reported" in page.text or "carrier-reported" in page.text
    # The word "verified" must never be attached to a carrier reading.
    for phrase in (
        "carrier verified",
        "verified by carrier",
        "carrier-verified",
        "delivery confirmed",
    ):
        assert phrase not in page.text.lower()


def test_the_checklist_lists_the_carrier_as_supporting_not_satisfying(carrier_app):
    client, _, dispute_id = carrier_app()

    with client:
        login(client)
        token = csrf_from(client.get(f"/cases/{dispute_id}").text)
        seller_input_form(client, dispute_id, token)
        page = client.get(f"/cases/{dispute_id}")

    assert "supports PROOF_OF_FULFILLMENT" in page.text
    assert "carrier-reported, not verified" in page.text


# -- the button ----------------------------------------------------------


def test_the_check_button_requires_csrf(carrier_app):
    client, double, dispute_id = carrier_app()

    with client:
        login(client)
        before = double.call_count
        refused = client.post(
            f"/cases/{dispute_id}/check-carrier",
            data={CSRF_FIELD: "not-the-token"},
            follow_redirects=False,
        )

    assert refused.status_code in (400, 403)
    assert double.call_count == before


def test_the_check_endpoint_requires_a_session(carrier_app):
    client, double, dispute_id = carrier_app()

    with client:
        refused = client.post(
            f"/cases/{dispute_id}/check-carrier", data={}, follow_redirects=False
        )

    assert refused.status_code in (302, 303, 307, 400, 401, 403)
    assert double.call_count == 0


def test_a_second_press_inside_the_cooldown_is_refused(carrier_app):
    client, double, dispute_id = carrier_app()

    with client:
        login(client)
        token = csrf_from(client.get(f"/cases/{dispute_id}").text)
        seller_input_form(client, dispute_id, token)
        client.get(f"/cases/{dispute_id}")

        client.post(
            f"/cases/{dispute_id}/check-carrier",
            data={CSRF_FIELD: token},
            follow_redirects=False,
        )
        after_first = double.call_count

        client.post(
            f"/cases/{dispute_id}/check-carrier",
            data={CSRF_FIELD: token},
            follow_redirects=False,
        )
        after_second = double.call_count

        page = client.get(f"/cases/{dispute_id}")

    assert after_second == after_first
    assert f"once every {CARRIER_CHECK_COOLDOWN_SECONDS} seconds" in page.text


def test_a_case_with_no_seller_tracking_looks_nothing_up(carrier_app):
    """Nothing to ask about: no ledger row and no seller form entry."""
    client, double, dispute_id = carrier_app()

    with client:
        login(client)
        page = client.get(f"/cases/{dispute_id}")

    # The fixture's tracking is in the PayPal record, not seller-supplied.
    assert double.call_count == 0
    assert "nothing to look up" in page.text


# -- secrets and URLs stay out of the page and the logs -------------------


def test_the_page_never_carries_the_carrier_key(carrier_app):
    client, _, dispute_id = carrier_app()

    with client:
        login(client)
        token = csrf_from(client.get(f"/cases/{dispute_id}").text)
        seller_input_form(client, dispute_id, token)
        page = client.get(f"/cases/{dispute_id}")

    assert CARRIER_KEY not in page.text


def test_no_full_provider_url_appears_on_the_page(carrier_app):
    client, _, dispute_id = carrier_app()

    with client:
        login(client)
        token = csrf_from(client.get(f"/cases/{dispute_id}").text)
        seller_input_form(client, dispute_id, token)
        page = client.get(f"/cases/{dispute_id}")

    assert "api.aftership.com" not in page.text
    assert "/trackings/" not in page.text


def test_nothing_in_the_logs_carries_the_key(carrier_app, caplog):
    caplog.set_level("DEBUG")
    client, _, dispute_id = carrier_app()

    with client:
        login(client)
        token = csrf_from(client.get(f"/cases/{dispute_id}").text)
        seller_input_form(client, dispute_id, token)
        client.get(f"/cases/{dispute_id}")

    assert CARRIER_KEY not in caplog.text
    assert "api.aftership.com" not in caplog.text


# -- the adversarial response reaches nothing -----------------------------


def test_no_carrier_text_reaches_the_page(carrier_app):
    client, _, dispute_id = carrier_app()

    with client:
        login(client)
        token = csrf_from(client.get(f"/cases/{dispute_id}").text)
        seller_input_form(client, dispute_id, token)
        page = client.get(f"/cases/{dispute_id}")

    assert CARRIER_TEXT not in page.text
    assert CARRIER_SENTINEL not in page.text


def test_no_carrier_text_reaches_the_payload_or_the_approval_hash(carrier_app):
    """The payload is built from the tracking facts; the carrier is not in it."""
    client, _, dispute_id = carrier_app()

    with client:
        login(client)
        token = csrf_from(client.get(f"/cases/{dispute_id}").text)
        seller_input_form(client, dispute_id, token)
        page = client.get(f"/cases/{dispute_id}")

    payload_block = re.search(r'<pre class="payload">(.*?)</pre>', page.text, re.DOTALL)
    assert payload_block is not None
    body = payload_block.group(1)

    assert CARRIER_SENTINEL not in body
    assert "carrier_status" not in body
    assert "carrier_reported" not in body
    # The payload template has no carrier field, so the only tracking values
    # in it are the seller's.
    assert FIXTURE_TRACKING_NUMBER in body


def test_the_payload_is_identical_with_and_without_a_carrier_reading(
    tmp_path, monkeypatch
):
    """The evidence body does not change because a carrier answered.

    Two apps over the same database and the same case: one with the
    connector on and a delivered reading, one with it off. The payload and
    its digest must match exactly.
    """
    monkeypatch.setenv("ORRIX_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("POLLER_ENABLED", "false")
    store.init_db()

    snapshot = seller_tracking_snapshot()
    dispute_id = snapshot["dispute_id"]
    store.save_case_snapshot(dispute_id, snapshot)

    def payload_for(**overrides):
        config = build_app_config(tmp_path, **overrides)
        double = FakeCarrierClient(ADVERSARIAL_RESPONSE)
        with TestClient(create_app(config=config, carrier_client=double)) as client:
            login(client)
            token = csrf_from(client.get(f"/cases/{dispute_id}").text)
            seller_input_form(client, dispute_id, token)
            return client.get(f"/cases/{dispute_id}").text

    with_carrier = payload_for(
        carrier_enabled=True,
        carrier_api_provider="aftership",
        carrier_api_key=CARRIER_KEY,
    )
    without_carrier = payload_for(carrier_enabled=False)

    assert _payload_of(with_carrier) == _payload_of(without_carrier)
    assert _payload_hash_of(with_carrier) == _payload_hash_of(without_carrier)
    assert _payload_of(with_carrier) != ""


def _payload_of(html: str) -> str:
    match = re.search(r'<pre class="payload">(.*?)</pre>', html, re.DOTALL)
    return match.group(1) if match else ""


def _payload_hash_of(html: str) -> str:
    """The payload digest, not the evidence pack's.

    Both are rendered as "sha256 <16 hex>", so this anchors to the payload
    block. The pack's hash is expected to differ when a carrier reading is
    present -- the pack prints the carrier rows, the payload does not.
    """
    block = html.split('<pre class="payload">', 1)
    if len(block) != 2:
        return ""
    match = re.search(r"sha256 ([0-9a-f]{16})", block[1])
    return match.group(1) if match else ""


def test_an_adversarial_status_field_cannot_fake_a_delivery(carrier_app):
    hostile = {"data": {"tracking": {"tag": CARRIER_TEXT}}}
    client, _, dispute_id = carrier_app(response=hostile)

    with client:
        login(client)
        token = csrf_from(client.get(f"/cases/{dispute_id}").text)
        seller_input_form(client, dispute_id, token)
        page = client.get(f"/cases/{dispute_id}")

    assert CARRIER_SENTINEL not in page.text
    # An unknown tag is unavailable, never a delivery.
    assert "unavailable" in page.text


def test_the_reader_is_never_given_a_carrier_reading(carrier_app):
    """The Reader receives buyer text and the amount ceiling. Nothing else."""
    import inspect

    from orrix import reader

    source = inspect.getsource(reader)
    assert "carrier" not in source.lower()

    client, _, dispute_id = carrier_app()
    with client:
        login(client)
        token = csrf_from(client.get(f"/cases/{dispute_id}").text)
        seller_input_form(client, dispute_id, token)
        page = client.get(f"/cases/{dispute_id}")

    # The Reader card reports a status code, never provider text.
    assert CARRIER_SENTINEL not in page.text
