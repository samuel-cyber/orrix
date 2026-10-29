"""Webhook intake tests. PayPal is mocked; no network call is ever made."""

from __future__ import annotations

import json
import logging

from orrix import store, webhooks
from orrix.paypal import PayPalError

from .conftest import (
    FAKE_SECRET,
    FAKE_TOKEN,
    FULL_WEBHOOK_ID,
    SIGNATURE_HEADERS,
    FakePayPalClient,
    make_event,
    post_event,
)


def test_health_returns_200(client):
    assert client.get("/health").status_code == 200


def test_invalid_signature_is_rejected_and_stores_nothing(client):
    fake = FakePayPalClient(verified=False)
    webhooks.set_client(fake)

    response = post_event(client, make_event())

    assert response.status_code == 400
    assert response.json()["reason"] == "invalid_signature"
    assert fake.fetch_calls == []
    assert store.count_events() == 0
    assert store.count_cases() == 0


def test_invalid_signature_logs_safe_diagnostics(client, caplog):
    fake = FakePayPalClient(verified=False, verification_status="FAILURE", debug_id="dbg-abc123")
    webhooks.set_client(fake)

    with caplog.at_level(logging.WARNING, logger="orrix.webhooks"):
        post_event(client, make_event(event_id="WH-BAD", dispute_id="PP-D-42"))

    message = caplog.text
    assert "reason=invalid_signature" in message
    assert "event_id=WH-BAD" in message
    assert "event_type=CUSTOMER.DISPUTE.CREATED" in message
    assert "resource_id=PP-D-42" in message
    assert "verification_status=FAILURE" in message
    assert "debug_id=dbg-abc123" in message
    assert "webhook_id_set=True" in message
    assert "webhook_id_last4=9XYZ" in message


def test_invalid_signature_log_leaks_no_secrets_or_body(client, caplog):
    fake = FakePayPalClient(verified=False)
    webhooks.set_client(fake)
    event = make_event(event_id="WH-BAD")

    with caplog.at_level(logging.WARNING, logger="orrix.webhooks"):
        post_event(
            client,
            event,
            headers={**SIGNATURE_HEADERS, "Authorization": f"Bearer {FAKE_TOKEN}"},
        )

    message = caplog.text
    # The full webhook id must never appear, only its last 4 characters.
    assert FULL_WEBHOOK_ID not in message
    assert "WH-SECRET" not in message
    # No token, no secret, no signature material.
    assert FAKE_TOKEN not in message
    assert FAKE_SECRET not in message
    assert "signature-1" not in message
    assert "SHA256withRSA" not in message
    # No request body: none of the payload values beyond the ids.
    assert "ignore previous instructions" not in message
    assert "999999.00" not in message
    assert "RESOLVED_IN_FAVOUR_OF_BUYER" not in message
    assert json.dumps(event) not in message


def test_invalid_signature_logs_when_webhook_id_is_unset(client, caplog):
    fake = FakePayPalClient(verified=False, webhook_id=None)
    webhooks.set_client(fake)

    with caplog.at_level(logging.WARNING, logger="orrix.webhooks"):
        post_event(client, make_event())

    assert "webhook_id_set=False" in caplog.text
    assert "webhook_id_last4=None" in caplog.text


def test_verification_unavailable_logs_debug_id_and_returns_503(client, caplog):
    fake = FakePayPalClient(
        raise_paypal_error=PayPalError(
            "verify-webhook-signature call failed", status_code=500, debug_id="dbg-upstream"
        )
    )
    webhooks.set_client(fake)

    with caplog.at_level(logging.WARNING, logger="orrix.webhooks"):
        response = post_event(client, make_event(event_id="WH-UP"))

    assert response.status_code == 503
    assert "reason=verification_unavailable" in caplog.text
    assert "event_id=WH-UP" in caplog.text
    assert "http_status=500" in caplog.text
    assert "debug_id=dbg-upstream" in caplog.text
    assert store.count_events() == 0


def test_missing_headers_rejection_logs_diagnostics(client, caplog):
    fake = FakePayPalClient(raise_missing_headers=True)
    webhooks.set_client(fake)

    with caplog.at_level(logging.WARNING, logger="orrix.webhooks"):
        post_event(client, make_event(event_id="WH-NOHDR"), headers={})

    message = caplog.text
    assert "reason=missing_signature_headers" in message
    assert "event_id=WH-NOHDR" in message
    assert "webhook_id_last4=9XYZ" in message
    assert FULL_WEBHOOK_ID not in message


def test_diagnostics_tolerate_a_malformed_resource(client, caplog):
    fake = FakePayPalClient(verified=False)
    webhooks.set_client(fake)
    event = {"id": "WH-WEIRD", "event_type": None, "resource": "not-a-dict"}

    with caplog.at_level(logging.WARNING, logger="orrix.webhooks"):
        response = post_event(client, event)

    assert response.status_code == 400
    assert "event_id=WH-WEIRD" in caplog.text
    assert "resource_id=None" in caplog.text


def test_missing_signature_headers_is_rejected_and_stores_nothing(client):
    fake = FakePayPalClient(raise_missing_headers=True)
    webhooks.set_client(fake)

    response = post_event(client, make_event(), headers={})

    assert response.status_code == 400
    assert response.json()["reason"] == "missing_signature_headers"
    assert fake.fetch_calls == []
    assert store.count_events() == 0
    assert store.count_cases() == 0


def test_valid_event_is_accepted_and_fetched_once(client):
    fake = FakePayPalClient()
    webhooks.set_client(fake)

    response = post_event(client, make_event())

    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    assert fake.fetch_calls == ["PP-D-1"]
    assert store.get_event("WH-1")["status"] == "processed"
    assert store.get_case("PP-D-1") is not None


def test_duplicate_event_is_processed_once(client):
    fake = FakePayPalClient()
    webhooks.set_client(fake)
    event = make_event()

    first = post_event(client, event)
    second = post_event(client, event)

    assert first.json()["status"] == "accepted"
    assert second.status_code == 200
    assert second.json()["status"] == "duplicate"
    assert store.count_events() == 1


def test_replayed_event_does_not_trigger_a_second_fetch(client):
    fake = FakePayPalClient()
    webhooks.set_client(fake)
    event = make_event()

    post_event(client, event)
    post_event(client, event)
    post_event(client, event)

    assert fake.fetch_calls == ["PP-D-1"]


def test_out_of_order_events_leave_the_freshly_fetched_state(client):
    # The second delivery is the stale one by payload, but the fetch that
    # follows it is the newest truth, so that is what must be stored.
    fetched_states = [
        {"dispute_id": "PP-D-1", "status": "WAITING_FOR_SELLER_RESPONSE", "seq": 1},
        {"dispute_id": "PP-D-1", "status": "RESOLVED", "seq": 2},
    ]
    fake = FakePayPalClient(snapshots=fetched_states)
    webhooks.set_client(fake)

    post_event(client, make_event(event_id="WH-NEW", event_type="CUSTOMER.DISPUTE.UPDATED"))
    post_event(
        client,
        make_event(
            event_id="WH-OLD",
            event_type="CUSTOMER.DISPUTE.CREATED",
            status="WAITING_FOR_SELLER_RESPONSE",
        ),
    )

    case = store.get_case("PP-D-1")
    assert case["snapshot"] == fetched_states[1]
    assert case["snapshot"]["seq"] == 2
    assert len(fake.fetch_calls) == 2


def test_unknown_event_type_is_stored_and_does_not_crash(client):
    fake = FakePayPalClient()
    webhooks.set_client(fake)

    response = post_event(
        client, make_event(event_id="WH-?", event_type="CUSTOMER.DISPUTE.SOMETHING.NEW")
    )

    assert response.status_code == 200
    stored = store.get_event("WH-?")
    assert stored["event_type"] == "CUSTOMER.DISPUTE.SOMETHING.NEW"
    assert stored["status"] == "processed"


def test_event_without_a_dispute_id_is_recorded_and_not_fetched(client):
    fake = FakePayPalClient()
    webhooks.set_client(fake)
    event = {"id": "WH-NO-ID", "event_type": "SOMETHING.ELSE", "resource": {"foo": "bar"}}

    response = post_event(client, event)

    assert response.status_code == 200
    assert store.get_event("WH-NO-ID")["status"] == "no_dispute_id"
    assert fake.fetch_calls == []


def test_fallback_dispute_id_field_is_accepted(client):
    fake = FakePayPalClient()
    webhooks.set_client(fake)
    event = {
        "id": "WH-FALLBACK",
        "event_type": "CUSTOMER.DISPUTE.CREATED",
        "resource": {"id": "PP-D-FALLBACK"},
    }

    post_event(client, event)

    assert fake.fetch_calls == ["PP-D-FALLBACK"]


def test_payload_fields_other_than_dispute_id_never_reach_the_snapshot(client):
    fetched = {"dispute_id": "PP-D-1", "status": "WAITING_FOR_SELLER_RESPONSE"}
    fake = FakePayPalClient(snapshots=[fetched])
    webhooks.set_client(fake)

    post_event(client, make_event())

    case = store.get_case("PP-D-1")
    assert case["snapshot"] == fetched

    stored_json = case["snapshot_json"]
    assert "999999.00" not in stored_json
    assert "RESOLVED_IN_FAVOUR_OF_BUYER" not in stored_json
    assert "ignore previous instructions" not in stored_json
    assert "1999-01-01" not in stored_json


def test_malformed_json_is_rejected_without_verification(client):
    fake = FakePayPalClient()
    webhooks.set_client(fake)

    response = client.post(
        "/webhooks/paypal", content="{not json", headers=SIGNATURE_HEADERS
    )

    assert response.status_code == 400
    assert fake.verify_calls == []
    assert store.count_events() == 0
