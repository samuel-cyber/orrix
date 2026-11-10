"""The carrier connector: enums in, free text dropped, failures contained.

Every test here uses FakeCarrierClient or a stub session object. Nothing in
this file makes a network call, and no real provider key exists in the test
environment.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from orrix.approval import DisputeVersion, create_approval
from orrix.carrier import (
    MAX_ATTEMPTS,
    AfterShipCarrierClient,
    CarrierConfig,
    CarrierLookup,
    CarrierResult,
    CarrierStatus,
    FakeCarrierClient,
    NullCarrierClient,
    StubCarrierClient,
    apply_carrier,
    build_client,
    carrier_binding,
    carrier_result,
    parse_aftership,
    unavailable,
)
from orrix.discrepancy import DISCREPANCY_MESSAGE, detect_discrepancy
from orrix.executor import REASON_STALE_CARRIER, ExecutorDeps, execute
from orrix.facts import (
    CARRIER_DELIVERED_AT,
    CARRIER_STATUS,
    FACT_NAMES,
    SOURCE_CARRIER_API,
    FactStatus,
    build_facts,
)
from orrix.policy import PROVIDE_EVIDENCE, CaseState, decide

from .conftest import (
    FIXTURE_CARRIER,
    FIXTURE_INJECTION,
    FIXTURE_TRACKING_NUMBER,
    FakePayPalClient,
    FakeWriter,
    actionable_snapshot,
    recorded_snapshot,
)

ENABLED = CarrierConfig(enabled=True, provider="aftership", api_key="test-carrier-key")

# A provider response with the injection string in every single field, free
# text and status alike. Nothing in it may reach a fact, a page or a payload.
HOSTILE_BODY = {
    "meta": {"code": 200, "message": FIXTURE_INJECTION},
    "data": {
        "tracking": {
            "tag": "Delivered",
            "subtag": FIXTURE_INJECTION,
            "subtag_message": FIXTURE_INJECTION,
            "shipment_delivery_date": "2026-10-20T10:00:00Z",
            "title": FIXTURE_INJECTION,
            "note": FIXTURE_INJECTION,
            "signed_by": FIXTURE_INJECTION,
            "origin_country_region": FIXTURE_INJECTION,
            "courier_destination_country_region": FIXTURE_INJECTION,
            "checkpoints": [
                {
                    "message": FIXTURE_INJECTION,
                    "location": FIXTURE_INJECTION,
                    "raw_tag": FIXTURE_INJECTION,
                }
            ],
        }
    },
}


class FakeResponse:
    """A requests-like response. Contacts nothing."""

    def __init__(self, status_code=200, body=None, raises=False):
        self.status_code = status_code
        self._body = body
        self._raises = raises

    def json(self):
        if self._raises:
            raise ValueError("not json")
        return self._body


class FakeSession:
    """Records the request without making it."""

    def __init__(self, response=None, raises=None):
        self._response = response or FakeResponse(200, HOSTILE_BODY)
        self._raises = raises
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append({"url": url, "headers": headers or {}, "timeout": timeout})
        if self._raises is not None:
            raise self._raises
        return self._response


def lookup_for(client, **overrides):
    config = CarrierConfig(**{**ENABLED.__dict__, **overrides})
    return CarrierLookup(client=client, config=config, sleep=lambda seconds: None)


# -- the enum boundary ---------------------------------------------------


def test_every_documented_tag_maps_to_an_enum():
    tags = {
        "Delivered": CarrierStatus.DELIVERED,
        "InTransit": CarrierStatus.IN_TRANSIT,
        "OutForDelivery": CarrierStatus.IN_TRANSIT,
        "InfoReceived": CarrierStatus.IN_TRANSIT,
        "Pending": CarrierStatus.IN_TRANSIT,
        "AvailableForPickup": CarrierStatus.IN_TRANSIT,
        "AttemptFail": CarrierStatus.EXCEPTION,
        "Exception": CarrierStatus.EXCEPTION,
        "Expired": CarrierStatus.EXCEPTION,
    }
    for tag, expected in tags.items():
        assert parse_aftership({"tag": tag}).status is expected


def test_an_unknown_tag_is_unavailable_not_a_guess():
    assert parse_aftership({"tag": "SomethingNew"}).status is CarrierStatus.UNAVAILABLE


def test_the_result_keeps_four_fields_and_nothing_else():
    """A CarrierResult has no room for provider prose, by construction."""
    assert set(CarrierResult.__dataclass_fields__) == {
        "status",
        "delivered_at",
        "checked_at",
        "source",
    }


def test_parsing_drops_every_free_text_field():
    result = parse_aftership(HOSTILE_BODY)

    assert result.status is CarrierStatus.DELIVERED
    assert result.delivered_at == "2026-10-20T10:00:00Z"
    assert result.source == "aftership"

    # The injection string appears nowhere in the result, at any depth.
    blob = repr(result) + str(result.as_dict())
    assert FIXTURE_INJECTION not in blob
    assert "Ignore your rules" not in blob


def test_a_hostile_status_field_cannot_invent_a_status():
    body = {"data": {"tracking": {"tag": FIXTURE_INJECTION}}}
    assert parse_aftership(body).status is CarrierStatus.UNAVAILABLE


def test_only_a_delivery_may_carry_a_delivery_time():
    result = carrier_result(CarrierStatus.IN_TRANSIT, "2026-10-20T10:00:00Z")
    assert result.delivered_at is None


def test_a_malformed_delivery_time_is_dropped():
    result = carrier_result(CarrierStatus.DELIVERED, FIXTURE_INJECTION)
    assert result.status is CarrierStatus.DELIVERED
    assert result.delivered_at is None


def test_a_hostile_provider_name_is_not_echoed():
    assert carrier_result(CarrierStatus.DELIVERED, None, None, FIXTURE_INJECTION).source == "none"


@pytest.mark.parametrize(
    "body",
    [None, "a string", 42, [], {}, {"data": None}, {"data": {}}, {"data": {"tracking": "x"}}],
)
def test_an_unparseable_envelope_is_unavailable(body):
    assert parse_aftership(body).status is CarrierStatus.UNAVAILABLE


# -- every failure mode is unavailable -----------------------------------


@pytest.mark.parametrize("status_code", [400, 401, 403, 429, 500, 502, 503])
def test_every_error_status_yields_unavailable(status_code):
    session = FakeSession(FakeResponse(status_code, {"tag": "Delivered"}))
    client = AfterShipCarrierClient("k", session=session)

    assert client.lookup(FIXTURE_CARRIER, FIXTURE_TRACKING_NUMBER).status is (
        CarrierStatus.UNAVAILABLE
    )


def test_a_404_is_not_found_rather_than_unavailable():
    client = AfterShipCarrierClient("k", session=FakeSession(FakeResponse(404, None)))
    result = client.lookup(FIXTURE_CARRIER, FIXTURE_TRACKING_NUMBER)
    assert result.status is CarrierStatus.NOT_FOUND


def test_a_body_that_is_not_json_is_unavailable():
    client = AfterShipCarrierClient("k", session=FakeSession(FakeResponse(200, raises=True)))
    assert client.lookup(FIXTURE_CARRIER, "1Z").status is CarrierStatus.UNAVAILABLE


def test_a_transport_failure_is_unavailable_not_an_exception():
    client = AfterShipCarrierClient("k", session=FakeSession(raises=TimeoutError("timed out")))
    assert client.lookup(FIXTURE_CARRIER, "1Z").status is CarrierStatus.UNAVAILABLE


def test_a_client_that_raises_never_escapes_the_lookup():
    lookup = lookup_for(FakeCarrierClient(raises=RuntimeError("boom")))
    assert lookup.lookup(FIXTURE_CARRIER, "1Z").status is CarrierStatus.UNAVAILABLE


def test_a_client_returning_rubbish_is_unavailable():
    class Rubbish:
        source = "fake"

        def lookup(self, carrier, number):
            return {"status": "delivered"}

    assert lookup_for(Rubbish()).lookup(FIXTURE_CARRIER, "1Z").status is (
        CarrierStatus.UNAVAILABLE
    )


# -- retries, cache and the cap -----------------------------------------


def test_an_unavailable_result_is_retried_up_to_the_cap():
    client = FakeCarrierClient(unavailable("fake"))
    lookup_for(client).lookup(FIXTURE_CARRIER, "1Z")
    assert client.call_count == MAX_ATTEMPTS


def test_a_real_answer_stops_the_retries():
    client = FakeCarrierClient({"tag": "Delivered"})
    lookup_for(client).lookup(FIXTURE_CARRIER, "1Z")
    assert client.call_count == 1


def test_a_cache_hit_avoids_a_second_call():
    client = FakeCarrierClient({"tag": "Delivered"})
    lookup = lookup_for(client)

    first = lookup.lookup(FIXTURE_CARRIER, "1Z")
    second = lookup.lookup(FIXTURE_CARRIER, "1Z")

    assert client.call_count == 1
    assert first == second


def test_the_cache_expires_after_its_ttl():
    client = FakeCarrierClient({"tag": "Delivered"})
    now = [1000.0]
    lookup = CarrierLookup(
        client=client,
        config=CarrierConfig(**{**ENABLED.__dict__, "cache_ttl_seconds": 60.0}),
        clock=lambda: now[0],
        sleep=lambda seconds: None,
    )

    lookup.lookup(FIXTURE_CARRIER, "1Z")
    now[0] += 61.0
    lookup.lookup(FIXTURE_CARRIER, "1Z")

    assert client.call_count == 2


def test_a_different_tracking_number_is_a_different_cache_entry():
    client = FakeCarrierClient({"tag": "Delivered"})
    lookup = lookup_for(client)

    lookup.lookup(FIXTURE_CARRIER, "1Z")
    lookup.lookup(FIXTURE_CARRIER, "2Z")

    assert client.call_count == 2


def test_an_unavailable_result_is_not_cached():
    """One provider blip must not become an hour of silence.

    The first lookup exhausts its retries on unavailable answers; the second
    must reach the client again rather than being served a cached failure.
    """
    client = FakeCarrierClient(
        [unavailable("fake")] * MAX_ATTEMPTS + [{"tag": "Delivered"}]
    )
    lookup = lookup_for(client)

    first = lookup.lookup(FIXTURE_CARRIER, "1Z")
    assert first.status is CarrierStatus.UNAVAILABLE

    second = lookup.lookup(FIXTURE_CARRIER, "1Z")
    assert second.status is CarrierStatus.DELIVERED


def test_the_hourly_cap_is_enforced_in_code():
    client = FakeCarrierClient(lambda carrier, number: carrier_result(CarrierStatus.DELIVERED))
    lookup = lookup_for(client, max_lookups_per_hour=3)

    # Distinct numbers, so the cache never answers for us.
    results = [lookup.lookup(FIXTURE_CARRIER, f"TRACK{index}") for index in range(5)]

    assert client.call_count == 3
    assert [result.status for result in results[:3]] == [CarrierStatus.DELIVERED] * 3
    assert all(result.status is CarrierStatus.UNAVAILABLE for result in results[3:])


def test_the_cap_window_slides():
    client = FakeCarrierClient(lambda carrier, number: carrier_result(CarrierStatus.DELIVERED))
    now = [1000.0]
    lookup = CarrierLookup(
        client=client,
        config=CarrierConfig(**{**ENABLED.__dict__, "max_lookups_per_hour": 1}),
        clock=lambda: now[0],
        sleep=lambda seconds: None,
    )

    lookup.lookup(FIXTURE_CARRIER, "A1")
    assert lookup.lookup(FIXTURE_CARRIER, "B2").status is CarrierStatus.UNAVAILABLE

    now[0] += 3601.0
    assert lookup.lookup(FIXTURE_CARRIER, "C3").status is CarrierStatus.DELIVERED


def test_prose_in_a_tracking_number_is_never_requested():
    client = FakeCarrierClient({"tag": "Delivered"})
    lookup = lookup_for(client)

    result = lookup.lookup(FIXTURE_CARRIER, FIXTURE_INJECTION)

    assert result.status is CarrierStatus.UNAVAILABLE
    assert client.call_count == 0


def test_a_disabled_connector_makes_no_call():
    client = FakeCarrierClient({"tag": "Delivered"})
    lookup = CarrierLookup(client=client, config=CarrierConfig(enabled=False))

    assert lookup.lookup(FIXTURE_CARRIER, "1Z").status is CarrierStatus.UNAVAILABLE
    assert client.call_count == 0


# -- the client factory --------------------------------------------------


def test_the_factory_builds_nothing_live_when_disabled():
    assert isinstance(build_client(CarrierConfig(enabled=False)), NullCarrierClient)


def test_the_factory_builds_nothing_live_without_a_key():
    config = CarrierConfig(enabled=True, provider="aftership", api_key=None)
    assert isinstance(build_client(config), NullCarrierClient)


def test_an_unimplemented_provider_is_a_stub_that_reports_unavailable():
    config = CarrierConfig(enabled=True, provider="someone-else", api_key="k")
    client = build_client(config)

    assert isinstance(client, StubCarrierClient)
    assert client.lookup(FIXTURE_CARRIER, "1Z").status is CarrierStatus.UNAVAILABLE


def test_the_factory_builds_the_aftership_adapter_when_configured():
    assert isinstance(build_client(ENABLED), AfterShipCarrierClient)


# -- secrets stay out of logs and requests -------------------------------


def test_the_key_travels_in_a_header_and_not_in_the_url():
    session = FakeSession()
    AfterShipCarrierClient("super-secret-key", session=session).lookup(FIXTURE_CARRIER, "1Z")

    call = session.calls[0]
    assert "super-secret-key" not in call["url"]
    assert call["headers"]["as-api-key"] == "super-secret-key"


def test_no_log_line_carries_the_key_or_a_full_url(caplog):
    caplog.set_level("DEBUG", logger="orrix.carrier")
    session = FakeSession(FakeResponse(500, None))
    AfterShipCarrierClient("super-secret-key", session=session).lookup(FIXTURE_CARRIER, "1Z")

    text = caplog.text
    assert "super-secret-key" not in text
    assert "https://" not in text
    assert "/trackings/" not in text


def test_the_config_summary_never_carries_the_key():
    summary = ENABLED.summary()
    assert summary["api_key_set"] is True
    assert "test-carrier-key" not in str(summary)


def test_the_config_repr_never_carries_the_key():
    assert "test-carrier-key" not in repr(ENABLED)


# -- onto the facts ------------------------------------------------------


def facts_for(snapshot=None, seller_input=None):
    snapshot = snapshot or actionable_snapshot()
    return build_facts(
        snapshot,
        seller_input=seller_input,
        expected_dispute_id=snapshot["dispute_id"],
        retrieved_at=datetime(2026, 10, 30, tzinfo=timezone.utc),
    )


def test_carrier_facts_are_outside_the_paypal_allowlist():
    """build_facts must never produce them; only the overlay may."""
    assert CARRIER_STATUS not in FACT_NAMES
    assert CARRIER_DELIVERED_AT not in FACT_NAMES
    assert CARRIER_STATUS not in facts_for().facts


def test_the_overlay_adds_exactly_two_facts_with_the_carrier_origin():
    facts = facts_for()
    overlaid = apply_carrier(facts, carrier_result(CarrierStatus.DELIVERED, "2026-10-20"))

    added = set(overlaid.facts) - set(facts.facts)
    assert added == {CARRIER_STATUS, CARRIER_DELIVERED_AT}

    status = overlaid.get(CARRIER_STATUS)
    assert status.status is FactStatus.CARRIER_REPORTED
    assert status.source == SOURCE_CARRIER_API
    assert status.value == "DELIVERED"


def test_a_carrier_fact_is_never_usable_and_never_confirmed():
    """carrier_reported must not be actionable: no payload may rest on it."""
    overlaid = apply_carrier(facts_for(), carrier_result(CarrierStatus.DELIVERED, "2026-10-20"))
    fact = overlaid.get(CARRIER_STATUS)

    assert fact.is_confirmed is False
    assert fact.is_usable is False
    # .value() returns None for an unusable fact, so nothing can read it by
    # accident on the acting path.
    assert overlaid.value(CARRIER_STATUS) is None


def test_the_overlay_never_touches_an_existing_fact():
    facts = facts_for()
    overlaid = apply_carrier(facts, carrier_result(CarrierStatus.DELIVERED, "2026-10-20"))

    for name in FACT_NAMES:
        assert overlaid.get(name) == facts.get(name)


def test_an_unavailable_lookup_asserts_nothing():
    overlaid = apply_carrier(facts_for(), unavailable("fake"))

    assert overlaid.get(CARRIER_STATUS).status is FactStatus.UNAVAILABLE
    assert overlaid.get(CARRIER_STATUS).value is None


def test_a_not_found_lookup_asserts_nothing():
    overlaid = apply_carrier(facts_for(), carrier_result(CarrierStatus.NOT_FOUND))
    assert overlaid.get(CARRIER_STATUS).status is FactStatus.UNAVAILABLE


def test_the_overlay_of_nothing_is_the_identity():
    facts = facts_for()
    assert apply_carrier(facts, None) is facts


# -- the policy never reads a carrier fact -------------------------------


def test_the_carrier_never_changes_the_action_set(policy_config):
    """The action set is identical whatever the carrier says.

    A carrier-reported delivery against a not-received claim does add the
    existing `discrepancy_detected` reason and review flag -- that is the
    fixed discrepancy path, and it is the only thing a carrier may move. The
    set of permitted actions never changes.
    """
    snapshot = actionable_snapshot()
    facts = facts_for(snapshot)
    state = CaseState(dispute_id=snapshot["dispute_id"])

    before = decide(facts, None, state, policy_config)

    for status in (CarrierStatus.DELIVERED, CarrierStatus.EXCEPTION, CarrierStatus.NOT_FOUND):
        overlaid = apply_carrier(facts, carrier_result(status, "2026-10-20"))
        after = decide(overlaid, None, state, policy_config)

        assert after.allowed_actions == before.allowed_actions
        # Reasons may gain the discrepancy marker and nothing else.
        assert set(after.reasons) - set(before.reasons) <= {"discrepancy_detected"}
        assert set(before.reasons) - set(after.reasons) == set()


def test_a_carrier_delivery_does_not_block_approval(policy_config):
    """A discrepancy is for review. It is not a veto on the seller."""
    snapshot = actionable_snapshot()
    facts = apply_carrier(
        facts_for(snapshot), carrier_result(CarrierStatus.DELIVERED, "2026-10-20")
    )
    decision = decide(facts, None, CaseState(dispute_id=snapshot["dispute_id"]), policy_config)

    assert PROVIDE_EVIDENCE in decision.allowed_actions


# -- the discrepancy wording is unchanged --------------------------------


def test_a_carrier_delivery_against_a_not_received_claim_uses_the_fixed_wording():
    snapshot = actionable_snapshot()
    snapshot["reason"] = "MERCHANDISE_OR_SERVICE_NOT_RECEIVED"
    facts = apply_carrier(
        facts_for(snapshot), carrier_result(CarrierStatus.DELIVERED, "2026-10-20")
    )

    discrepancy = detect_discrepancy(facts)

    assert discrepancy is not None
    assert discrepancy.message == DISCREPANCY_MESSAGE
    # No accusation, no mention of the buyer's honesty.
    for word in ("fraud", "lying", "lied", "false", "dishonest", "scam"):
        assert word not in discrepancy.message.lower()


def test_a_carrier_in_transit_reading_raises_no_discrepancy():
    snapshot = actionable_snapshot()
    snapshot["reason"] = "MERCHANDISE_OR_SERVICE_NOT_RECEIVED"
    facts = apply_carrier(facts_for(snapshot), carrier_result(CarrierStatus.IN_TRANSIT))

    assert detect_discrepancy(facts) is None


def test_the_discrepancy_dict_is_unchanged_without_a_carrier():
    snapshot = actionable_snapshot()
    snapshot["reason"] = "MERCHANDISE_OR_SERVICE_NOT_RECEIVED"
    facts = facts_for(snapshot)

    discrepancy = detect_discrepancy(facts)
    if discrepancy is not None:
        assert discrepancy.carrier_status is None
        assert len(discrepancy.as_dict()["facts"]) == 2


# -- the approval binding -------------------------------------------------


def binding_approval(snapshot, payload, status=None, checked_at=None):
    return create_approval(
        dispute_id=snapshot["dispute_id"],
        action=PROVIDE_EVIDENCE,
        payload=payload,
        dispute_version=DisputeVersion.from_snapshot(snapshot),
        carrier_status=status,
        carrier_checked_at=checked_at,
    )


def test_the_binding_is_absent_when_nothing_was_reported():
    assert carrier_binding(None) == (None, None)
    assert carrier_binding(unavailable("fake")) == (None, None)
    assert carrier_binding(carrier_result(CarrierStatus.NOT_FOUND)) == (None, None)


def test_the_binding_carries_the_status_and_the_check_time():
    result = carrier_result(CarrierStatus.DELIVERED, "2026-10-20", "2026-10-30T00:00:00+00:00")
    assert carrier_binding(result) == ("DELIVERED", "2026-10-30T00:00:00+00:00")


def test_a_carrier_binding_changes_the_approval_id():
    from orrix.executor import build_evidence_payload

    snapshot = actionable_snapshot()
    payload = build_evidence_payload(facts_for(snapshot))

    without = binding_approval(snapshot, payload)
    with_carrier = binding_approval(snapshot, payload, "DELIVERED", "2026-10-30T00:00:00+00:00")

    assert without.approval_id != with_carrier.approval_id
    assert without.is_intact()
    assert with_carrier.is_intact()


def test_a_different_reading_is_a_different_approval_id():
    from orrix.executor import build_evidence_payload

    snapshot = actionable_snapshot()
    payload = build_evidence_payload(facts_for(snapshot))

    first = binding_approval(snapshot, payload, "DELIVERED", "2026-10-30T00:00:00+00:00")
    later = binding_approval(snapshot, payload, "DELIVERED", "2026-10-30T01:00:00+00:00")
    other = binding_approval(snapshot, payload, "IN_TRANSIT", "2026-10-30T00:00:00+00:00")

    assert len({first.approval_id, later.approval_id, other.approval_id}) == 3


def test_a_half_binding_is_refused():
    from orrix.approval import ApprovalError
    from orrix.executor import build_evidence_payload

    snapshot = actionable_snapshot()
    payload = build_evidence_payload(facts_for(snapshot))

    with pytest.raises(ApprovalError):
        binding_approval(snapshot, payload, "DELIVERED", None)


# -- the executor refuses a stale reading ---------------------------------


def carrier_deps(audit_log, executed, policy_config, snapshot, status, checked_at):
    return ExecutorDeps(
        paypal_reader=FakePayPalClient(snapshots=[snapshot, recorded_snapshot(snapshot)]),
        writer=FakeWriter(),
        audit=audit_log,
        executed=executed,
        policy_config=policy_config,
        carrier_status=status,
        carrier_checked_at=checked_at,
    )


def test_the_executor_refuses_when_the_reading_moved(
    audit_log, executed, policy_config
):
    from orrix.executor import build_evidence_payload

    snapshot = actionable_snapshot()
    payload = build_evidence_payload(facts_for(snapshot))
    approval = binding_approval(snapshot, payload, "DELIVERED", "2026-10-30T00:00:00+00:00")

    # The carrier now says the same thing at a different time.
    deps = carrier_deps(
        audit_log, executed, policy_config, snapshot, "DELIVERED", "2026-10-30T02:00:00+00:00"
    )
    result = execute(approval, deps)

    assert result.status == "refused"
    assert result.reason == REASON_STALE_CARRIER
    assert result.writes_attempted == 0
    assert result.requires_review is True


def test_the_executor_refuses_when_the_reading_disappeared(
    audit_log, executed, policy_config
):
    from orrix.executor import build_evidence_payload

    snapshot = actionable_snapshot()
    payload = build_evidence_payload(facts_for(snapshot))
    approval = binding_approval(snapshot, payload, "DELIVERED", "2026-10-30T00:00:00+00:00")

    deps = carrier_deps(audit_log, executed, policy_config, snapshot, None, None)

    assert execute(approval, deps).reason == REASON_STALE_CARRIER


def test_an_approval_with_no_binding_is_unaffected_by_the_check(
    audit_log, executed, policy_config
):
    """The flag-off case: no binding, so the check is not reached at all."""
    from orrix.executor import build_evidence_payload

    snapshot = actionable_snapshot()
    payload = build_evidence_payload(facts_for(snapshot))
    approval = binding_approval(snapshot, payload)

    deps = carrier_deps(audit_log, executed, policy_config, snapshot, None, None)
    result = execute(approval, deps)

    assert result.reason != REASON_STALE_CARRIER
    assert result.status == "executed"


def test_a_matching_reading_still_executes(audit_log, executed, policy_config):
    from orrix.executor import build_evidence_payload

    snapshot = actionable_snapshot()
    payload = build_evidence_payload(facts_for(snapshot))
    approval = binding_approval(snapshot, payload, "DELIVERED", "2026-10-30T00:00:00+00:00")

    deps = carrier_deps(
        audit_log, executed, policy_config, snapshot, "DELIVERED", "2026-10-30T00:00:00+00:00"
    )

    assert execute(approval, deps).status == "executed"
