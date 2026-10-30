"""Seller-sourced tracking: facts, policy, and the end-to-end write.

This is the path that was unreachable before seller input existed: the real
PP-R-PXL-10195222 carries no tracking in the PayPal record, so evidence
could never be built from the record alone.
"""

from __future__ import annotations

import copy
import json

import pytest

from orrix.executor import STATUS_EXECUTED, build_evidence_payload, execute
from orrix.facts import FactStatus, build_facts
from orrix.policy import (
    FLAG_DISCREPANCY,
    FLAG_NEEDS_HUMAN_REVIEW,
    PROVIDE_EVIDENCE,
    CaseState,
    decide,
)
from orrix.seller_input import parse_seller_input

from .conftest import (
    FIXTURE_DISPUTE_ID,
    FIXTURE_INJECTION,
    FakeReader,
    FakeWriter,
    actionable_snapshot,
    approve_from,
    load_fixture,
    make_deps,
    recorded_snapshot,
)

SELLER_DELIVERED = {
    "carrier": "FEDEX",
    "tracking_number": "123456789",
    "delivery_status": "DELIVERED",
    "delivered_on": "2026-10-28",
}
SELLER_SHIPPED = {
    "carrier": "DHL",
    "tracking_number": "ZZ-999-888",
    "delivery_status": "SHIPPED",
}


@pytest.fixture
def seller_input():
    return parse_seller_input(SELLER_DELIVERED)


@pytest.fixture
def state():
    return CaseState(dispute_id=FIXTURE_DISPUTE_ID)


# -- facts from two sources ---------------------------------------------


def test_seller_tracking_is_seller_asserted_not_confirmed(seller_input):
    facts = build_facts(load_fixture(), seller_input=seller_input)

    for name in ("tracking_carrier", "tracking_number"):
        assert facts.status(name) is FactStatus.SELLER_ASSERTED
        assert facts.source(name) == "seller_input"
        assert facts.get(name).is_usable
        assert not facts.get(name).is_confirmed

    assert facts.value("tracking_carrier") == "FEDEX"
    assert facts.value("tracking_number") == "123456789"
    assert facts.status("delivery_status") is FactStatus.SELLER_ASSERTED
    assert facts.value("delivered_on") == "2026-10-28"


def test_no_seller_sourced_fact_is_ever_confirmed(seller_input):
    """Only the PayPal record can confirm. The seller can only assert."""
    for snapshot in (load_fixture(), actionable_snapshot()):
        facts = build_facts(snapshot, seller_input=seller_input)
        for name, fact in facts.facts.items():
            if fact.status is FactStatus.CONFIRMED:
                assert fact.source == "paypal_record", (
                    f"{name} is confirmed but sourced from {fact.source}"
                )
            if fact.source == "seller_input":
                assert fact.status is not FactStatus.CONFIRMED, (
                    f"{name} came from the seller but is marked confirmed"
                )


def test_paypal_tracking_stays_confirmed_when_the_seller_agrees(seller_input):
    """The record corroborates the seller, so the fact is confirmed."""
    facts = build_facts(actionable_snapshot(), seller_input=seller_input)

    assert facts.status("tracking_number") is FactStatus.CONFIRMED
    assert facts.source("tracking_number") == "paypal_record"
    assert facts.value("tracking_number") == "123456789"


def test_paypal_tracking_alone_is_confirmed():
    facts = build_facts(actionable_snapshot())

    assert facts.status("tracking_number") is FactStatus.CONFIRMED
    assert facts.source("tracking_number") == "paypal_record"


def test_disagreeing_sources_are_conflicting():
    facts = build_facts(actionable_snapshot(), seller_input=parse_seller_input(SELLER_SHIPPED))

    assert facts.status("tracking_number") is FactStatus.CONFLICTING
    assert facts.status("tracking_carrier") is FactStatus.CONFLICTING
    # A conflicting fact carries no value, so nothing can act on either side.
    assert facts.value("tracking_number") is None
    assert facts.value("tracking_carrier") is None


def test_carrier_comparison_ignores_case():
    facts = build_facts(
        actionable_snapshot(),
        seller_input=parse_seller_input({**SELLER_DELIVERED, "carrier": "fedex"}),
    )

    assert facts.status("tracking_carrier") is FactStatus.CONFIRMED


def test_unvalidated_seller_input_fails_closed():
    from orrix.facts import FactsIntegrityError

    with pytest.raises(FactsIntegrityError, match="must be a SellerEvidenceInput"):
        build_facts(load_fixture(), seller_input=SELLER_DELIVERED)


def test_seller_input_cannot_introduce_prose_into_facts(seller_input):
    """Validation refuses prose up front; facts would refuse it again."""
    facts = build_facts(load_fixture(), seller_input=seller_input)
    dumped = facts.model_dump_json()

    assert FIXTURE_INJECTION not in dumped
    assert "ignore" not in dumped.lower()


# -- policy -------------------------------------------------------------


def test_seller_tracking_unlocks_provide_evidence(seller_input, state, policy_config):
    """Without seller input this dispute is not actionable; with it, it is."""
    without = decide(build_facts(load_fixture()), None, state, policy_config)
    assert without.allowed_actions == frozenset()

    with_seller = build_facts(load_fixture(), seller_input=seller_input)
    decision = decide(with_seller, None, state, policy_config)

    assert decision.allowed_actions == frozenset({PROVIDE_EVIDENCE})
    assert "tracking_available_from:seller_input" in decision.reasons


def test_a_discrepancy_flags_review_without_blocking(seller_input, state, policy_config):
    facts = build_facts(load_fixture(), seller_input=seller_input)

    decision = decide(facts, None, state, policy_config)

    assert decision.permits(PROVIDE_EVIDENCE), "a discrepancy must not veto submission"
    assert FLAG_DISCREPANCY in decision.flags
    assert FLAG_NEEDS_HUMAN_REVIEW in decision.flags
    assert "discrepancy_detected" in decision.reasons


def test_no_discrepancy_when_the_seller_only_claims_shipped(state, policy_config):
    facts = build_facts(
        load_fixture(),
        seller_input=parse_seller_input(
            {"carrier": "FEDEX", "tracking_number": "123456789", "delivery_status": "SHIPPED"}
        ),
    )

    decision = decide(facts, None, state, policy_config)

    assert decision.permits(PROVIDE_EVIDENCE)
    assert FLAG_DISCREPANCY not in decision.flags


def test_conflicting_tracking_blocks_submission(state, policy_config):
    facts = build_facts(actionable_snapshot(), seller_input=parse_seller_input(SELLER_SHIPPED))

    decision = decide(facts, None, state, policy_config)

    assert decision.allowed_actions == frozenset()
    assert decision.requires_review
    assert any("tracking_conflicting" in reason for reason in decision.reasons)


# -- payload ------------------------------------------------------------


def test_the_payload_uses_the_fixed_note_template(seller_input):
    facts = build_facts(load_fixture(), seller_input=seller_input)

    payload = build_evidence_payload(facts)
    evidence = payload["evidences"][0]

    assert evidence["notes"] == "Tracking supplied by seller: FEDEX 123456789."
    tracking = evidence["evidence_info"]["tracking_info"][0]
    assert tracking["carrier_name"] == "FEDEX"
    assert tracking["tracking_number"] == "123456789"
    assert tracking["delivered_date"] == "2026-10-28"


def test_the_payload_omits_the_date_when_not_asserted():
    facts = build_facts(load_fixture(), seller_input=parse_seller_input(SELLER_SHIPPED))

    tracking = build_evidence_payload(facts)["evidences"][0]["evidence_info"]["tracking_info"][0]

    assert "delivered_date" not in tracking
    assert set(tracking) == {"carrier_name", "tracking_number"}


def test_the_payload_has_no_field_beyond_the_template(seller_input):
    facts = build_facts(load_fixture(), seller_input=seller_input)

    payload = build_evidence_payload(facts)

    assert set(payload) == {"evidences"}
    evidence = payload["evidences"][0]
    assert set(evidence) == {"evidence_type", "evidence_info", "notes"}
    assert set(evidence["evidence_info"]) == {"tracking_info"}


def test_hostile_text_never_reaches_the_payload_with_seller_tracking(seller_input):
    snapshot = load_fixture()
    facts = build_facts(snapshot, seller_input=seller_input)

    sent = json.dumps(build_evidence_payload(facts))

    for hostile in (
        FIXTURE_INJECTION,
        snapshot["messages"][0]["content"],
        snapshot["evidences"][0]["notes"],
        snapshot["disputed_transactions"][0]["buyer"]["name"],
        snapshot["disputed_transactions"][0]["buyer"]["email"],
        snapshot["disputed_transactions"][0]["items"][0]["item_name"],
        snapshot["disputed_transactions"][0]["items"][0]["item_description"],
    ):
        assert hostile not in sent, f"{hostile!r} reached the payload"


# -- end to end ---------------------------------------------------------


def test_the_full_seller_evidence_path_writes_exactly_once(
    seller_input, audit_log, executed, policy_config
):
    """Real record, seller input, approval, execution: one write."""
    snapshot = load_fixture()
    facts = build_facts(snapshot, seller_input=seller_input)

    decision = decide(facts, None, CaseState(dispute_id=FIXTURE_DISPUTE_ID), policy_config)
    assert decision.permits(PROVIDE_EVIDENCE)

    payload = build_evidence_payload(facts)
    approval = approve_from(snapshot, payload=payload)

    after = recorded_snapshot(snapshot, tracking_number="123456789")
    writer = FakeWriter()
    reader = FakeReader([snapshot, after])
    deps = make_deps(reader, writer, audit_log, executed, policy_config, seller_input=seller_input)

    result = execute(approval, deps)

    assert result.status == STATUS_EXECUTED
    assert len(writer.calls) == 1
    assert writer.calls[0]["request_id"] == approval.approval_id
    assert writer.calls[0]["payload"]["evidences"][0]["notes"] == (
        "Tracking supplied by seller: FEDEX 123456789."
    )
    assert audit_log.verify_chain() is None


def test_the_end_to_end_path_sends_no_hostile_text(
    seller_input, audit_log, executed, policy_config
):
    snapshot = load_fixture()
    facts = build_facts(snapshot, seller_input=seller_input)
    approval = approve_from(snapshot, payload=build_evidence_payload(facts))

    writer = FakeWriter()
    reader = FakeReader([snapshot, recorded_snapshot(snapshot, tracking_number="123456789")])
    deps = make_deps(reader, writer, audit_log, executed, policy_config, seller_input=seller_input)

    execute(approval, deps)

    sent = json.dumps(writer.calls[0]["payload"])
    assert FIXTURE_INJECTION not in sent
    assert snapshot["disputed_transactions"][0]["items"][0]["item_name"] not in sent


def test_a_replay_of_the_seller_path_still_writes_once(
    seller_input, audit_log, executed, policy_config
):
    snapshot = load_fixture()
    facts = build_facts(snapshot, seller_input=seller_input)
    approval = approve_from(snapshot, payload=build_evidence_payload(facts))

    writer = FakeWriter()
    reader = FakeReader([snapshot, recorded_snapshot(snapshot, tracking_number="123456789")])
    deps = make_deps(reader, writer, audit_log, executed, policy_config, seller_input=seller_input)

    execute(approval, deps)
    second = execute(approval, deps)

    assert second.reason == "already_executed"
    assert len(writer.calls) == 1


def test_executor_refuses_when_the_seller_input_changes_after_approval(
    seller_input, audit_log, executed, policy_config
):
    """The approved payload must still match what Facts produce now."""
    snapshot = load_fixture()
    facts = build_facts(snapshot, seller_input=seller_input)
    approval = approve_from(snapshot, payload=build_evidence_payload(facts))

    different = parse_seller_input({**SELLER_DELIVERED, "tracking_number": "999999999"})
    writer = FakeWriter()
    reader = FakeReader([snapshot])
    deps = make_deps(reader, writer, audit_log, executed, policy_config, seller_input=different)

    result = execute(approval, deps)

    assert result.reason == "payload_mismatch"
    assert writer.calls == []
