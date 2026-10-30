"""Discrepancy detector tests: fixed wording, no accusation, no buyer text."""

from __future__ import annotations

import copy
import json

import pytest

from orrix.discrepancy import DISCREPANCY_MESSAGE, detect_discrepancy
from orrix.facts import build_facts
from orrix.seller_input import parse_seller_input

from .conftest import FIXTURE_INJECTION, actionable_snapshot, load_fixture

DELIVERED = {"carrier": "FEDEX", "tracking_number": "123456789", "delivery_status": "DELIVERED"}
SHIPPED = {"carrier": "FEDEX", "tracking_number": "123456789", "delivery_status": "SHIPPED"}
UNKNOWN = {"carrier": "FEDEX", "tracking_number": "123456789", "delivery_status": "UNKNOWN"}


def facts_with(seller_data, snapshot=None):
    return build_facts(
        snapshot or load_fixture(), seller_input=parse_seller_input(seller_data)
    )


def test_not_received_versus_delivered_is_a_discrepancy():
    discrepancy = detect_discrepancy(facts_with(DELIVERED))

    assert discrepancy is not None
    assert discrepancy.message == DISCREPANCY_MESSAGE


def test_the_wording_is_exactly_the_fixed_sentence():
    discrepancy = detect_discrepancy(facts_with(DELIVERED))

    assert discrepancy.message == "Claim conflicts with available delivery evidence. Review required."


def test_the_discrepancy_cites_both_facts_with_their_sources():
    discrepancy = detect_discrepancy(facts_with(DELIVERED))

    assert discrepancy.dispute_reason.name == "reason"
    assert discrepancy.dispute_reason.value == "MERCHANDISE_OR_SERVICE_NOT_RECEIVED"
    assert discrepancy.dispute_reason.source == "paypal_record"
    assert discrepancy.dispute_reason.status == "confirmed"

    assert discrepancy.delivery_status.name == "delivery_status"
    assert discrepancy.delivery_status.value == "DELIVERED"
    assert discrepancy.delivery_status.source == "seller_input"
    assert discrepancy.delivery_status.status == "seller_asserted"


def test_shipped_or_unknown_is_not_a_discrepancy():
    assert detect_discrepancy(facts_with(SHIPPED)) is None
    assert detect_discrepancy(facts_with(UNKNOWN)) is None


def test_no_seller_input_means_no_discrepancy():
    assert detect_discrepancy(build_facts(load_fixture())) is None


def test_a_different_dispute_reason_is_not_a_discrepancy():
    other = copy.deepcopy(load_fixture())
    other["reason"] = "MERCHANDISE_OR_SERVICE_NOT_AS_DESCRIBED"

    assert detect_discrepancy(facts_with(DELIVERED, other)) is None


def test_an_unconfirmed_reason_is_not_a_discrepancy():
    """The claim side must be corroborated by the record, not just present."""
    broken = copy.deepcopy(load_fixture())
    broken["reason"] = "not a code"

    assert detect_discrepancy(facts_with(DELIVERED, broken)) is None


def test_garbage_input_yields_no_discrepancy():
    for hostile in (None, "facts", 7, {}):
        assert detect_discrepancy(hostile) is None


# -- what it never says -------------------------------------------------


def test_the_output_never_contains_buyer_text():
    snapshot = load_fixture()
    discrepancy = detect_discrepancy(facts_with(DELIVERED, snapshot))

    dumped = json.dumps(discrepancy.as_dict())

    assert FIXTURE_INJECTION not in dumped
    assert snapshot["messages"][0]["content"] not in dumped
    assert snapshot["evidences"][0]["notes"] not in dumped
    assert snapshot["disputed_transactions"][0]["buyer"]["name"] not in dumped
    assert snapshot["disputed_transactions"][0]["buyer"]["email"] not in dumped
    assert snapshot["disputed_transactions"][0]["items"][0]["item_name"] not in dumped


def test_the_output_never_accuses_anyone():
    discrepancy = detect_discrepancy(facts_with(DELIVERED))
    dumped = json.dumps(discrepancy.as_dict()).lower()

    for accusation in (
        "lying",
        "lie",
        "fraud",
        "fraudulent",
        "false",
        "dishonest",
        "abuse",
        "scam",
        "intent",
        "deliberate",
        "bad faith",
    ):
        assert accusation not in dumped, f"the detector must not say {accusation!r}"


def test_the_output_carries_no_wording_beyond_the_fixed_sentence():
    discrepancy = detect_discrepancy(facts_with(DELIVERED))
    payload = discrepancy.as_dict()

    # The only prose anywhere in the structure is the fixed message.
    assert payload["message"] == DISCREPANCY_MESSAGE
    for fact in payload["facts"]:
        assert set(fact) == {"name", "value", "source", "status"}
        # Values are codes, not sentences.
        assert " " not in str(fact["value"])


def test_discrepancy_is_immutable():
    discrepancy = detect_discrepancy(facts_with(DELIVERED))

    with pytest.raises(Exception):
        discrepancy.message = "The buyer is lying."


def test_discrepancy_detected_when_paypal_also_has_tracking():
    """Both sources agree on tracking; the delivery conflict still stands."""
    discrepancy = detect_discrepancy(facts_with(DELIVERED, actionable_snapshot()))

    assert discrepancy is not None
    assert discrepancy.delivery_status.source == "seller_input"
