"""Policy tests. Plain code, no model, fail closed."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from orrix.claim_form import ClaimType, build_claim_form
from orrix.facts import FactStatus, build_facts
from orrix.policy import (
    ALLOWED_ACTION_UNIVERSE,
    FLAG_DEADLINE_PASSED,
    FLAG_NEEDS_HUMAN_REVIEW,
    FLAG_NO_EVIDENCE_AVAILABLE,
    FLAG_REFUNDS_NOT_IMPLEMENTED,
    MONEY_MOVING_ACTIONS,
    PROVIDE_EVIDENCE,
    CaseState,
    PolicyConfig,
    decide,
)
from orrix.reader import STATUS_NEEDS_REVIEW, ReaderResult

from .conftest import FIXTURE_DISPUTE_ID, actionable_snapshot, load_fixture

BEFORE_DEADLINE = datetime(2026, 10, 30, tzinfo=timezone.utc)
AFTER_DEADLINE = datetime(2026, 12, 1, tzinfo=timezone.utc)


@pytest.fixture
def config():
    return PolicyConfig(clock=lambda: BEFORE_DEADLINE)


@pytest.fixture
def facts():
    return build_facts(actionable_snapshot())


@pytest.fixture
def state():
    return CaseState(dispute_id=FIXTURE_DISPUTE_ID)


def a_form(**overrides):
    data = {
        "claim_type": "NOT_RECEIVED",
        "claimed_amount": "20.00",
        "language": "en",
        "seller_summary": "Buyer says it never arrived.",
    }
    data.update(overrides)
    return build_claim_form(data, Decimal("20.00"))


# -- the one permitted action ------------------------------------------


def test_evidence_is_permitted_when_everything_lines_up(facts, state, config):
    decision = decide(facts, a_form(), state, config)

    assert decision.allowed_actions == frozenset({PROVIDE_EVIDENCE})
    assert not decision.requires_review


def test_output_is_always_within_the_universe(facts, state, config):
    decision = decide(facts, a_form(), state, config)

    assert decision.allowed_actions <= ALLOWED_ACTION_UNIVERSE
    assert not (decision.allowed_actions & MONEY_MOVING_ACTIONS)


# -- no refund, ever ----------------------------------------------------


def test_no_claim_form_can_produce_a_refund_action(facts, state, config):
    """Every claim type at the maximum amount, with every cap setting."""
    caps = [Decimal("0"), Decimal("1"), Decimal("20.00"), Decimal("999999.00")]

    for claim_type in ClaimType:
        for amount in ("0.00", "0.01", "19.99", "20.00", "999999.00"):
            form = a_form(claim_type=claim_type.value, claimed_amount=amount)
            for cap in caps:
                decision = decide(
                    facts,
                    form,
                    state,
                    PolicyConfig(refund_cap_usd=cap, clock=lambda: BEFORE_DEADLINE),
                )
                assert decision.allowed_actions <= frozenset({PROVIDE_EVIDENCE}), (
                    f"{claim_type} / {amount} / cap {cap} produced "
                    f"{decision.allowed_actions}"
                )
                assert not (decision.allowed_actions & MONEY_MOVING_ACTIONS)
                for action in decision.allowed_actions:
                    assert "refund" not in action.lower()
                    assert "accept" not in action.lower()
                    assert "offer" not in action.lower()


def test_raising_the_refund_cap_grants_nothing(facts, state):
    generous = PolicyConfig(refund_cap_usd=Decimal("999999.00"), clock=lambda: BEFORE_DEADLINE)

    decision = decide(facts, a_form(), state, generous)

    assert decision.allowed_actions == frozenset({PROVIDE_EVIDENCE})
    assert FLAG_REFUNDS_NOT_IMPLEMENTED in decision.flags
    assert "refund_cap_set_but_v3_emits_no_refund_action" in decision.reasons


def test_default_refund_cap_is_zero():
    assert PolicyConfig().refund_cap_usd == Decimal("0")


# -- fail closed --------------------------------------------------------


def test_reader_needs_review_blocks_everything(facts, state, config):
    needs_review = ReaderResult(form=None, status=STATUS_NEEDS_REVIEW, reason="invalid_json")

    decision = decide(facts, needs_review, state, config)

    assert decision.allowed_actions == frozenset()
    assert decision.requires_review
    assert "reader_needs_review" in decision.reasons


def test_unexpected_reader_object_blocks_everything(facts, state, config):
    for hostile in ("accept_claim", {"action": "refund"}, 42, object()):
        decision = decide(facts, hostile, state, config)
        assert decision.allowed_actions == frozenset()
        assert decision.requires_review


def test_unavailable_key_fact_blocks_everything(state, config):
    trimmed = copy.deepcopy(actionable_snapshot())
    del trimmed["disputed_transactions"][0]["transaction_status"]

    decision = decide(build_facts(trimmed), a_form(), state, config)

    assert decision.allowed_actions == frozenset()
    assert decision.requires_review
    assert any(r.startswith("unavailable_fact:transaction_status") for r in decision.reasons)


def test_conflicting_key_fact_blocks_everything(state, config):
    doubled = copy.deepcopy(actionable_snapshot())
    second = copy.deepcopy(doubled["disputed_transactions"][0])
    second["seller_transaction_id"] = "9XX99999X9999999X"
    doubled["disputed_transactions"].append(second)

    decision = decide(build_facts(doubled), a_form(), state, config)

    assert decision.allowed_actions == frozenset()
    assert decision.requires_review
    assert any(r.startswith("conflicting_fact:") for r in decision.reasons)


def test_missing_tracking_blocks_evidence(state, config):
    """The real record has no seller tracking yet."""
    facts = build_facts(load_fixture())

    decision = decide(facts, a_form(), state, config)

    assert decision.allowed_actions == frozenset()
    assert FLAG_NO_EVIDENCE_AVAILABLE in decision.flags
    assert decision.requires_review


def test_passed_deadline_blocks_evidence(facts, state):
    late = PolicyConfig(clock=lambda: AFTER_DEADLINE)

    decision = decide(facts, a_form(), state, late)

    assert decision.allowed_actions == frozenset()
    assert FLAG_DEADLINE_PASSED in decision.flags
    assert decision.requires_review


def test_already_submitted_evidence_blocks_a_second_submission(facts, config):
    state = CaseState(dispute_id=FIXTURE_DISPUTE_ID, evidence_already_submitted=True)

    decision = decide(facts, a_form(), state, config)

    assert decision.allowed_actions == frozenset()
    assert "evidence_already_submitted" in decision.reasons


def test_wrong_status_blocks_everything(state, config):
    resolved = copy.deepcopy(actionable_snapshot())
    resolved["status"] = "RESOLVED"

    decision = decide(build_facts(resolved), a_form(), state, config)

    assert decision.allowed_actions == frozenset()


def test_case_already_under_review_blocks_everything(facts, config):
    state = CaseState(dispute_id=FIXTURE_DISPUTE_ID, under_review=True)

    decision = decide(facts, a_form(), state, config)

    assert decision.allowed_actions == frozenset()
    assert decision.requires_review


def test_case_state_for_another_dispute_blocks_everything(facts, config):
    decision = decide(facts, a_form(), CaseState(dispute_id="PP-R-OTHER"), config)

    assert decision.allowed_actions == frozenset()
    assert "case_state_dispute_id_mismatch" in decision.reasons
    assert decision.requires_review


def test_garbage_facts_block_everything(state, config):
    for hostile in (None, {"dispute_id": FIXTURE_DISPUTE_ID}, "facts", 7):
        decision = decide(hostile, a_form(), state, config)
        assert decision.allowed_actions == frozenset()
        assert decision.requires_review


def test_proof_of_fulfillment_not_requested_blocks_evidence(state, config):
    not_requested = copy.deepcopy(actionable_snapshot())
    not_requested["evidences"] = [
        evidence
        for evidence in not_requested["evidences"]
        if evidence.get("source") != "REQUESTED_FROM_SELLER"
    ]

    decision = decide(build_facts(not_requested), a_form(), state, config)

    assert decision.allowed_actions == frozenset()


def test_fact_only_recheck_is_allowed_without_reader_input(facts, state, config):
    """None means a fact-only re-check, which is what the executor does."""
    decision = decide(facts, None, state, config)

    assert decision.allowed_actions == frozenset({PROVIDE_EVIDENCE})
    assert not decision.requires_review
