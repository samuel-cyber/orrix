"""Pipeline tests: orchestration only, no judgement of its own."""

from __future__ import annotations

import copy
import json
from decimal import Decimal

import pytest

from orrix.audit import AuditConfig, AuditLog
from orrix.pipeline import (
    STATUS_ACTION_AVAILABLE,
    STATUS_FACTS_FAILED,
    STATUS_NEEDS_HUMAN_REVIEW,
    CaseViewStore,
    PipelineDeps,
    process_case,
)
from orrix.policy import PROVIDE_EVIDENCE, PolicyConfig
from orrix.reader import REASON_NOT_CONFIGURED, ReaderConfig
from orrix.seller_input import parse_seller_input

from .conftest import (
    FIXTURE_DISPUTE_ID,
    FIXTURE_INJECTION,
    actionable_snapshot,
    load_fixture,
)

SELLER = {
    "carrier": "FEDEX",
    "tracking_number": "123456789",
    "delivery_status": "DELIVERED",
}


@pytest.fixture
def deps(tmp_path, policy_config):
    return PipelineDeps(
        audit=AuditLog(AuditConfig(db_path=str(tmp_path / "audit.db"))),
        case_views=CaseViewStore(str(tmp_path / "views.db")),
        policy_config=policy_config,
        reader_config=None,
    )


# -- the stages run and persist -----------------------------------------


def test_processing_a_case_persists_a_view(deps):
    view = process_case(load_fixture(), deps)

    assert view.dispute_id == FIXTURE_DISPUTE_ID
    assert deps.case_views.count() == 1

    row = deps.case_views.get(FIXTURE_DISPUTE_ID)
    assert row["status"] == view.status
    assert row["update_time"] == load_fixture()["update_time"]
    assert json.loads(row["facts_json"])["dispute_id"] == FIXTURE_DISPUTE_ID
    assert json.loads(row["decision_json"])["allowed_actions"] == []


def test_reprocessing_updates_the_same_row(deps):
    process_case(load_fixture(), deps)

    moved = copy.deepcopy(load_fixture())
    moved["update_time"] = "2026-11-02T10:00:00.000Z"
    process_case(moved, deps)

    assert deps.case_views.count() == 1
    assert deps.case_views.get(FIXTURE_DISPUTE_ID)["update_time"] == moved["update_time"]


def test_every_stage_is_audited(deps):
    process_case(load_fixture(), deps)

    actions = [entry.action for entry in deps.audit.entries()]
    assert any(action.startswith("pipeline.facts_built") for action in actions)
    assert any(action.startswith("pipeline.buyer_text_extracted") for action in actions)
    assert any(action.startswith("pipeline.reader:") for action in actions)
    assert any(action.startswith("pipeline.decided:") for action in actions)
    assert deps.audit.verify_chain() is None


def test_each_audit_entry_carries_the_right_origin_tag(deps):
    process_case(load_fixture(), deps)

    by_action = {entry.action: entry.origin_tag for entry in deps.audit.entries()}
    for action, tag in by_action.items():
        if action.startswith("pipeline.facts_built"):
            assert tag == "paypal_record"
        elif action.startswith("pipeline.buyer_text_extracted"):
            assert tag == "buyer_text"
        elif action.startswith("pipeline.reader:"):
            assert tag == "reader_output"
        elif action.startswith("pipeline.decided"):
            assert tag == "system"


def test_buyer_text_is_audited_as_a_hash_never_as_text(deps):
    process_case(load_fixture(), deps)

    dumped = str([entry.__dict__ for entry in deps.audit.entries()])
    assert FIXTURE_INJECTION not in dumped
    # The length is recorded so an operator can see there was text at all.
    assert any("chars=" in entry.action for entry in deps.audit.entries())


# -- the reader is advisory ---------------------------------------------


def test_an_unconfigured_reader_does_not_block_the_fact_based_path(deps):
    """No model configured must not brick the evidence path."""
    view = process_case(
        actionable_snapshot(), deps, seller_input=parse_seller_input(SELLER)
    )

    assert view.reader_result.status == "needs_review"
    assert view.reader_result.reason == REASON_NOT_CONFIGURED
    assert view.decision.permits(PROVIDE_EVIDENCE)
    assert view.status == STATUS_ACTION_AVAILABLE


def test_a_reader_that_ran_and_failed_does_block(tmp_path, policy_config):
    """A reader that produced bad output is a signal, and blocks."""

    class BadResponse:
        status_code = 200
        headers: dict = {}

        def json(self):
            return {"choices": [{"message": {"content": "not json at all"}}]}

    class FakeClient:
        def post(self, url, **kwargs):
            return BadResponse()

    deps = PipelineDeps(
        audit=AuditLog(AuditConfig(db_path=str(tmp_path / "audit.db"))),
        case_views=CaseViewStore(str(tmp_path / "views.db")),
        policy_config=policy_config,
        reader_config=ReaderConfig(
            base_url="https://model.example.invalid/v1",
            api_key="sk-test",
            model="m",
            retry_backoff_seconds=0.0,
        ),
        reader_client=FakeClient(),
    )

    view = process_case(
        actionable_snapshot(), deps, seller_input=parse_seller_input(SELLER)
    )

    assert view.reader_result.reason == "invalid_json"
    assert view.decision.allowed_actions == frozenset()
    assert view.status == STATUS_NEEDS_HUMAN_REVIEW


def test_a_successful_reader_is_recorded_with_timestamps(tmp_path, policy_config):
    good = json.dumps(
        {
            "claim_type": "NOT_RECEIVED",
            "claimed_amount": "20.00",
            "language": "en",
            "seller_summary": "Buyer says it never arrived.",
        }
    )

    class Response:
        status_code = 200
        headers: dict = {}

        def json(self):
            return {"choices": [{"message": {"content": good}}]}

    class FakeClient:
        def __init__(self):
            self.requests = []

        def post(self, url, **kwargs):
            self.requests.append(kwargs)
            return Response()

    fake = FakeClient()
    deps = PipelineDeps(
        audit=AuditLog(AuditConfig(db_path=str(tmp_path / "audit.db"))),
        case_views=CaseViewStore(str(tmp_path / "views.db")),
        policy_config=policy_config,
        reader_config=ReaderConfig(
            base_url="https://model.example.invalid/v1", api_key="sk-test", model="m"
        ),
        reader_client=fake,
    )

    view = process_case(actionable_snapshot(), deps, seller_input=parse_seller_input(SELLER))

    assert view.reader_result.ok
    assert view.reader_started_at and view.reader_finished_at
    row = deps.case_views.get(FIXTURE_DISPUTE_ID)
    assert row["reader_started_at"] == view.reader_started_at
    assert json.loads(row["reader_json"])["form"]["claim_type"] == "NOT_RECEIVED"

    # The model saw the buyer text and the ceiling, and nothing else.
    body = fake.requests[0]["json"]
    assert set(body) == {"model", "temperature", "messages"}


def test_the_reader_is_given_the_dispute_amount_as_the_ceiling(tmp_path, policy_config):
    seen = {}

    class Response:
        status_code = 200
        headers: dict = {}

        def json(self):
            return {"choices": [{"message": {"content": "{}"}}]}

    class FakeClient:
        def post(self, url, **kwargs):
            seen["body"] = kwargs["json"]
            return Response()

    deps = PipelineDeps(
        audit=AuditLog(AuditConfig(db_path=str(tmp_path / "a.db"))),
        case_views=CaseViewStore(str(tmp_path / "v.db")),
        policy_config=policy_config,
        reader_config=ReaderConfig(
            base_url="https://model.example.invalid/v1",
            api_key="sk-test",
            model="m",
            retry_backoff_seconds=0.0,
        ),
        reader_client=FakeClient(),
    )

    process_case(load_fixture(), deps)

    user_turn = seen["body"]["messages"][1]["content"]
    assert "20.00" in user_turn


# -- the reader never reaches the payload -------------------------------


def test_the_persisted_view_keeps_reader_output_out_of_the_facts(deps):
    view = process_case(actionable_snapshot(), deps, seller_input=parse_seller_input(SELLER))

    facts_json = deps.case_views.get(FIXTURE_DISPUTE_ID)["facts_json"]

    # Facts carry only paypal_record and seller_input sources. There is no
    # reader-sourced fact, so reader output cannot reach a payload.
    sources = {fact["source"] for fact in json.loads(facts_json)["facts"].values()}
    assert sources <= {"paypal_record", "seller_input"}
    assert "reader" not in facts_json


# -- failure --------------------------------------------------------------


def test_a_record_that_fails_facts_is_recorded_as_such(deps):
    broken = copy.deepcopy(load_fixture())
    broken["dispute_id"] = "not a valid id!!"

    view = process_case(broken, deps)

    assert view.status == STATUS_FACTS_FAILED
    assert view.facts is None
    assert view.decision.allowed_actions == frozenset()
    assert deps.case_views.count() == 1


def test_a_snapshot_with_a_discrepancy_records_it(deps):
    view = process_case(load_fixture(), deps, seller_input=parse_seller_input(SELLER))

    assert view.discrepancy is not None
    row = deps.case_views.get(FIXTURE_DISPUTE_ID)
    assert "Review required" in row["discrepancy_json"]
    assert any(
        entry.action == "pipeline.discrepancy_detected" for entry in deps.audit.entries()
    )
