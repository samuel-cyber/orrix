"""Caps, clock, and autonomy rules in plain code."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable

from .claim_form import ClaimForm
from .discrepancy import detect_discrepancy
from .facts import Facts, FactStatus

# The complete universe of actions v3 policy may ever permit. Refunds,
# accepting a claim and making an offer are deliberately absent: there is no
# code path in this version that can produce them.
PROVIDE_EVIDENCE = "provide_evidence"
ALLOWED_ACTION_UNIVERSE = frozenset({PROVIDE_EVIDENCE})

# Names of actions that move money. Checked against output as a backstop so a
# future edit cannot quietly introduce one.
MONEY_MOVING_ACTIONS = frozenset(
    {
        "refund",
        "full_refund",
        "partial_refund",
        "accept_claim",
        "make_offer",
        "escalate",
        "send_message",
    }
)

# Facts that must be confirmed before any action is considered.
REQUIRED_FACTS: tuple[str, ...] = (
    "dispute_id",
    "status",
    "dispute_state",
    "stage",
    "reason",
    "dispute_amount",
    "dispute_currency",
    "seller_transaction_id",
    "transaction_status",
    "gross_amount",
    "seller_protection_eligible",
)

# Facts specific to submitting proof of fulfilment.
EVIDENCE_FACTS: tuple[str, ...] = ("tracking_carrier", "tracking_number")

REQUIRED_STATUS = "WAITING_FOR_SELLER_RESPONSE"
REQUIRED_DISPUTE_STATE = "REQUIRED_ACTION"
ALLOWED_STAGES = frozenset({"INQUIRY"})
PROOF_OF_FULFILLMENT = "PROOF_OF_FULFILLMENT"

# Reader reasons that mean the reader never ran, as opposed to ran and
# failed. Duplicated as literals rather than imported: policy must not
# import the reader, and tests/test_boundaries.py enforces that. Kept in
# step with orrix.reader by test_policy_and_reader_agree_on_did_not_run.
DID_NOT_RUN_REASONS = frozenset({"reader_not_configured", "no_buyer_text"})

_TIMESTAMP_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z")

# Flags
FLAG_NEEDS_HUMAN_REVIEW = "needs_human_review"
FLAG_FACTS_INCOMPLETE = "facts_incomplete"
FLAG_FACTS_CONFLICTING = "facts_conflicting"
FLAG_NO_EVIDENCE_AVAILABLE = "no_evidence_available"
FLAG_DEADLINE_PASSED = "deadline_passed"
FLAG_ALREADY_DONE = "already_done"
FLAG_REFUNDS_NOT_IMPLEMENTED = "refunds_not_implemented"
FLAG_DISCREPANCY = "discrepancy_detected"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class PolicyConfig:
    """Caps, clock and autonomy settings, passed in by the caller.

    refund_cap_usd exists so the cap is explicit and auditable, but v3 has no
    refund action at all: raising it grants nothing. See
    test_no_claim_form_can_produce_a_refund_action.
    """

    refund_cap_usd: Decimal = Decimal("0")
    required_facts: tuple[str, ...] = REQUIRED_FACTS
    allowed_stages: frozenset[str] = ALLOWED_STAGES
    min_hours_before_deadline: float = 0.0
    clock: Callable[[], datetime] = field(default=_utc_now, repr=False)


@dataclass(frozen=True)
class CaseState:
    """What Orrix has already done on this dispute."""

    dispute_id: str
    executed_actions: frozenset[str] = frozenset()
    evidence_already_submitted: bool = False
    under_review: bool = False


@dataclass(frozen=True)
class PolicyDecision:
    allowed_actions: frozenset[str]
    reasons: tuple[str, ...]
    flags: frozenset[str]

    @property
    def requires_review(self) -> bool:
        return FLAG_NEEDS_HUMAN_REVIEW in self.flags

    def permits(self, action: str) -> bool:
        return action in self.allowed_actions


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip().replace("Z", "+0000")
    text = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", text)
    for fmt in _TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _needs_review(claim_input: Any) -> bool:
    """True when the reader ran and could not produce a usable form.

    A ClaimForm is fine. None means a fact-only check with no reader
    involvement, which is what the executor does.

    A reader that never ran is distinct from one that ran and failed. No
    model configured, or no buyer text to read, is an operational absence
    and leaves the fact-based rules to decide — the evidence path does not
    depend on the reader, since the payload is built from Facts. A reader
    that did run and returned unparseable or invalid output is a signal
    something is wrong, and blocks.

    Either way the reader can only ever block. It can never enable an action.
    """
    if claim_input is None or isinstance(claim_input, ClaimForm):
        return False

    status = getattr(claim_input, "status", None)
    form = getattr(claim_input, "form", None)
    if status == "ok" and isinstance(form, ClaimForm):
        return False

    if getattr(claim_input, "reason", None) in DID_NOT_RUN_REASONS:
        return False

    return True


def decide(
    facts: Facts,
    claim_form_or_needs_review: Any,
    case_state: CaseState,
    config: PolicyConfig | None = None,
) -> PolicyDecision:
    """Decide what Orrix may do. Plain code; no model is consulted.

    Fails closed at every branch: anything unexpected, missing, conflicting
    or stale yields no actions and a review flag. The only action that can
    ever come out is provide_evidence.
    """
    config = config or PolicyConfig()
    reasons: list[str] = []
    flags: set[str] = set()

    if config.refund_cap_usd and config.refund_cap_usd > 0:
        # Recorded rather than honoured: v3 emits no money-moving action.
        reasons.append("refund_cap_set_but_v3_emits_no_refund_action")
        flags.add(FLAG_REFUNDS_NOT_IMPLEMENTED)

    if not isinstance(facts, Facts):
        return _blocked(["facts_missing"], {FLAG_NEEDS_HUMAN_REVIEW}, reasons, flags)

    if not isinstance(case_state, CaseState):
        return _blocked(["case_state_missing"], {FLAG_NEEDS_HUMAN_REVIEW}, reasons, flags)

    if case_state.dispute_id != facts.dispute_id:
        return _blocked(
            ["case_state_dispute_id_mismatch"], {FLAG_NEEDS_HUMAN_REVIEW}, reasons, flags
        )

    if case_state.under_review:
        return _blocked(["case_already_under_review"], {FLAG_NEEDS_HUMAN_REVIEW}, reasons, flags)

    # The reader could not produce a form: a human decides, not Orrix.
    if _needs_review(claim_form_or_needs_review):
        return _blocked(["reader_needs_review"], {FLAG_NEEDS_HUMAN_REVIEW}, reasons, flags)

    # Any key fact missing or contradictory stops everything.
    unavailable: list[str] = []
    conflicting: list[str] = []
    for name in config.required_facts:
        try:
            status = facts.status(name)
        except KeyError:
            unavailable.append(name)
            continue
        if status is FactStatus.UNAVAILABLE:
            unavailable.append(name)
        elif status is FactStatus.CONFLICTING:
            conflicting.append(name)

    if conflicting:
        return _blocked(
            [f"conflicting_fact:{name}" for name in sorted(conflicting)],
            {FLAG_NEEDS_HUMAN_REVIEW, FLAG_FACTS_CONFLICTING},
            reasons,
            flags,
        )
    if unavailable:
        return _blocked(
            [f"unavailable_fact:{name}" for name in sorted(unavailable)],
            {FLAG_NEEDS_HUMAN_REVIEW, FLAG_FACTS_INCOMPLETE},
            reasons,
            flags,
        )

    # -- from here on, every required fact is confirmed -------------------

    blocking: list[str] = []

    if facts.value("status") != REQUIRED_STATUS:
        blocking.append(f"status_not_actionable:{facts.value('status')}")
    if facts.value("dispute_state") != REQUIRED_DISPUTE_STATE:
        blocking.append(f"dispute_state_not_actionable:{facts.value('dispute_state')}")
    if facts.value("stage") not in config.allowed_stages:
        blocking.append(f"stage_not_actionable:{facts.value('stage')}")

    if case_state.evidence_already_submitted or PROVIDE_EVIDENCE in case_state.executed_actions:
        blocking.append("evidence_already_submitted")
        flags.add(FLAG_ALREADY_DONE)

    requested = facts.value("requested_evidence_types") or ()
    if PROOF_OF_FULFILLMENT not in requested:
        blocking.append("proof_of_fulfillment_not_requested")

    # Tracking from either source is enough to submit evidence, but a
    # conflict between the two sources is not: that needs a human.
    conflicting_evidence_facts = [
        name for name in EVIDENCE_FACTS if facts.status(name) is FactStatus.CONFLICTING
    ]
    if conflicting_evidence_facts:
        blocking.append("tracking_conflicting:" + ",".join(sorted(conflicting_evidence_facts)))
        flags.add(FLAG_FACTS_CONFLICTING)

    missing_evidence_facts = [
        name for name in EVIDENCE_FACTS if not facts.get(name).is_usable
    ]
    if missing_evidence_facts:
        blocking.append("tracking_unavailable:" + ",".join(sorted(missing_evidence_facts)))
        flags.add(FLAG_NO_EVIDENCE_AVAILABLE)

    deadline = _parse_timestamp(facts.value("seller_response_due_date"))
    if deadline is None:
        blocking.append("deadline_unavailable")
        flags.add(FLAG_FACTS_INCOMPLETE)
    else:
        remaining_hours = (deadline - config.clock()).total_seconds() / 3600.0
        if remaining_hours <= config.min_hours_before_deadline:
            blocking.append("deadline_passed")
            flags.add(FLAG_DEADLINE_PASSED)

    if blocking:
        reasons.extend(sorted(blocking))
        if (
            FLAG_NO_EVIDENCE_AVAILABLE in flags
            or FLAG_DEADLINE_PASSED in flags
            or FLAG_FACTS_CONFLICTING in flags
        ):
            flags.add(FLAG_NEEDS_HUMAN_REVIEW)
        return PolicyDecision(
            allowed_actions=frozenset(), reasons=tuple(reasons), flags=frozenset(flags)
        )

    reasons.append(f"tracking_available_from:{facts.source('tracking_number')}")
    reasons.append("proof_of_fulfillment_requested_and_tracking_available")

    # A discrepancy is surfaced for review but does not veto a submission the
    # seller has approved: the seller is entitled to put their evidence in
    # front of PayPal even when it contradicts the buyer's account.
    discrepancy = detect_discrepancy(facts)
    if discrepancy is not None:
        reasons.append("discrepancy_detected")
        flags.add(FLAG_DISCREPANCY)
        flags.add(FLAG_NEEDS_HUMAN_REVIEW)

    allowed = frozenset({PROVIDE_EVIDENCE})

    # Backstop: nothing outside the universe, and never a money-moving action.
    assert allowed <= ALLOWED_ACTION_UNIVERSE, "policy emitted an unknown action"
    assert not (allowed & MONEY_MOVING_ACTIONS), "policy emitted a money-moving action"

    return PolicyDecision(
        allowed_actions=allowed, reasons=tuple(reasons), flags=frozenset(flags)
    )


def _blocked(
    new_reasons: list[str],
    new_flags: set[str],
    reasons: list[str],
    flags: set[str],
) -> PolicyDecision:
    return PolicyDecision(
        allowed_actions=frozenset(),
        reasons=tuple(reasons + new_reasons),
        flags=frozenset(flags | new_flags),
    )
