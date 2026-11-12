"""The evaluation summary: Orrix's own numbers, never pooled with baselines.

The landing page's headline card is a claim about Orrix specifically. Reading
it off a combined total -- the sum over every system the harness ran,
including the two baseline agents kept for comparison -- let a baseline's own
failure print as "by Orrix" on the one page most visitors read. These tests
pin the fix: the card's number is the orrix row's own count, and nothing
else, verified against both a synthetic multi-system fixture and the real
committed results/summary.json.
"""

from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

from orrix.evaluation import ORRIX_SYSTEM, load_results
from orrix.main import create_app

from .conftest import build_app_config

REPO_ROOT_RESULTS = "results/summary.json"


def _row(system, category, runs, unauthorized, soft_failures=0, **extra):
    return {
        "system": system,
        "attack_category": category,
        "runs": runs,
        "valid_runs": runs,
        "unauthorized_actions": unauthorized,
        "soft_failures": soft_failures,
        **extra,
    }


def write_summary(path, rows, **extra):
    payload = {
        "model": "test-model",
        "date": "2026-11-13",
        "n": 3,
        "rows": rows,
        **extra,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# -- the fix, isolated from any real file --------------------------------


def test_orrix_unauthorized_is_the_orrix_row_alone(tmp_path):
    """A baseline's failure must not count toward Orrix's own number."""
    summary = write_summary(
        tmp_path / "summary.json",
        [
            _row("naive_agent", "fake_authority", runs=3, unauthorized=1),
            _row("defended_agent", "fake_authority", runs=3, unauthorized=0),
            _row(ORRIX_SYSTEM, "fake_authority", runs=3, unauthorized=0),
        ],
    )

    results = load_results(summary)

    assert results.orrix_unauthorized == 0
    # The old, buggy source: this must NOT equal the Orrix-only number here,
    # or the fixture is not actually exercising the bug this test pins.
    assert results.combined_unauthorized == 1
    assert results.orrix_unauthorized != results.combined_unauthorized


def test_orrix_unauthorized_counts_only_orrix_rows_when_orrix_also_fails(tmp_path):
    """Symmetric check: Orrix's own failures count; a baseline's do not."""
    summary = write_summary(
        tmp_path / "summary.json",
        [
            _row("naive_agent", "fake_authority", runs=3, unauthorized=2),
            _row(ORRIX_SYSTEM, "fake_authority", runs=3, unauthorized=1),
            _row(ORRIX_SYSTEM, "direct_override", runs=3, unauthorized=1),
        ],
    )

    results = load_results(summary)

    assert results.orrix_unauthorized == 2
    assert results.combined_unauthorized == 4


def test_orrix_valid_runs_is_the_orrix_row_alone(tmp_path):
    summary = write_summary(
        tmp_path / "summary.json",
        [
            _row("naive_agent", "fake_authority", runs=84, unauthorized=1),
            _row(ORRIX_SYSTEM, "fake_authority", runs=84, unauthorized=0),
        ],
    )

    results = load_results(summary)

    assert results.orrix_valid_runs == 84


def test_no_orrix_row_is_zero_not_an_error(tmp_path):
    """A summary missing the orrix system must not crash the page."""
    summary = write_summary(
        tmp_path / "summary.json",
        [_row("naive_agent", "fake_authority", runs=3, unauthorized=1)],
    )

    results = load_results(summary)

    assert results.orrix_unauthorized == 0
    assert results.orrix_valid_runs == 0


# -- against the real, committed summary file -----------------------------


@pytest.fixture
def real_summary_rows():
    try:
        payload = json.loads(open(REPO_ROOT_RESULTS, encoding="utf-8").read())
    except FileNotFoundError:
        pytest.skip(f"{REPO_ROOT_RESULTS} is not present in this checkout")
    return payload["rows"]


def test_the_card_equals_the_orrix_row_of_the_real_summary(real_summary_rows):
    """The exact ask: the headline must equal results/summary.json's own
    orrix row, recomputed independently of orrix/evaluation.py's internals.
    """
    expected_unauthorized = sum(
        row["unauthorized_actions"]
        for row in real_summary_rows
        if row["system"] == ORRIX_SYSTEM
    )
    expected_runs = sum(
        row.get("valid_runs") or row["runs"]
        for row in real_summary_rows
        if row["system"] == ORRIX_SYSTEM
    )

    results = load_results(REPO_ROOT_RESULTS)

    assert results.orrix_unauthorized == expected_unauthorized
    assert results.orrix_valid_runs == expected_runs


def test_the_real_summary_actually_exercises_the_distinction():
    """If this ever stops being true, the regression test above goes quiet
    without anyone noticing -- so it is checked explicitly here.
    """
    results = load_results(REPO_ROOT_RESULTS)
    if not results.available:
        pytest.skip("results/summary.json not present in this checkout")

    assert results.combined_unauthorized >= 1
    assert results.orrix_unauthorized == 0
    assert results.orrix_unauthorized != results.combined_unauthorized


# -- through the rendered page --------------------------------------------


@pytest.fixture
def landing_client(tmp_path):
    # A label is included so the per-label card (and its "reported per
    # system, on one model" sentence) actually renders -- that block is
    # gated on `results.labels` being non-empty.
    summary = write_summary(
        tmp_path / "summary.json",
        [
            _row("naive_agent", "fake_authority", runs=84, unauthorized=1),
            _row("defended_agent", "fake_authority", runs=84, unauthorized=0),
            _row(ORRIX_SYSTEM, "fake_authority", runs=84, unauthorized=0),
        ],
        labels=[
            {
                "label": "test-label",
                "model": "test-model",
                "date": "2026-11-13",
                "n": 3,
                "unauthorized_by_system": {
                    "naive_agent": 1,
                    "defended_agent": 0,
                    ORRIX_SYSTEM: 0,
                },
                "valid_runs_by_system": {
                    "naive_agent": 84,
                    "defended_agent": 84,
                    ORRIX_SYSTEM: 84,
                },
            }
        ],
    )
    config = build_app_config(tmp_path, results_path=str(summary))
    with TestClient(create_app(config=config), follow_redirects=False) as client:
        yield client


def test_the_landing_page_shows_zero_not_the_pooled_total(landing_client):
    body = landing_client.get("/").text

    assert "unauthorized actions by Orrix" in body
    # Find the number's own span, not just any "0" on the page: the
    # data-count-to attribute is what the count-up animation reads, so it is
    # the authoritative source of "what number does this card show".
    match = re.search(
        r'data-count-to="(\d+)">\1</span>\s*<span class="proof-label">'
        r"unauthorized actions by Orrix",
        body,
    )
    assert match is not None, "could not find the Orrix unauthorized-count span"
    assert match.group(1) == "0", (
        f"the card shows {match.group(1)}, not Orrix's own count (0); the "
        f"pooled total (1, from naive_agent) may have leaked back in"
    )


def test_the_landing_page_shows_the_run_count_alongside_it(landing_client):
    body = landing_client.get("/").text

    assert "84 runs" in body


def test_the_proof_section_wording_is_per_system_not_pooled(landing_client):
    # Collapsed because the template line-wraps this sentence; the words and
    # their order are what matter, not the exact whitespace.
    collapsed = re.sub(r"\s+", " ", landing_client.get("/").text)

    assert "Results are reported per system, on one model." in collapsed
    assert "Results are never pooled into a single headline." not in collapsed
