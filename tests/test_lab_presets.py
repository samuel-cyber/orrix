"""The Attack Lab's presets must be available in a deployed build.

On Render the lab reported "the corpus is not installed" for two independent
reasons: `attacks` is not a declared package, so it is not importable from an
installed app; and attacks/corpus.py imports PyYAML, which is not a runtime
dependency. Both are swallowed by a broad except, so the symptom was simply
an empty preset list.

The fix ships the preset data inside orrix.web. These tests hold the shipped
file to the corpus so the two cannot drift, and prove the lab works with the
harness unreachable.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from orrix.web.lab import PRESETS_FILE, _presets_from_file, load_presets

REPO_ROOT = Path(__file__).parent.parent


# -- the shipped file exists and is well formed --------------------------


def test_the_shipped_preset_file_is_committed():
    assert PRESETS_FILE.is_file(), (
        f"{PRESETS_FILE} is missing. Regenerate it with "
        f"`python scripts/build_lab_presets.py`."
    )


def test_the_shipped_file_lives_inside_the_installed_package():
    """Outside orrix/ it would not be packaged."""
    assert PRESETS_FILE.parent.name == "web"
    assert PRESETS_FILE.parent.parent.name == "orrix"


def test_every_shipped_preset_has_the_four_display_fields():
    presets = load_presets()

    assert presets
    for preset in presets:
        assert set(preset) == {"id", "category", "text", "kind"}
        assert all(isinstance(value, str) and value for value in preset.values())
        assert preset["kind"] in ("honest", "hostile")


def test_the_shipped_file_carries_no_run_data():
    """Only message text and labels; nothing from attacks/recorded/."""
    payload = json.loads(PRESETS_FILE.read_text(encoding="utf-8"))

    for preset in payload["presets"]:
        assert set(preset) == {"id", "category", "text", "kind"}

    raw = PRESETS_FILE.read_text(encoding="utf-8")
    for forbidden in ("recorded", "jsonl", "unauthorized_action", "runs", "metrics"):
        assert forbidden not in raw


def test_the_shipped_file_is_small():
    """It is preset text, not a corpus dump."""
    assert PRESETS_FILE.stat().st_size < 64 * 1024


# -- it matches the corpus ------------------------------------------------


def corpus_presets():
    from attacks.corpus import load_corpus

    return [
        {
            "id": attack.id,
            "category": attack.category,
            "text": attack.text,
            "kind": "honest" if attack.is_honest else "hostile",
        }
        for attack in load_corpus()
    ]


def test_the_shipped_file_matches_the_corpus_exactly():
    """Regenerate with scripts/build_lab_presets.py if this fails."""
    shipped = json.loads(PRESETS_FILE.read_text(encoding="utf-8"))["presets"]

    assert shipped == corpus_presets(), (
        "orrix/web/lab_presets.json is out of step with attacks/corpus.yaml. "
        "Run `python scripts/build_lab_presets.py` and commit the result."
    )


def test_the_generator_is_reproducible(tmp_path):
    """Running it twice produces the same bytes."""
    from scripts.build_lab_presets import build

    first = json.dumps(build(), sort_keys=True)
    second = json.dumps(build(), sort_keys=True)

    assert first == second


# -- it works with the harness unreachable --------------------------------


PROBE = """
import json, sys

class Blocker:
    def find_module(self, name, path=None):
        return self.find_spec(name, path)

    def find_spec(self, name, path=None, target=None):
        if name == "attacks" or name.startswith("attacks."):
            raise ImportError("the evaluation harness is not installed")
        if name == "yaml" or name.startswith("yaml."):
            raise ImportError("PyYAML is not a runtime dependency")
        return None

sys.meta_path.insert(0, Blocker())

from orrix.web.lab import load_presets

for module in ("attacks", "yaml"):
    try:
        __import__(module)
    except ImportError:
        pass
    else:
        print(json.dumps({"error": module + " was importable despite the block"}))
        raise SystemExit(1)

presets = load_presets()
print(json.dumps({"count": len(presets), "first": presets[0] if presets else None}))
"""


def test_presets_load_without_the_harness_or_pyyaml():
    """The deployed condition, reproduced exactly.

    Both imports the old code depended on are made to fail, and the preset
    list must still come back populated.
    """
    completed = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(PROBE)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=120,
    )

    assert completed.returncode == 0, f"{completed.stdout}\n{completed.stderr}"
    result = json.loads(completed.stdout.strip().splitlines()[-1])

    assert "error" not in result, result
    assert result["count"] == len(corpus_presets())
    assert result["first"]["id"]
    assert result["first"]["text"]


# -- degradation is honest ------------------------------------------------


def test_a_missing_file_is_an_empty_list_not_an_exception(tmp_path):
    assert _presets_from_file(tmp_path / "nope.json") == ()


def test_a_corrupt_file_is_an_empty_list_not_an_exception(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")

    assert _presets_from_file(bad) == ()


def test_a_file_with_no_preset_list_is_empty(tmp_path):
    odd = tmp_path / "odd.json"
    odd.write_text(json.dumps({"format": 1}), encoding="utf-8")

    assert _presets_from_file(odd) == ()


def test_entries_missing_a_field_are_dropped_not_half_rendered(tmp_path):
    partial = tmp_path / "partial.json"
    partial.write_text(
        json.dumps(
            {
                "format": 1,
                "presets": [
                    {"id": "ok", "category": "c", "text": "t", "kind": "hostile"},
                    {"id": "no_text", "category": "c", "kind": "hostile"},
                    {"id": "bad_kind", "category": "c", "text": "t", "kind": "maybe"},
                ],
            }
        ),
        encoding="utf-8",
    )

    presets = _presets_from_file(partial)

    assert [preset["id"] for preset in presets] == ["ok"]


# -- packaging ------------------------------------------------------------


def test_the_package_data_declares_the_preset_file():
    """Without this the wheel would not carry it."""
    content = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert "lab_presets.json" in content


def test_the_harness_is_still_not_a_declared_package():
    """Shipping the data, not the harness: recorded runs stay out of builds."""
    content = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert 'packages = ["orrix", "orrix.web"]' in content
    assert '"attacks"' not in content
