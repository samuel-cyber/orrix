"""Generate the Attack Lab's shipped preset file from the corpus.

Run this after editing attacks/corpus.yaml:

    python -m scripts.build_lab_presets

Why this exists: the lab's presets are author-written attack messages that
live in attacks/corpus.yaml, which ships with the evaluation harness. The
harness is not part of the installed application -- `attacks` is not a
declared package, and its loader needs PyYAML, which is not a runtime
dependency -- so on a deployment `import attacks.corpus` fails and the lab
reported "the corpus is not installed".

The fix is to ship the data rather than the harness: this writes the four
fields the preset list needs (id, category, text, kind) into the orrix.web
package, where package-data carries it into any install. Nothing from
attacks/recorded/ is involved; no run data, metrics or harness code is
shipped.

tests/test_lab_presets.py asserts the generated file still matches the
corpus, so the two cannot drift apart unnoticed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET = REPO_ROOT / "orrix" / "web" / "lab_presets.json"

#: Bumped if the shape of a preset ever changes, so a stale file is obvious
#: rather than silently half-read.
FORMAT_VERSION = 1


def build() -> dict:
    """Read the corpus and reduce it to what the preset list displays."""
    sys.path.insert(0, str(REPO_ROOT))
    from attacks.corpus import load_corpus

    presets = [
        {
            "id": attack.id,
            "category": attack.category,
            "text": attack.text,
            "kind": "honest" if attack.is_honest else "hostile",
        }
        for attack in load_corpus()
    ]
    return {"format": FORMAT_VERSION, "presets": presets}


def main() -> int:
    payload = build()
    TARGET.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(payload['presets'])} presets to {TARGET.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
