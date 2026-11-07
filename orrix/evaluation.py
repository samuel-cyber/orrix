"""Reads the evaluation harness output for display.

Plain code: it loads a JSON summary and the caveats that must be read
alongside it, validates the shape, and reports clearly when neither exists.
It computes nothing and asserts nothing about the numbers it finds.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

logger = logging.getLogger("orrix.evaluation")

#: How to produce the file when it is missing. Shown in the empty state.
GENERATE_COMMAND = "python -m attacks.run --live --out results/summary.json"

#: Rows must carry these; anything else in a row is ignored.
ROW_FIELDS = ("system", "attack_category", "runs", "unauthorized_actions", "soft_failures")


@dataclass(frozen=True)
class EvaluationRow:
    system: str
    attack_category: str
    runs: int
    unauthorized_actions: int
    soft_failures: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "system": self.system,
            "attack_category": self.attack_category,
            "runs": self.runs,
            "unauthorized_actions": self.unauthorized_actions,
            "soft_failures": self.soft_failures,
        }


@dataclass(frozen=True)
class EvaluationResults:
    """A loaded summary, or an explained absence."""

    available: bool
    model: str | None = None
    date: str | None = None
    n: int = 0
    rows: tuple[EvaluationRow, ...] = ()
    caveats: tuple[str, ...] = ()
    notes_available: bool = False
    message: str | None = None
    generate_command: str = GENERATE_COMMAND
    results_path: str = ""

    @property
    def systems(self) -> tuple[str, ...]:
        return tuple(sorted({row.system for row in self.rows}))

    @property
    def categories(self) -> tuple[str, ...]:
        return tuple(sorted({row.attack_category for row in self.rows}))

    @property
    def total_unauthorized(self) -> int:
        return sum(row.unauthorized_actions for row in self.rows)

    @property
    def total_soft_failures(self) -> int:
        return sum(row.soft_failures for row in self.rows)

    def as_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "model": self.model,
            "date": self.date,
            "n": self.n,
            "rows": [row.as_dict() for row in self.rows],
            "caveats": list(self.caveats),
            "notes_available": self.notes_available,
            "message": self.message,
            "generate_command": self.generate_command,
            "results_path": self.results_path,
            "systems": list(self.systems),
            "categories": list(self.categories),
            "total_unauthorized": self.total_unauthorized,
            "total_soft_failures": self.total_soft_failures,
        }


def _int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else ""


def _parse_rows(raw: Any) -> tuple[EvaluationRow, ...]:
    if not isinstance(raw, list):
        return ()
    rows: list[EvaluationRow] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        system = _text(item.get("system"))
        category = _text(item.get("attack_category"))
        if not system or not category:
            continue
        rows.append(
            EvaluationRow(
                system=system,
                attack_category=category,
                runs=_int(item.get("runs")),
                unauthorized_actions=_int(item.get("unauthorized_actions")),
                soft_failures=_int(item.get("soft_failures")),
            )
        )
    return tuple(rows)


def load_caveats(notes_path: str | Path) -> tuple[tuple[str, ...], bool]:
    """Pull the caveats out of docs/RESULTS.md.

    Looks for a heading containing "caveat" or "limitation" and returns the
    bullet lines under it. Absent file or absent section is not an error.
    """
    path = Path(notes_path)
    if not path.is_file():
        return (), False

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return (), False

    caveats: list[str] = []
    in_section = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            heading = stripped.lstrip("#").strip().lower()
            in_section = "caveat" in heading or "limitation" in heading
            continue
        if not in_section:
            continue
        if stripped.startswith(("-", "*")):
            caveats.append(stripped.lstrip("-* ").strip())
        elif stripped and not caveats:
            caveats.append(stripped)
    return tuple(caveats), True


def load_results(
    results_path: str | Path, notes_path: str | Path | None = None
) -> EvaluationResults:
    """Load the summary, or explain why there is nothing to show."""
    path = Path(results_path)
    caveats, notes_available = load_caveats(notes_path) if notes_path else ((), False)

    if not path.is_file():
        return EvaluationResults(
            available=False,
            message=f"No evaluation results at {path}.",
            caveats=caveats,
            notes_available=notes_available,
            results_path=str(path),
        )

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        logger.warning("evaluation results could not be read: %s", type(error).__name__)
        return EvaluationResults(
            available=False,
            message=f"{path} exists but could not be parsed as JSON.",
            caveats=caveats,
            notes_available=notes_available,
            results_path=str(path),
        )

    if not isinstance(payload, Mapping):
        return EvaluationResults(
            available=False,
            message=f"{path} is not a JSON object.",
            caveats=caveats,
            notes_available=notes_available,
            results_path=str(path),
        )

    rows = _parse_rows(payload.get("rows"))
    if not rows:
        return EvaluationResults(
            available=False,
            message=f"{path} carries no usable rows.",
            caveats=caveats,
            notes_available=notes_available,
            results_path=str(path),
        )

    declared_n = _int(payload.get("n"))
    return EvaluationResults(
        available=True,
        model=_text(payload.get("model")) or None,
        date=_text(payload.get("date")) or None,
        n=declared_n or sum(row.runs for row in rows),
        rows=rows,
        caveats=caveats,
        notes_available=notes_available,
        results_path=str(path),
    )
