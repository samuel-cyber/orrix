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
    #: Which provider/model run produced this row. Empty for a summary
    #: written before labels existed.
    label: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "system": self.system,
            "attack_category": self.attack_category,
            "runs": self.runs,
            "unauthorized_actions": self.unauthorized_actions,
            "soft_failures": self.soft_failures,
            "label": self.label,
        }


@dataclass(frozen=True)
class EvaluationLabel:
    """One provider/model run, reported on its own terms.

    Results are never pooled into a single headline: a label is the unit
    that a model id and a date actually describe.
    """

    label: str
    model: str
    date: str
    n: int
    record_count: int = 0
    total_unauthorized: int = 0
    total_soft_failures: int = 0
    systems: tuple[str, ...] = ()
    unauthorized_by_system: tuple[tuple[str, int], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "model": self.model,
            "date": self.date,
            "n": self.n,
            "record_count": self.record_count,
            "total_unauthorized": self.total_unauthorized,
            "total_soft_failures": self.total_soft_failures,
            "systems": list(self.systems),
            "unauthorized_by_system": [
                {"system": system, "unauthorized_actions": count}
                for system, count in self.unauthorized_by_system
            ],
        }


@dataclass(frozen=True)
class EvaluationResults:
    """A loaded summary, or an explained absence."""

    available: bool
    model: str | None = None
    date: str | None = None
    n: int = 0
    rows: tuple[EvaluationRow, ...] = ()
    labels: tuple[EvaluationLabel, ...] = ()
    combined_unauthorized: int = 0
    combined_soft_failures: int = 0
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
    def label_names(self) -> tuple[str, ...]:
        return tuple(label.label for label in self.labels)

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
            "labels": [label.as_dict() for label in self.labels],
            "combined_unauthorized": self.combined_unauthorized,
            "combined_soft_failures": self.combined_soft_failures,
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
                label=_text(item.get("label")),
            )
        )
    return tuple(rows)


def _parse_labels(raw: Any) -> tuple[EvaluationLabel, ...]:
    if not isinstance(raw, list):
        return ()
    labels: list[EvaluationLabel] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        name = _text(item.get("label"))
        if not name:
            continue
        by_system = item.get("unauthorized_by_system")
        pairs: list[tuple[str, int]] = []
        if isinstance(by_system, Mapping):
            pairs = [(str(k), _int(v)) for k, v in sorted(by_system.items())]
        elif isinstance(by_system, list):
            for entry in by_system:
                if isinstance(entry, Mapping):
                    pairs.append(
                        (_text(entry.get("system")), _int(entry.get("unauthorized_actions")))
                    )
        systems = item.get("systems")
        labels.append(
            EvaluationLabel(
                label=name,
                model=_text(item.get("model")) or "unrecorded",
                date=_text(item.get("date")) or "unrecorded",
                n=_int(item.get("n")),
                record_count=_int(item.get("record_count")),
                total_unauthorized=_int(item.get("total_unauthorized")),
                total_soft_failures=_int(item.get("total_soft_failures")),
                systems=tuple(str(s) for s in systems) if isinstance(systems, list) else (),
                unauthorized_by_system=tuple(pairs),
            )
        )
    return tuple(labels)


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

    # Caveats come from docs/RESULTS.md when it exists; the harness also
    # writes them into the summary, so the page is never left showing bare
    # numbers because a notes file went missing.
    if not caveats:
        embedded = payload.get("caveats")
        if isinstance(embedded, list):
            caveats = tuple(_text(item) for item in embedded if _text(item))

    return EvaluationResults(
        available=True,
        model=_text(payload.get("model")) or None,
        date=_text(payload.get("date")) or None,
        n=declared_n or sum(row.runs for row in rows),
        rows=rows,
        labels=_parse_labels(payload.get("labels")),
        combined_unauthorized=_int(payload.get("combined_unauthorized_actions"))
        or sum(row.unauthorized_actions for row in rows),
        combined_soft_failures=_int(payload.get("combined_soft_failures"))
        or sum(row.soft_failures for row in rows),
        caveats=caveats,
        notes_available=notes_available,
        results_path=str(path),
    )
