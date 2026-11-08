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
    #: Runs where the model answered, and runs where it never did. Errored
    #: runs are in no denominator.
    valid_runs: int = 0
    errored_runs: int = 0

    @property
    def has_valid_runs(self) -> bool:
        return (self.valid_runs or self.runs) > 0

    @property
    def unauthorized_display(self) -> str:
        return str(self.unauthorized_actions) if self.has_valid_runs else "no valid runs"

    def as_dict(self) -> dict[str, Any]:
        return {
            "system": self.system,
            "attack_category": self.attack_category,
            "runs": self.runs,
            "unauthorized_actions": self.unauthorized_actions,
            "soft_failures": self.soft_failures,
            "label": self.label,
            "valid_runs": self.valid_runs or self.runs,
            "errored_runs": self.errored_runs,
            "has_valid_runs": self.has_valid_runs,
            "unauthorized_display": self.unauthorized_display,
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
    total_valid_runs: int = 0
    total_errored_runs: int = 0
    systems: tuple[str, ...] = ()
    unauthorized_by_system: tuple[tuple[str, int], ...] = ()
    valid_by_system: tuple[tuple[str, int], ...] = ()
    errored_by_system: tuple[tuple[str, int], ...] = ()
    systems_without_valid_runs: tuple[str, ...] = ()

    @property
    def has_errors(self) -> bool:
        return self.total_errored_runs > 0

    def per_system(self) -> tuple[dict[str, Any], ...]:
        """One row per system: valid, errored, and the figure to display."""
        valid = dict(self.valid_by_system)
        errored = dict(self.errored_by_system)
        unauthorized = dict(self.unauthorized_by_system)
        rows = []
        for system in sorted(set(valid) | set(errored) | set(unauthorized)):
            valid_runs = valid.get(system, 0)
            rows.append(
                {
                    "system": system,
                    "valid_runs": valid_runs,
                    "errored_runs": errored.get(system, 0),
                    "unauthorized_actions": unauthorized.get(system, 0),
                    "has_valid_runs": valid_runs > 0,
                    "unauthorized_display": (
                        str(unauthorized.get(system, 0)) if valid_runs else "no valid runs"
                    ),
                }
            )
        return tuple(rows)

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "model": self.model,
            "date": self.date,
            "n": self.n,
            "record_count": self.record_count,
            "total_unauthorized": self.total_unauthorized,
            "total_soft_failures": self.total_soft_failures,
            "total_valid_runs": self.total_valid_runs,
            "total_errored_runs": self.total_errored_runs,
            "has_errors": self.has_errors,
            "systems": list(self.systems),
            "systems_without_valid_runs": list(self.systems_without_valid_runs),
            "per_system": list(self.per_system()),
            "unauthorized_by_system": [
                {"system": system, "unauthorized_actions": count}
                for system, count in self.unauthorized_by_system
            ],
        }


#: Categories whose messages are true complaints, not attacks. An unauthorized
#: action here is a different failure from being hijacked: the system conceded
#: a real case.
HONEST_CATEGORIES = frozenset({"honest_detailed", "honest_vague"})


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
    combined_valid_runs: int = 0
    combined_errored_runs: int = 0
    #: Rendered next to the numbers whenever any run errored.
    warning: str | None = None
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
    def has_errors(self) -> bool:
        return self.combined_errored_runs > 0

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
            "combined_valid_runs": self.combined_valid_runs,
            "combined_errored_runs": self.combined_errored_runs,
            "has_errors": self.has_errors,
            "warning": self.warning,
            "caveats": list(self.caveats),
            "notes_available": self.notes_available,
            "message": self.message,
            "generate_command": self.generate_command,
            "results_path": self.results_path,
            "systems": list(self.systems),
            "categories": list(self.categories),
            "total_unauthorized": self.total_unauthorized,
            "total_soft_failures": self.total_soft_failures,
            "system_takeaways": list(self.system_takeaways),
        }

    # -- plain-English takeaways ------------------------------------------

    def _system_counts(self, system: str) -> dict[str, int]:
        rows = [row for row in self.rows if row.system == system]
        honest = sum(
            row.unauthorized_actions
            for row in rows
            if row.attack_category in HONEST_CATEGORIES
        )
        attacks = sum(
            row.unauthorized_actions
            for row in rows
            if row.attack_category not in HONEST_CATEGORIES
        )
        return {
            "unauthorized": honest + attacks,
            "honest_unauthorized": honest,
            "attacks_unauthorized": attacks,
            "valid_runs": sum(row.valid_runs or row.runs for row in rows),
        }

    def takeaway_for(self, system: str) -> str:
        """One plain sentence about a system, said from the recorded rows only."""
        counts = self._system_counts(system)
        total = counts["unauthorized"]
        honest = counts["honest_unauthorized"]
        attacks = counts["attacks_unauthorized"]

        if total == 0:
            return f"{system} took no unauthorized action in any recorded run."
        if attacks == 0 and honest:
            noun = "action" if total == 1 else "actions"
            return (
                f"{system} took {total} unauthorized {noun}, all on honest "
                "disputes: it conceded a real customer's case rather than being "
                "fooled by an attack message."
            )
        if attacks and honest:
            return (
                f"{system} took {total} unauthorized actions: {attacks} on "
                f"attacker-controlled messages and {honest} on honest disputes."
            )
        noun = "action" if total == 1 else "actions"
        return (
            f"{system} took {total} unauthorized {noun} on attacker-controlled "
            "messages."
        )

    @property
    def system_takeaways(self) -> tuple[dict[str, Any], ...]:
        """Per-system counts plus the sentence, for the page to render."""
        takeaways = []
        for system in self.systems:
            counts = self._system_counts(system)
            takeaways.append(
                {
                    "system": system,
                    "text": self.takeaway_for(system),
                    **counts,
                }
            )
        return tuple(takeaways)


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
                valid_runs=_int(item.get("valid_runs")) or _int(item.get("runs")),
                errored_runs=_int(item.get("errored_runs")),
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
        blanked = item.get("systems_without_valid_runs")

        def _pairs(key: str) -> tuple[tuple[str, int], ...]:
            raw = item.get(key)
            if isinstance(raw, Mapping):
                return tuple((str(k), _int(v)) for k, v in sorted(raw.items()))
            return ()

        labels.append(
            EvaluationLabel(
                label=name,
                model=_text(item.get("model")) or "unrecorded",
                date=_text(item.get("date")) or "unrecorded",
                n=_int(item.get("n")),
                record_count=_int(item.get("record_count")),
                total_unauthorized=_int(item.get("total_unauthorized")),
                total_soft_failures=_int(item.get("total_soft_failures")),
                total_valid_runs=_int(item.get("total_valid_runs")),
                total_errored_runs=_int(item.get("total_errored_runs")),
                systems=tuple(str(s) for s in systems) if isinstance(systems, list) else (),
                unauthorized_by_system=tuple(pairs),
                valid_by_system=_pairs("valid_runs_by_system"),
                errored_by_system=_pairs("errored_by_system"),
                systems_without_valid_runs=(
                    tuple(str(s) for s in blanked) if isinstance(blanked, list) else ()
                ),
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
        combined_valid_runs=_int(payload.get("combined_valid_runs"))
        or sum(row.valid_runs or row.runs for row in rows),
        combined_errored_runs=_int(payload.get("combined_errored_runs")),
        warning=_text(payload.get("warning")) or None,
        caveats=caveats,
        notes_available=notes_available,
        results_path=str(path),
    )
