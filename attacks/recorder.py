"""Reads and writes recorded runs under attacks/recorded/<label>/<system>/.

One JSONL file per (label, system, attack), one line per run. Replay needs
only these files: no model, no credentials, no network.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping

from attacks.status import classify, is_ok, needs_reclassification

logger = logging.getLogger("attacks.recorder")

DEFAULT_RECORDED_DIR = Path(__file__).parent / "recorded"


def _with_classification(record: dict[str, Any]) -> dict[str, Any]:
    status, reason = classify(record)
    updated = dict(record)
    updated["status"] = status
    updated["error_reason"] = reason
    updated["reclassified"] = True
    return updated


@dataclass(frozen=True)
class Recorder:
    """Paths are passed in; nothing here reads the environment."""

    root: Path = DEFAULT_RECORDED_DIR

    def label_dir(self, label: str) -> Path:
        return self.root / label

    def path_for(self, label: str, system: str, attack_id: str) -> Path:
        return self.label_dir(label) / system / f"{attack_id}.jsonl"

    # -- writing ---------------------------------------------------------

    def append(self, record: Mapping[str, Any]) -> Path:
        path = self.path_for(
            str(record["label"]), str(record["system"]), str(record["attack_id"])
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        # newline="\n" so a record written on Windows is byte-identical to
        # one written on Linux. Without it, text mode turns every \n into
        # \r\n and the same run produces different bytes per platform.
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
        return path

    # -- reading ---------------------------------------------------------

    def runs_recorded(self, label: str, system: str, attack_id: str) -> int:
        """How many runs already exist, errored ones included."""
        return len(self.read_file(self.path_for(label, system, attack_id)))

    def ok_run_indices(self, label: str, system: str, attack_id: str) -> set[int]:
        """Run indices that produced a usable result.

        Resume skips only these. An errored run is not a result, so leaving
        it in place would permanently bake an endpoint outage into the
        numbers.
        """
        return {
            int(record.get("run_index", 0) or 0)
            for record in self.read_file(self.path_for(label, system, attack_id))
            if is_ok(record)
        }

    def errored_run_indices(self, label: str, system: str, attack_id: str) -> set[int]:
        return {
            int(record.get("run_index", 0) or 0)
            for record in self.read_file(self.path_for(label, system, attack_id))
            if not is_ok(record)
        }

    def raw_records_for_label(self, label: str) -> list[dict[str, Any]]:
        """Records exactly as stored, with no status stamped on."""
        directory = self.label_dir(label)
        if not directory.is_dir():
            return []
        records: list[dict[str, Any]] = []
        for path in sorted(directory.rglob("*.jsonl")):
            records.extend(self.read_file(path))
        return records

    def reclassified_count(self, label: str) -> int:
        """Records written before `status` existed, classified by evidence.

        Counted from the stored bytes, not from the classified view, so the
        number reported to the operator is the number actually inferred.
        """
        return sum(
            1 for record in self.raw_records_for_label(label) if needs_reclassification(record)
        )

    def purge_errored(self, label: str) -> tuple[int, int]:
        """Delete errored records for a label.

        Returns (removed, kept). Files left with no records are deleted so a
        later run does not see an empty file and think work was done.
        """
        directory = self.label_dir(label)
        if not directory.is_dir():
            return 0, 0

        removed = 0
        kept = 0
        for path in sorted(directory.rglob("*.jsonl")):
            records = self.read_file(path)
            survivors = [record for record in records if is_ok(record)]
            removed += len(records) - len(survivors)
            kept += len(survivors)

            if not survivors:
                path.unlink()
                continue
            # LF here too, so a purge does not rewrite surviving records
            # with different line endings than the ones around them.
            with path.open("w", encoding="utf-8", newline="\n") as handle:
                for record in survivors:
                    handle.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")

        return removed, kept

    def read_file(self, path: Path) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return records
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
            except ValueError:
                logger.warning("skipping malformed line %s in %s", line_number, path.name)
                continue
            if isinstance(parsed, dict):
                records.append(parsed)
        return records

    def labels(self) -> list[str]:
        if not self.root.is_dir():
            return []
        return sorted(
            child.name
            for child in self.root.iterdir()
            if child.is_dir() and not child.name.startswith(".")
        )

    def records_for_label(self, label: str) -> list[dict[str, Any]]:
        """Every record for a label, in a stable order so replay is deterministic."""
        directory = self.label_dir(label)
        if not directory.is_dir():
            return []

        records: list[dict[str, Any]] = []
        for path in sorted(directory.rglob("*.jsonl")):
            records.extend(self.read_file(path))

        records.sort(
            key=lambda record: (
                str(record.get("system", "")),
                str(record.get("attack_id", "")),
                int(record.get("run_index", 0) or 0),
            )
        )

        # Legacy records carry no status; classify them from the evidence
        # they do carry so every consumer sees one shape.
        return [
            record if not needs_reclassification(record) else _with_classification(record)
            for record in records
        ]

    def all_records(self) -> dict[str, list[dict[str, Any]]]:
        return {label: self.records_for_label(label) for label in self.labels()}

    def iter_all(self) -> Iterator[dict[str, Any]]:
        for records in self.all_records().values():
            yield from records
