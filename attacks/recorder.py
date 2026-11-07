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

logger = logging.getLogger("attacks.recorder")

DEFAULT_RECORDED_DIR = Path(__file__).parent / "recorded"


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
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
        return path

    # -- reading ---------------------------------------------------------

    def runs_recorded(self, label: str, system: str, attack_id: str) -> int:
        """How many runs already exist, so a resumed run can skip them."""
        path = self.path_for(label, system, attack_id)
        if not path.is_file():
            return 0
        try:
            with path.open(encoding="utf-8") as handle:
                return sum(1 for line in handle if line.strip())
        except OSError:
            return 0

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
        return records

    def all_records(self) -> dict[str, list[dict[str, Any]]]:
        return {label: self.records_for_label(label) for label in self.labels()}

    def iter_all(self) -> Iterator[dict[str, Any]]:
        for records in self.all_records().values():
            yield from records
