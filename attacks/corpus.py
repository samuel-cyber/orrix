"""Loads and validates the attack corpus.

The corpus is data, not configuration: it is read from a path the caller
supplies, and nothing here reads the environment.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Mapping

import yaml

DEFAULT_CORPUS_PATH = Path(__file__).parent / "corpus.yaml"

CLAIM_TYPES = frozenset({"NOT_RECEIVED", "NOT_AS_DESCRIBED", "UNAUTHORIZED", "OTHER"})

#: Categories whose messages are honest. Used to measure over-refusal rather
#: than resistance: flagging these is a failure of a different kind.
HONEST_CATEGORIES = frozenset(
    {"honest_vague", "honest_detailed", "benign_mention", "false_claim"}
)

REQUIRED_FIELDS = (
    "id",
    "category",
    "text",
    "expected_claim_type",
    "max_acceptable_amount",
    "notes",
)


class CorpusError(ValueError):
    """The corpus file is malformed. Fail loudly; never guess."""


@dataclass(frozen=True)
class Attack:
    id: str
    category: str
    text: str
    expected_claim_type: str
    max_acceptable_amount: Decimal
    notes: str

    @property
    def is_honest(self) -> bool:
        return self.category in HONEST_CATEGORIES

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "expected_claim_type": self.expected_claim_type,
            "max_acceptable_amount": str(self.max_acceptable_amount),
            "is_honest": self.is_honest,
        }


def _require_text(item: Mapping[str, Any], field: str, attack_id: str) -> str:
    value = item.get(field)
    if not isinstance(value, str) or not value.strip():
        raise CorpusError(f"{attack_id}: {field} must be a non-empty string")
    return value


def parse_attack(item: Any) -> Attack:
    if not isinstance(item, Mapping):
        raise CorpusError("each corpus entry must be a mapping")

    missing = [field for field in REQUIRED_FIELDS if field not in item]
    if missing:
        raise CorpusError(f"corpus entry missing fields: {', '.join(missing)}")

    attack_id = _require_text(item, "id", "<unknown>")
    category = _require_text(item, "category", attack_id)
    # Text is kept exactly as written: trimming an attack changes the attack.
    text = item["text"]
    if not isinstance(text, str) or not text.strip():
        raise CorpusError(f"{attack_id}: text must be a non-empty string")

    expected = _require_text(item, "expected_claim_type", attack_id)
    if expected not in CLAIM_TYPES:
        raise CorpusError(
            f"{attack_id}: expected_claim_type {expected!r} is not one of {sorted(CLAIM_TYPES)}"
        )

    raw_amount = item["max_acceptable_amount"]
    try:
        amount = Decimal(str(raw_amount))
    except InvalidOperation as error:
        raise CorpusError(f"{attack_id}: max_acceptable_amount is not a number") from error
    if amount < 0:
        raise CorpusError(f"{attack_id}: max_acceptable_amount cannot be negative")

    return Attack(
        id=attack_id,
        category=category,
        text=text,
        expected_claim_type=expected,
        max_acceptable_amount=amount,
        notes=_require_text(item, "notes", attack_id),
    )


def load_corpus(path: str | Path = DEFAULT_CORPUS_PATH) -> tuple[Attack, ...]:
    """Read and validate the corpus. Raises CorpusError on anything wrong."""
    path = Path(path)
    if not path.is_file():
        raise CorpusError(f"no corpus at {path}")

    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise CorpusError(f"{path} is not valid YAML") from error

    if not isinstance(payload, Mapping) or "attacks" not in payload:
        raise CorpusError(f"{path} must be a mapping with an 'attacks' key")

    raw = payload["attacks"]
    if not isinstance(raw, list) or not raw:
        raise CorpusError(f"{path}: 'attacks' must be a non-empty list")

    attacks = tuple(parse_attack(item) for item in raw)

    seen: set[str] = set()
    for attack in attacks:
        if attack.id in seen:
            raise CorpusError(f"duplicate attack id {attack.id!r}")
        seen.add(attack.id)

    return attacks


def categories(attacks: tuple[Attack, ...]) -> tuple[str, ...]:
    return tuple(sorted({attack.category for attack in attacks}))


def by_id(attacks: tuple[Attack, ...]) -> dict[str, Attack]:
    return {attack.id: attack for attack in attacks}
