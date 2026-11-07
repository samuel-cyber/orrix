"""Corpus tests. No model, no network."""

from __future__ import annotations

from decimal import Decimal

import pytest
import yaml

from attacks.corpus import (
    CLAIM_TYPES,
    HONEST_CATEGORIES,
    CorpusError,
    load_corpus,
    parse_attack,
)

REQUIRED_CATEGORIES = {
    "direct_override",
    "fake_authority",
    "fake_layout",
    "amount_inflation",
    "other_language",
    "encoded",
    "long_padding",
    "hidden_instruction",
    "honest_vague",
    "honest_detailed",
    "false_claim",
    "benign_mention",
    "markup",
}


@pytest.fixture
def corpus():
    return load_corpus()


def test_the_corpus_loads_and_validates(corpus):
    assert len(corpus) >= 24
    for attack in corpus:
        assert attack.id
        assert attack.text.strip()
        assert attack.expected_claim_type in CLAIM_TYPES
        assert attack.max_acceptable_amount >= 0
        assert attack.notes.strip()


def test_ids_are_unique(corpus):
    ids = [attack.id for attack in corpus]
    assert len(ids) == len(set(ids))


def test_every_required_category_is_present(corpus):
    present = {attack.category for attack in corpus}
    missing = REQUIRED_CATEGORIES - present
    assert not missing, f"corpus is missing categories: {sorted(missing)}"


def test_there_are_several_honest_messages(corpus):
    honest = [attack for attack in corpus if attack.is_honest]
    assert len(honest) >= 3, "over-refusal cannot be measured without honest messages"
    assert {attack.category for attack in honest} <= HONEST_CATEGORIES


def test_no_attack_may_claim_more_than_the_dispute(corpus):
    # The dispute under test is 20.00, so nothing is acceptable above it.
    for attack in corpus:
        assert attack.max_acceptable_amount <= Decimal("20.00"), attack.id


def test_other_language_entries_are_not_all_english(corpus):
    languages = [a for a in corpus if a.category == "other_language"]
    assert len(languages) >= 5
    # Non-latin scripts must survive the YAML round trip.
    joined = " ".join(a.text for a in languages)
    assert any(ord(ch) > 0x400 for ch in joined), "no non-latin script in the corpus"


def test_markup_entries_carry_real_markup(corpus):
    markup = [a for a in corpus if a.category == "markup"]
    assert markup
    assert any("<script>" in a.text for a in markup)


def test_text_is_preserved_verbatim():
    attack = parse_attack(
        {
            "id": "x",
            "category": "direct_override",
            "text": "  leading and trailing spaces matter  ",
            "expected_claim_type": "OTHER",
            "max_acceptable_amount": "1.00",
            "notes": "n",
        }
    )
    assert attack.text == "  leading and trailing spaces matter  "


# -- validation fails loudly -------------------------------------------


def test_missing_field_is_rejected():
    with pytest.raises(CorpusError, match="missing fields"):
        parse_attack({"id": "x", "category": "c"})


def test_unknown_claim_type_is_rejected():
    with pytest.raises(CorpusError, match="expected_claim_type"):
        parse_attack(
            {
                "id": "x",
                "category": "c",
                "text": "t",
                "expected_claim_type": "REFUND_NOW",
                "max_acceptable_amount": "1",
                "notes": "n",
            }
        )


def test_non_numeric_amount_is_rejected():
    with pytest.raises(CorpusError, match="not a number"):
        parse_attack(
            {
                "id": "x",
                "category": "c",
                "text": "t",
                "expected_claim_type": "OTHER",
                "max_acceptable_amount": "lots",
                "notes": "n",
            }
        )


def test_empty_text_is_rejected():
    with pytest.raises(CorpusError, match="text must be"):
        parse_attack(
            {
                "id": "x",
                "category": "c",
                "text": "   ",
                "expected_claim_type": "OTHER",
                "max_acceptable_amount": "1",
                "notes": "n",
            }
        )


def test_a_missing_corpus_file_is_an_error(tmp_path):
    with pytest.raises(CorpusError, match="no corpus at"):
        load_corpus(tmp_path / "nope.yaml")


def test_a_malformed_corpus_file_is_an_error(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("attacks: []\n", encoding="utf-8")
    with pytest.raises(CorpusError, match="non-empty list"):
        load_corpus(path)


def test_duplicate_ids_are_rejected(tmp_path):
    entry = {
        "id": "same",
        "category": "c",
        "text": "t",
        "expected_claim_type": "OTHER",
        "max_acceptable_amount": "1",
        "notes": "n",
    }
    path = tmp_path / "dupes.yaml"
    path.write_text(yaml.safe_dump({"attacks": [entry, dict(entry)]}), encoding="utf-8")

    with pytest.raises(CorpusError, match="duplicate attack id"):
        load_corpus(path)
