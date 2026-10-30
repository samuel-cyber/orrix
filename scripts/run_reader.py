"""Run the real Reader once against a fixture. Sandbox-safe: no PayPal call.

    python scripts/run_reader.py [fixture-filename]

Reads .env for the model credentials, builds a ReaderConfig, extracts the
buyer text from the fixture, and makes one chat-completions request. Prints
the resulting ClaimForm or the needs_review reason. Makes no PayPal call of
any kind and writes nothing.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from decimal import Decimal
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent.parent))

from orrix.reader import ReaderConfig, extract_buyer_text, read_claim  # noqa: E402

DEFAULT_FIXTURE = "dispute_PP-R-PXL-10195222.json"
FIXTURES_DIR = Path(__file__).parent.parent / "tests" / "fixtures"


def build_config() -> ReaderConfig:
    """The caller owns credential handling; the reader never reads env."""
    api_key = os.environ.get("READER_API_KEY")
    if not api_key:
        raise SystemExit(
            "READER_API_KEY is not set. Add it to .env along with READER_BASE_URL "
            "and READER_MODEL."
        )
    return ReaderConfig(
        base_url=os.environ.get("READER_BASE_URL", "https://api.openai.com/v1"),
        api_key=api_key,
        model=os.environ.get("READER_MODEL", "gpt-4o-mini"),
        timeout=float(os.environ.get("READER_TIMEOUT", "30")),
        max_retries=int(os.environ.get("READER_MAX_RETRIES", "2")),
    )


def main() -> int:
    load_dotenv()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

    fixture_name = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FIXTURE
    fixture_path = FIXTURES_DIR / fixture_name
    if not fixture_path.is_file():
        available = ", ".join(p.name for p in sorted(FIXTURES_DIR.glob("*.json")))
        raise SystemExit(f"No fixture at {fixture_path}. Available: {available}")

    snapshot = json.loads(fixture_path.read_text(encoding="utf-8"))
    buyer_text = extract_buyer_text(snapshot)
    ceiling = Decimal(str(snapshot.get("dispute_amount", {}).get("value", "0")))

    print(f"fixture:      {fixture_name}")
    print(f"dispute:      {snapshot.get('dispute_id')}")
    print(f"ceiling:      {ceiling} {snapshot.get('dispute_amount', {}).get('currency_code')}")
    print(f"buyer text:   {len(buyer_text)} chars")
    print("-" * 60)
    print(buyer_text or "(none)")
    print("-" * 60)

    if not buyer_text:
        print("No buyer text in this fixture; the reader would return needs_review.")
        return 0

    config = build_config()
    result = read_claim(buyer_text, ceiling, config)

    print(f"status:       {result.status}")
    print(f"attempts:     {result.attempts}")
    print(f"http status:  {result.http_status}")

    if result.ok:
        form = result.form
        print("claim form:")
        print(f"  claim_type:         {form.claim_type.value}")
        print(f"  claimed_amount:     {form.claimed_amount}")
        print(f"  amount_was_clamped: {form.amount_was_clamped}")
        print(f"  language:           {form.language}")
        print(f"  seller_summary:     {form.seller_summary}")
        print()
        print(f"decision inputs:      {form.decision_inputs()}")
        print("(seller_summary is display-only and absent from decision inputs)")
    else:
        print(f"needs_review reason:  {result.reason}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
