# Orrix

Sandbox-only agent for responding to PayPal disputes.

Buyer text is untrusted: it may only fill a fixed claim form, never reach a tool
call. Decisions are made from facts pulled out of PayPal records, and a single
module is permitted to perform PayPal writes.

**Sandbox only.** Orrix never touches real money.

## Status

Skeleton. No implementation yet.

## Layout

| Path | Job |
| --- | --- |
| `orrix/claim_form.py` | The only schema buyer text can fill |
| `orrix/reader.py` | Model call with no tools; outputs a claim form |
| `orrix/facts.py` | Trusted facts from PayPal records; free text dropped |
| `orrix/investigator.py` | Model call that sees facts only |
| `orrix/policy.py` | Caps, clock, autonomy rules in plain code |
| `orrix/executor.py` | The only module allowed PayPal write calls |
| `orrix/audit.py` | Hash-chained log with origin tags |
| `orrix/paypal.py` | Sandbox PayPal client |
| `orrix/webhooks.py` | Receives and verifies PayPal events |

`attacks/`, `baselines/`, and `simulator/` hold evaluation harnesses.
`scripts/spike.py` is the throwaway API spike.

## Setup

```sh
cp .env.example .env   # fill in sandbox credentials
pip install -e ".[dev]"
pytest
```

Requires Python 3.12+.

## License

MIT. See [LICENSE](LICENSE).
