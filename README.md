# Orrix

Sandbox-only agent for responding to PayPal disputes, built so that the thing
reading untrusted text is never the thing that can act on it.

**Sandbox only.** Orrix uses `api-m.sandbox.paypal.com` and never touches real
money.

## The idea

A buyer's message is untrusted input. Orrix lets a model read it, but gives
that model no way to do anything:

- The **Reader** sees the buyer's text and the dispute amount. No tools, no
  function calling, no other context. Its only possible output is a
  `ClaimForm` with four fields, and the one free-text field is excluded from
  every decision.
- **Facts** are built from the PayPal record through an allowlist of named
  paths. Messages, evidence notes, names, emails and item descriptions are
  never read. A value that fails its pattern becomes `unavailable`, never a
  guess.
- **Policy** is plain code. The only action it can ever permit is
  `provide_evidence`. There is no refund, accept-claim or make-offer path in
  this version, and raising `refund_cap_usd` grants nothing.
- An **Approval** is the only thing that authorises a write. Its id is a hash
  of the dispute, the action, the payload and the dispute version, so it
  cannot be retargeted, edited or replayed.
- The **Executor** is the only module that can write. It re-fetches, checks
  the version still matches, re-runs policy against the fresh record,
  requires the approved payload to equal what Facts produce now, claims the
  approval id before writing, then re-fetches to confirm the evidence landed.

The evidence payload is built from Facts through a fixed template. No model
output and no buyer text has a path into it.

## Layout

| Path | Job |
| --- | --- |
| `orrix/claim_form.py` | The only schema buyer text can fill |
| `orrix/reader.py` | Model call with no tools; outputs a claim form |
| `orrix/facts.py` | Trusted facts from PayPal records; free text dropped |
| `orrix/seller_input.py` | The only schema seller shipment data can fill |
| `orrix/discrepancy.py` | Compares the claim with the delivery assertion |
| `orrix/policy.py` | Caps, clock and autonomy rules in plain code |
| `orrix/approval.py` | Explicit seller approval, bound to a dispute version |
| `orrix/executor.py` | The only module allowed PayPal write calls |
| `orrix/paypal_write.py` | Write capability, imported by the executor alone |
| `orrix/audit.py` | Hash-chained log with origin tags |
| `orrix/pipeline.py` | Plain orchestration, record in and case view out |
| `orrix/web/` | Server-rendered console |
| `attacks/` | The evaluation harness and its corpus |
| `baselines/` | Single-LLM agents to compare against |

The boundary is not just documented: `tests/test_boundaries.py` parses the
source and fails if `reader.py` imports `paypal.py`, if anything but
`executor.py` imports write capability, if buyer-text keys appear outside the
reader, or if a web asset assigns data to `innerHTML`.

## Running it

```sh
cp .env.example .env     # fill in sandbox credentials and ADMIN_PASSWORD
pip install -e ".[dev]"
pytest
uvicorn orrix.main:app --port 8010
```

Then open <http://127.0.0.1:8010>, sign in, and work a case: `/cases` is the
queue, `/cases/<id>` is the case file with its origin badges, `/audit` is the
hash chain, `/evaluation` is the harness output.

Requires Python 3.12+.

## Evaluation

```sh
# Recompute every number from recorded runs. No network, no credentials.
python -m attacks.run --replay

# Record a new label against a model.
python -m attacks.run --live --n 3 --yes --label <label> \
    --env-file .env.meta --max-calls 400
```

`attacks/corpus.yaml` holds the hostile and honest buyer messages; three
systems are measured against them (Orrix, a naive single-LLM agent, and a
prompt-defended single-LLM agent). Results land in `docs/RESULTS.md` and
`results/summary.json`.

Read `docs/RESULTS.md` with its caveats: the attacks are author-written, N is
small, results are per model, and Orrix's guarantee does not depend on the
Reader behaving well.

## Documents

- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — what is defended, and what is
  not. States plainly that the audit log is tamper-evident rather than
  tamper-proof, and what the HMAC key does and does not buy.
- [docs/RESULTS.md](docs/RESULTS.md) — evaluation results and their limits.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## License

MIT. See [LICENSE](LICENSE).
