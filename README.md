# Orrix

Orrix responds to PayPal disputes on a seller's behalf, built so that the
component reading untrusted buyer text is structurally unable to act on it.
A model reads the buyer's message and can only fill in a four-field form;
every decision and every write is plain code behind an explicit human
approval.

**Sandbox only.** Orrix uses `api-m.sandbox.paypal.com` and never touches
real money. Do not point it at live credentials.

## How it works

```
  PayPal webhook ──┐
                   ├──> re-fetch the dispute from PayPal  (never trust the payload)
  poller (60s) ────┘                │
                                    v
                         ┌──────────────────────┐
                         │ Facts (allowlist)    │  messages, notes, names,
                         │ from the record      │  emails, item text: dropped
                         └──────────┬───────────┘
                                    │
          buyer text ──> Reader ────┤   no tools, no function calling,
          (untrusted)   (a model)   │   output is a ClaimForm or nothing
                                    │
                                    v
                         ┌──────────────────────┐
                         │ Policy (plain code)  │  may permit at most
                         │ caps · clock · rules │  provide_evidence
                         └──────────┬───────────┘
                                    │
                         seller presses Approve
                                    │
                                    v
                         ┌──────────────────────┐
                         │ Approval             │  id = hash(dispute,
                         │ (immutable)          │  action, payload, version)
                         └──────────┬───────────┘
                                    │
                                    v
                         ┌──────────────────────┐
                         │ Executor             │  the only module that
                         │ re-check then write  │  can write to PayPal
                         └──────────┬───────────┘
                                    │
                        re-fetch to confirm it landed
```

The executor re-checks everything before it writes: the record still has the
approved `update_time` and `status`, fresh policy still permits the action,
and the approved payload still equals what Facts produce now. It claims the
approval id before writing, so a replay cannot write twice, and it re-fetches
afterwards because a 2xx alone is not proof.

### Which module may import what

| Module | Job | May not import |
| --- | --- | --- |
| `claim_form.py` | the only schema buyer text may fill | paypal, executor, store, poller, webhooks |
| `reader.py` | one model call, no tools | the same, plus `facts` |
| `seller_input.py` | the only schema seller shipment data may fill | the same, plus reader |
| `facts.py` | trusted facts from the record | reader, paypal_write, executor |
| `discrepancy.py` | compares claim with delivery assertion | the same, plus reader |
| `policy.py` | caps, clock, autonomy rules | reader, paypal_write, executor, any model client |
| `approval.py` | explicit seller approval | paypal_write |
| `audit.py` | hash-chained log | paypal_write |
| `pipeline.py` | orchestration only | paypal_write, executor |
| `executor.py` | **the only writer** | — |
| `paypal_write.py` | write capability | imported by `executor.py` alone |
| `web/` | the console | paypal_write |

These are not conventions. `tests/test_boundaries.py` parses the source with
`ast` and fails the build if any of them is violated, including imports
hidden inside a function.

## What is claimed, narrowly

**A fully hijacked Reader can only produce a validated `ClaimForm`.** Even if
the model obeys an injected instruction completely, it cannot:

- select an action — `policy.py` decides, from Facts, in plain code;
- create an approval — `create_approval` is unreachable from the reader path,
  enforced statically;
- put text into a PayPal payload — the payload is built from Facts through a
  fixed template, and the executor refuses an approval whose payload does not
  equal what Facts produce at execution time.

A Reader that obeys an injection shows up in the evaluation as a *soft
failure* (a wrong claim type, an inflated amount, an obedient summary), not
as an unauthorized action.

### What is *not* claimed

- **It does not protect against a compromised process.** Anything that can
  run code in the app can call the executor directly.
- **It does not protect against a stolen credential.** PayPal cannot tell
  Orrix's token from anyone else's.
- **It does not protect against a wrong approval.** If the seller approves
  something they should not have, Orrix carries it out. The boundary makes
  the approval *informed and specific*; it cannot make it correct.
- **The audit log is tamper-evident, not tamper-proof.** Without
  `AUDIT_HMAC_KEY`, anyone who can write to the database can forge a
  consistent history — there is a test that asserts this is detected only in
  keyed mode. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- **No claim about model quality.** The evaluation measures a handful of
  author-written attacks at small N against one model at a time.

## Running locally

```sh
cp .env.example .env     # fill in sandbox credentials and ADMIN_PASSWORD
pip install -e ".[dev]"
uvicorn orrix.main:app --port 8010
```

Open <http://127.0.0.1:8010> and sign in. `/cases` is the queue,
`/cases/<id>` is the case file with an origin badge on every line, `/audit`
is the hash chain with a verify button, `/evaluation` is the harness output.

Requires Python 3.12+.

### Tests

```sh
pytest                   # the whole suite; no network, no model, no PayPal
pytest tests/test_boundaries.py    # the import rules on their own
```

Every test runs offline. A guard in `tests/conftest.py` fails any test that
opens the operational `orrix.db`, and a stub client fails any test that
would reach PayPal without a fake installed.

### Evaluation

Recompute every number from recorded runs. No credentials, no network:

```sh
python -m attacks.run --replay
```

Record a new label against your own model:

```sh
cp .env.example .env.meta        # set READER_BASE_URL, READER_API_KEY, READER_MODEL
python -m attacks.run --live --n 3 --yes --label <provider>-<model> \
    --env-file .env.meta --max-calls 400
```

`--live` prints the planned call count and refuses to spend anything without
`--yes`. It resumes where it stopped, retries records whose model call
errored, caps each request at 20 seconds, and aborts after five consecutive
failures rather than grinding on against a dead endpoint. Use `--plan-only`
to see the plan without calling anything.

Results land in [docs/RESULTS.md](docs/RESULTS.md) and
`results/summary.json`. Read them with the caveats printed alongside: the
attacks are author-written, N is small, and results are per model.

## Deploying on Render

`render.yaml` is a Render Blueprint. Push the repo, then in Render choose
**New > Blueprint** and point it at the repository.

Two things to know first:

- The persistent disk **requires a paid instance**. Without it, SQLite sits
  on ephemeral storage and every deploy wipes the audit chain and the
  executed-approval ledger — which would let an already-executed approval run
  again.
- **Free instances sleep.** A sleeping instance runs no poller and may not
  wake before an incoming webhook times out.

Set these in the Render dashboard; all are declared `sync: false` so nothing
secret is committed:

| Variable | Needed for |
| --- | --- |
| `ADMIN_PASSWORD` | console login; **12+ characters or the app refuses to start** |
| `SESSION_SECRET` | signing CSRF tokens; unset means everyone is logged out on restart |
| `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET` | sandbox API access |
| `PAYPAL_WEBHOOK_ID` | webhook signature verification |
| `READER_API_KEY`, `READER_BASE_URL`, `READER_MODEL` | the Reader; omit and it is skipped |
| `AUDIT_HMAC_KEY` | keying the audit chain |
| `AG_GRID_LICENSE_KEY` | optional; without it the grid shows a watermark |

Set inline in the blueprint: `ORRIX_DB=/var/data/orrix.db`,
`ORRIX_ENV=production`, `POLLER_ENABLED=true`,
`POLL_INTERVAL_SECONDS=60`.

With `ORRIX_ENV=production` the app marks cookies `Secure` and refuses to
start without a long enough `ADMIN_PASSWORD`.

## Webhook status, stated honestly

The webhook receiver at `POST /webhooks/paypal` is **built and unit-tested
against mocks**: signature verification, replay and duplicate handling,
out-of-order delivery, unknown event types, and the rule that only
`resource.dispute_id` is read from the payload.

**It has not been confirmed end to end with a real sandbox-signed dispute
event.** No PayPal-signed webhook has reached a running instance during
development, so the verification path is unproven against real
`PAYPAL-*` headers.

**The polling fallback is the verified path.** `list_disputes` plus
`get_dispute` has been exercised against the real sandbox and is what
actually populated the queue. The poller runs every 60 seconds by default
and makes the webhook an optimisation rather than a dependency.

## Known limitations

- **Seller tracking is asserted, not verified.** A seller can type any
  well-formed tracking number. Orrix marks it `seller_asserted`, never
  `confirmed`, and raises a review flag when it contradicts the buyer — but
  nothing checks the number with the carrier.
- **`delivered_date` may be ignored by PayPal.** It is included in the
  tracking entry because the evidence payload calls for a delivery date, but
  it is not a documented field on `provide-evidence`. PayPal may drop or
  reject it; confirm against a sandbox call before relying on it.
- **One seller per deployment.** Credentials, the admin password and the
  database are all single-tenant. There is no account model.
- **One action.** The only thing Orrix can do is submit proof of
  fulfilment. There is no refund, accept-claim or make-offer path, and
  `refund_cap_usd` defaults to 0 — raising it grants nothing.
- **A discrepancy does not block submission.** By design: the seller is
  entitled to put their evidence in front of PayPal. The review flag is the
  only consequence.
- **The login throttle is per-instance and in memory.** It raises the cost of
  guessing from one address; a restart clears it and it is not a defence
  against a distributed attempt.

## Documents

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — the modules and the data flow.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — assets, trust zones,
  invariants, what the tests prove, and the residual risks.
- [docs/RESULTS.md](docs/RESULTS.md) — evaluation results and their limits.

## Licence

MIT, see [LICENSE](LICENSE).

AG Grid Enterprise is loaded from a pinned CDN URL and is used under **its
own licence, not this one**. No licence key is committed: the optional
`AG_GRID_LICENSE_KEY` is read from the environment and injected at render
time. Without a key the grid still works and displays AG Grid's watermark.
Using AG Grid Enterprise in production requires a licence from AG Grid.
