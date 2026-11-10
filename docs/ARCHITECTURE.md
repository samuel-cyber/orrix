# Architecture

Orrix has one structural idea: **the component that reads untrusted text is
not the component that can act.** Everything below follows from keeping those
two things apart and making the separation checkable.

Sandbox only. Orrix never touches real money.

## The flow

```
  webhook ──┐
            ├──> get_dispute (re-fetch)  ──> store.cases
  poller ───┘          │
                       v
              build_facts(record, seller_input)
                       │
                       v
        apply_matched(order_ledger, facts)   fills only an unavailable fact;
                       │                    never adds, never overwrites
                       │
   ┌───────────────────┼───────────────────────────┐
   │                   │                           │
   v                   v                           v
extract_buyer_text   detect_discrepancy      policy.decide
   │                   │                           │
   v                   │                           │
read_claim ────────────┘                           │
(model, no tools)                                  │
   │                                               │
   └──> ClaimForm ─────> display only ─────────────┘
                                                   │
                                    seller approves in the console
                                                   │
                                                   v
                                      create_approval(dispute, action,
                                          payload, dispute_version,
                                          ledger_row_id, row version)
                                                   │
                                                   v
                                      executor.execute
                                        1. re-fetch
                                        2. version still matches?
                                        3. ledger row still at id+version?
                                        4. carrier reading unchanged?
                                        5. fresh policy still permits?
                                        6. payload == Facts' payload?
                                        7. claim approval id
                                        8. write via paypal_write
                                        9. re-fetch, confirm it landed
```

Every step appends to the hash-chained audit log with an origin tag
(`paypal_record`, `buyer_text`, `reader_output`, `system`,
`seller_approval`). Buyer text is logged as a hash and a length, never as
text.

## Modules

| Module | Responsibility |
| --- | --- |
| `config.py` | the only module that reads the environment |
| `paypal.py` | sandbox read client: token, `get_dispute`, `list_disputes`, webhook signature verification |
| `paypal_write.py` | write capability: `provide_evidence` only |
| `webhooks.py` | verify, dedupe, re-fetch; reads only `resource.dispute_id` |
| `poller.py` | the fallback path; always ends in a fresh `get_dispute` |
| `store.py` | events and dispute snapshots |
| `facts.py` | allowlisted facts with provenance and status |
| `reader.py` | `extract_buyer_text` and one model call with no tools |
| `claim_form.py` | the only schema buyer text may fill |
| `seller_input.py` | the only schema seller shipment data may fill |
| `orders.py` | the seller's order ledger: validated rows, idempotent upsert, match to a dispute, facts overlay |
| `demo_seed.py` | seeds a few ledger rows through the validated ingest |
| `discrepancy.py` | one fixed sentence when the claim and the delivery evidence conflict |
| `carrier.py` | optional carrier lookups, reduced to five status enums; off by default |
| `evidence_pack.py` | the one-page evidence PDF, built from Facts through a fixed layout |
| `policy.py` | caps, clock, autonomy rules; plain code |
| `approval.py` | immutable approval bound to a dispute version and, when a ledger row was used, to that row's id and version |
| `executor.py` | the only writer; the only importer of `paypal_write` |
| `audit.py` | hash chain, optionally keyed with HMAC |
| `pipeline.py` | orchestration; persists a case view |
| `evaluation.py` | reads the harness output for the console |
| `web/` | server-rendered console: queue, case file, orders, audit, evaluation |

`attacks/` holds the evaluation harness and corpus; `baselines/` holds two
single-LLM agents to compare against.

## Trust direction

Data flows one way: records and seller input become Facts, Facts become a
decision, a decision plus a human become an approval, and only an approval
reaches the writer. Nothing flows back — model output never becomes a fact,
and no untrusted string reaches a payload.

| Zone | Contents | May reach |
| --- | --- | --- |
| untrusted | buyer messages, buyer evidence notes, model output | `ClaimForm` only |
| untrusted, third party | carrier API responses | Facts as `carrier_reported`, via five enums and two validated timestamps; every free-text field dropped |
| first-party, unverified | seller shipment form; seller order ledger rows | Facts as `seller_asserted` (`seller_ledger` origin for ledger rows) |
| trusted record | PayPal `get_dispute` response | Facts as `confirmed` |
| derived | facts, discrepancy, policy decision, evidence checklist | the console, the approval |
| authority | an `Approval` | the executor |

"Trusted" means trusted to be *what PayPal recorded*, not trusted to be
true.

## Storage

One SQLite file, path from the config object:

| Table | Contents |
| --- | --- |
| `events` | webhook event ids, for duplicate detection |
| `cases` | the last fetched snapshot per dispute |
| `case_views` | pipeline output for the console |
| `orders` | the seller's ledger rows: validated fields, server-set `recorded_at`, monotonic `version` |
| `executed_approvals` | approval ids already acted on (idempotency) |
| `audit_log`, `audit_head` | the hash chain and its tip anchor |

## Enforcement

The separation is checked, not just described.
`tests/test_boundaries.py` reads the source with `ast` and fails if:

- `reader.py` or `claim_form.py` imports `paypal`, `executor`, `store`,
  `poller` or `webhooks`;
- anything but `executor.py` imports `paypal_write`;
- `facts.py` imports the reader, or the reader imports facts;
- buyer-text keys appear outside `reader.py`;
- `policy.py` imports a model client or the reader;
- the reader's request mentions tools or function calling;
- any module but `config.py` (and the pre-existing `store`, `poller`,
  `paypal`) reads the environment;
- `orders.py` or `demo_seed.py` imports `paypal`, `paypal_write`, `executor`
  or the reader, or reads a credential;
- a web template carries an inline script or style, or a web asset assigns
  data to `innerHTML` or calls `eval`;
- `carrier.py` imports `paypal`, `paypal_write`, `executor`, `store`, the
  reader or `approval`, or reads a credential;
- `CarrierResult` grows a field that could hold free text;
- `evidence_pack.py` names a prose-carrying field;
- any core module (`facts`, `policy`, `approval`, `executor`,
  `discrepancy`, `config`, `pipeline`, `reader`) imports `carrier` at module
  scope — which would break the guarantee that the connector can be deleted.

## The order ledger

`orders.py` is the seller's own shipment data, kept apart from the PayPal
record. A row is validated on the way in (fixed fields, no free text,
conservative patterns per field), stored with a server-set `recorded_at` and a
monotonic `version`, and upserted idempotently: the same row again changes
nothing, any changed field bumps the version. Rejected input is reported as
`field: reason` lines with the value left out, so a form or CSV cannot echo
text back into the page.

Matching is narrow. A row joins a dispute only by the PayPal-side
`seller_transaction_id` — never one the row supplies — and `apply_matched`
only fills a fact that was `unavailable`, stamped `seller_ledger` /
`seller_asserted`. It never adds a fact outside `FACT_NAMES`, never overwrites
a `confirmed` fact, and records `conflicting` when a seller assertion disagrees
with the record. `recorded_before_dispute` is computed in code from the
server-set `recorded_at` against the dispute's `create_time`; a caller cannot
supply it, and it fails closed.

`evidence_checklist(facts)` is a read-only view: the facts the payload needs,
each one's status and origin. An approval built from a ledger row folds that
row's **id and version** into the approval id, so a row edited after approval
no longer recomputes the id and the executor refuses the write
(`stale_ledger`).

Ingest paths: the session-guarded `/orders` form and CSV import, and the
public `POST /api/orders` machine route. The machine route is authenticated by
its own bearer token (`LEDGER_API_KEY`, constant-time, rate-limited per
minute); with no token set it is disabled. It never accepts `recorded_at`.

## The carrier connector

Optional, behind `CARRIER_ENABLED`, default off. It sits beside the ledger
rather than inside the trusted core, and the dependency runs one way only:
`carrier.py` imports `facts.py`, and nothing in the core imports
`carrier.py`. `config.py` builds a `CarrierConfig` through a function-scope
import for exactly this reason, so that deleting `orrix/carrier.py` leaves
facts, policy, approval and the executor building identically. That is
asserted by a subprocess test in which importing the module raises.

```
  case page opened ──> seller-supplied tracking? ──no──> nothing happens
            │                     │yes
            │                     v
            │        CarrierLookup: cache -> hourly cap -> retries (max 3)
            │                     │
            │                     v
            │            CarrierResult(status, delivered_at,
            │                          checked_at, source)
            │                     │
            │                     v
            └──> apply_carrier(facts, result)  adds carrier_status and
                                               carrier_delivered_at only;
                                               never touches a core fact
```

The two names it adds are held in `CARRIER_FACT_NAMES`, deliberately outside
`FACT_NAMES`, so `build_facts` never populates them and a case with no
lookup carries exactly the facts it carried before the connector existed.
Their status, `carrier_reported`, is absent from `USABLE_STATUSES`: the
payload builder, the policy rules and the executor cannot read it.

The connector never reaches the Reader, never changes the action set and
never changes the evidence payload — the fixed template has no field for a
carrier reading, so none was added. Its one effect on the decision path is
that `detect_discrepancy` also fires on a carrier-reported delivery, with
the same fixed sentence and the same review flag.

An approval granted while a reading was on the page folds that reading's
status and check time into the approval id. The executor compares them
against two plain strings on `ExecutorDeps` — not a carrier object, so the
executor imports nothing from the connector — and refuses with
`stale_carrier` if either moved.

## The evidence pack

`evidence_pack.py` renders a one-page PDF from Facts alone. It imports
neither the reader, the claim form, the order ledger nor the pipeline, and
names no prose-carrying field, so there is no path by which buyer text, a
Reader summary or a ledger item label could reach a document a seller may
forward to PayPal or a bank.

Output is deterministic: PDF metadata dates come from the facts, and the web
layer stamps those facts from the dispute record's own `update_time`, so the
hash shown on the page is always the hash inside the file. The printed digest
is a SHA-256 over the pack's canonical content, not over the PDF bytes, so it
can be recomputed without a PDF library. The content stream is uncompressed
so the "no untrusted text" property is checkable with `grep`.

Nothing about the pack touches the executor or any PayPal request. Attaching
it to the dispute is not implemented.
