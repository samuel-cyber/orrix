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
                                          payload, dispute_version)
                                                   │
                                                   v
                                      executor.execute
                                        1. re-fetch
                                        2. version still matches?
                                        3. fresh policy still permits?
                                        4. payload == Facts' payload?
                                        5. claim approval id
                                        6. write via paypal_write
                                        7. re-fetch, confirm it landed
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
| `discrepancy.py` | one fixed sentence when the claim and the delivery assertion conflict |
| `policy.py` | caps, clock, autonomy rules; plain code |
| `approval.py` | immutable approval bound to a dispute version |
| `executor.py` | the only writer; the only importer of `paypal_write` |
| `audit.py` | hash chain, optionally keyed with HMAC |
| `pipeline.py` | orchestration; persists a case view |
| `evaluation.py` | reads the harness output for the console |
| `web/` | server-rendered console: queue, case file, audit, evaluation |

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
| first-party, unverified | seller shipment form | Facts as `seller_asserted` |
| trusted record | PayPal `get_dispute` response | Facts as `confirmed` |
| derived | facts, discrepancy, policy decision | the console, the approval |
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
- a web template carries an inline script or style, or a web asset assigns
  data to `innerHTML` or calls `eval`.
