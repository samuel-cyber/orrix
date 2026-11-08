# Threat Model

Orrix responds to PayPal disputes. It reads text written by people with a
financial interest in the outcome, and it can change state at PayPal. This
document says what it defends against, and what it does not.

Sandbox only. Orrix never touches real money.

## Assets

What an attacker would want, in rough order of how much damage losing it does.

| Asset | Where it lives | Losing it means |
| --- | --- | --- |
| The ability to write to PayPal | `executor.py` via `paypal_write.py` | a dispute conceded or evidence forged in the seller's name |
| PayPal API credentials | `.env` / the platform's secret store | the same, without touching Orrix at all |
| The console session | `ADMIN_PASSWORD`, the session cookie | the approval button, so any permitted action |
| The approval chain | `executed_approvals`, the `Approval` id | a replayed or retargeted write |
| The audit log | `audit_log`, `audit_head` | a history that no longer reflects what happened |
| Dispute records | `cases`, `case_views` | buyer PII: names, emails, messages |
| The audit HMAC key | the environment | the ability to forge a log that verifies |
| The Reader API key | the environment | someone else's model bill |

## Trust zones

| Zone | Contents | Allowed to reach |
| --- | --- | --- |
| Untrusted | buyer messages, buyer evidence notes, model output | the `ClaimForm` schema, and nothing else |
| First-party, unverified | the seller's shipment form | Facts, as `seller_asserted` |
| Trusted record | the PayPal `get_dispute` response | Facts, as `confirmed` |
| Derived | Facts, discrepancy, policy decision | the console and an approval |
| Authority | an `Approval` | the executor, once |
| Platform | credentials, the HMAC key, the database | everything; this zone is the trust root |

## What each module may touch

| Module | Reads | Writes | May never |
| --- | --- | --- | --- |
| `reader.py` | buyer text, the amount ceiling | nothing | reach PayPal, the store, or an approval |
| `claim_form.py` | reader output | nothing | reach anything privileged |
| `seller_input.py` | a submitted form | nothing | reach PayPal or the reader |
| `facts.py` | the record, validated seller input | nothing | read buyer prose or model output |
| `policy.py` | Facts, a reader result, case state | nothing | consult a model; emit a money-moving action |
| `approval.py` | what a human approved | nothing | be reached from the reader path |
| `executor.py` | the fresh record, an approval | **PayPal**, the audit log, the approval ledger | write without an intact, fresh, payload-matching approval |
| `audit.py` | hashes and short codes | the audit tables | store raw buyer text or a credential |
| `web/` | stored snapshots, derived views | operator state, the audit log | import write capability |

## Trust levels

| Source | Trust | Where it may go |
| --- | --- | --- |
| PayPal dispute record | trusted as a record of what PayPal holds | Facts, `status: confirmed` |
| Seller shipment form | first-party, unverified | Facts, `status: seller_asserted` |
| Buyer message and evidence notes | untrusted | the `ClaimForm` schema, nothing else |
| Model output | untrusted | a validated `ClaimForm`, nothing else |

"Trusted" means *trusted to be what PayPal recorded*, not trusted to be true.
A buyer's claim is faithfully recorded and still may be wrong; so may a
seller's assertion. Orrix does not adjudicate.

## What is defended

**Prompt injection via buyer text.** `extract_buyer_text` is the only reader
of `messages[].content` and buyer evidence notes, enforced statically in
`tests/test_boundaries.py`. That text reaches one model call with no tools and
no function calling, and may only become a `ClaimForm`. The one free-text
field, `seller_summary`, is excluded from `decision_inputs()`.

**Untrusted data becoming a fact.** `build_facts` reads an allowlist of named
paths. A field PayPal adds tomorrow is absent until `FACT_NAMES` says
otherwise. Values must match a pattern for their kind, so prose in a carrier
field becomes `unavailable` rather than passing through.

**Untrusted data reaching PayPal.** The evidence payload is built from Facts
through a fixed template, interpolating only carrier, tracking number and an
asserted delivery date. The note is a format string with no caller-supplied
text.

**Acting without authority.** Only an `Approval` authorises a write.
`approval_id` is the hash of `(dispute_id, action, payload, dispute_version)`,
so an approval cannot be retargeted, edited or re-dated. The reader and
investigator cannot reach `create_approval`.

**Acting on stale state.** The executor re-fetches, requires `update_time` and
`status` to equal the approved version, re-runs policy against the fresh
record, and requires the approved payload to equal what Facts produce now.

**Acting twice.** The approval id is claimed in SQLite before the write and
sent as `PayPal-Request-Id`.

**Overreach.** `ALLOWED_ACTION_UNIVERSE` is `{"provide_evidence"}`. There is
no refund, accept-claim or make-offer code path; `refund_cap_usd` defaults to
0 and raising it grants nothing.

**Accusation.** The discrepancy detector emits one fixed sentence plus the two
facts and their sources. It never says a buyer is lying and never infers
intent.

## The audit log: tamper-evident, not tamper-proof

`audit_log` is a hash chain. Each entry digests its own fields plus the
previous entry's hash, so **altering, deleting or reordering** a row breaks
the chain, and `verify_chain()` returns the first bad `seq`. A separate
`audit_head` row anchors the expected tip and row count, which catches a row
appended straight into the table.

### Without `AUDIT_HMAC_KEY`

The digest is plain SHA-256, which requires no secret. **Anyone who can write
to the database can forge a consistent history**: recompute the entry hash,
update the head row, and `verify_chain()` returns `None`. This is not a
hypothetical — `test_plain_mode_cannot_detect_a_fully_consistent_forgery`
asserts that it succeeds. Plain mode protects against accidental corruption
and careless tampering, not against an attacker with write access.

### With `AUDIT_HMAC_KEY`

The digest becomes HMAC-SHA256 under the key. Forging now needs the key as
well as table access. `test_hmac_mode_detects_the_same_forgery` shows the
identical forgery failing.

### What the key does not protect

- **It is not tamper-proof.** An attacker who obtains the key can forge
  exactly as in plain mode. The key moves the bar from "database access" to
  "database access plus the key"; it does not remove the bar.
- **It does not help if the key sits beside the log.** A key in a `.env` on
  the same host, readable by the same process that can write the database,
  buys very little. It must live somewhere the database writer cannot read —
  a secret manager, a separate host, an HSM.
- **It does not prove completeness against wholesale replacement.** Someone
  with the key can rewrite the chain from genesis. Detecting that needs an
  external anchor: the head hash shipped off-box, published somewhere
  append-only, or counter-signed by another party.
- **It does not protect entries not yet written.** The log records what Orrix
  did; it cannot record what Orrix was prevented from doing.
- **Rotation is not implemented.** Changing the key invalidates every existing
  entry — `test_the_wrong_key_invalidates_an_existing_chain` pins that.
  Rotation would need a key id per entry.

### Honest summary

The log tells you *whether* the history was altered, provided the verifier
holds a key the tamperer does not. It does not prevent alteration, and
without a key held out of reach it does not reliably detect a deliberate one.

## The invariants

These are the properties the design exists to hold. Each is enforced in
code and checked by a test, not left to review.

1. **Untrusted text may only become a `ClaimForm`.** One model call, no
   tools, no function calling, four fields, `extra="forbid"`.
2. **The Reader can only ever block, never enable.** A reader result can
   empty `allowed_actions`; it can never add to it.
3. **Only the record can confirm a fact.** Seller input is
   `seller_asserted`; disagreement between sources is `conflicting` and
   carries no value.
4. **Missing data is `unavailable`, never a negative fact.** An absent
   field never becomes `False` or `""`.
5. **The action universe is `{provide_evidence}`.** No refund, accept-claim
   or make-offer path exists in this version.
6. **Only an `Approval` authorises a write**, and its id is a hash of the
   dispute, the action, the payload and the dispute version.
7. **The payload comes from Facts through a fixed template.** The executor
   refuses an approval whose payload differs from what Facts produce now.
8. **One approval, one write.** The approval id is claimed before the call
   and sent as `PayPal-Request-Id`.
9. **A 2xx is not a success.** The executor re-fetches and requires the
   evidence count to have grown.
10. **Only `executor.py` holds write capability.** Exactly one module
    imports `paypal_write`.

## What the tests prove

| Property | Test |
| --- | --- |
| The import boundary holds, including inside functions | `tests/test_boundaries.py` (ast) |
| No module but the executor can write | `test_only_the_executor_imports_write_capability` |
| Buyer text is read in exactly one place | `test_buyer_text_is_read_in_exactly_one_module` |
| Hostile text never reaches a payload, over the whole corpus | `tests/test_replay.py` |
| No reader output can produce a write without an approval | `test_no_reader_output_can_produce_a_write_without_approval` |
| A stale, tampered or retargeted approval is refused | `tests/test_invariants.py` |
| A replay writes once | `test_a_replayed_approval_produces_one_write` |
| Alter, delete, reorder and append are all detected | `tests/test_audit.py` |
| A keyed chain detects a forgery a plain chain misses | `test_hmac_mode_detects_the_same_forgery` |
| Buyer markup is escaped in the console | `test_buyer_text_is_html_escaped` |
| CSP allows exactly self plus one pinned CDN | `test_csp_allows_exactly_self_and_the_one_cdn` |
| Production refuses a weak admin password | `tests/test_deployment.py` |
| The login throttle locks after five failures | `test_five_failures_then_a_429` |
| No secret reaches a log or a config repr | `test_startup_logging_prints_no_secret` |
| The suite never opens the operational database | `tests/test_no_real_db.py` |
| Errored evaluation runs count in nothing | `tests/test_errored_runs.py` |

What no test proves: that the webhook signature path works against a real
PayPal-signed event. See the note in the README.

## Residual risks

Ordered by how much they should worry an operator.

1. **A compromised process.** Anything running code in the app can call the
   executor directly. The boundary is inside one process; it is not a
   sandbox. Mitigation is deployment hygiene, not code.
2. **A stolen PayPal credential.** PayPal cannot distinguish Orrix's token
   from an attacker holding the same token. Orrix's controls are irrelevant
   at that point.
3. **A wrong approval.** The design makes an approval specific and
   informed — it shows the exact payload, the origin of every fact and any
   discrepancy — but a seller who approves the wrong thing gets what they
   approved.
4. **A forged audit history.** Without `AUDIT_HMAC_KEY`, database write
   access is enough to produce a chain that verifies; a test asserts this
   plainly. With a key, the key becomes the thing to steal, and a key stored
   beside the database buys little.
5. **Unverified seller tracking.** A seller can assert any well-formed
   tracking number and Orrix will submit it. It is marked `seller_asserted`
   and a contradiction raises a review flag, but nothing contacts the
   carrier. Orrix is relaying a claim on the seller's behalf.
6. **Session theft.** The cookie is `HttpOnly`, `SameSite=Lax` and `Secure`
   in production, and the CSP forbids inline script, but a stolen cookie is
   a logged-in operator until it expires. There is no re-authentication step
   in front of Approve.
7. **The login throttle is per-instance and in memory.** It raises the cost
   of guessing from one address. It is cleared by a restart and does not
   defend against a distributed attempt.
8. **Buyer PII at rest.** Dispute snapshots are stored verbatim, including
   buyer names, emails and messages. They are excluded from Facts and from
   every JSON endpoint, but they are in the database and in the
   `cases` table unencrypted.
9. **`X-Forwarded-For` is caller-supplied.** Behind Render it is set by the
   proxy, but the app cannot prove that, so the throttle key is spoofable.
10. **Dependency and CDN supply chain.** AG Grid and HTMX load from
    `cdn.jsdelivr.net` at pinned versions under a CSP that allows that one
    host. A compromise of that host or of a pinned artefact would execute in
    the operator's browser. Nothing is vendored or integrity-pinned with
    SRI.
11. **No rate limiting on the model call.** One call per read with retries
    capped, but nothing caps reads per dispute across a day.
12. **`style-src` permits inline styles.** AG Grid sets row and cell
    geometry through inline style attributes and injects its own style
    elements, so a strict `style-src` broke the grid outright: production
    logged hundreds of "Applying inline style violates ..." and the layout
    collapsed. `style-src` is therefore
    `'self' https://cdn.jsdelivr.net 'unsafe-inline'`.

    **Scripts remain strict.** `script-src` is `'self'` plus the one pinned
    CDN, with no `'unsafe-inline'`, no `'unsafe-eval'`, no nonce and no
    `'strict-dynamic'`, so this does **not** permit script injection.
    Injected markup could at worst restyle the page — move or hide an
    element, which matters for a UI an operator reads before approving —
    but it cannot execute. Buyer text is still escaped and quarantined, and
    our own templates carry no style attributes.

## Known limitations

- **Seller assertions are not verified.** A seller can type any well-formed
  tracking number. Orrix marks it `seller_asserted`, never `confirmed`, and a
  discrepancy raises a review flag, but nothing checks the number with the
  carrier. Treat `seller_asserted` facts as a claim Orrix is relaying on the
  seller's behalf.
- **A discrepancy does not block submission.** By design: the seller is
  entitled to put their evidence in front of PayPal. The review flag is the
  only consequence.
- **`delivered_date` is not a documented PayPal field.** It is included in the
  tracking entry because the payload spec calls for the delivery date. PayPal
  may ignore or reject it; confirm against a sandbox call before relying on it.
- **No rate limiting or cost control on the model call.** One call per read,
  with retries capped, but nothing caps reads per dispute.
- **The webhook verifies signatures; the poller trusts the list endpoint.**
  Both end in a fresh `get_dispute`, so a forged list entry can at worst cause
  an extra fetch.
- **`orrix/paypal.py` still reads the environment at import.** Newer modules
  take config objects; that one has not been migrated.
