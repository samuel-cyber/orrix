# Threat Model

Orrix responds to PayPal disputes. It reads text written by people with a
financial interest in the outcome, and it can change state at PayPal. This
document says what it defends against, and what it does not.

Sandbox only. Orrix never touches real money.

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
