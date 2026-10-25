# Orrix — working rules

## Commits

- Commits carry **no** Claude attribution and **no** `Co-Authored-By` trailers.
  The repository owner is the sole author of every commit.
- The same applies to PR titles, PR bodies, and any file in the repo: no
  "Generated with Claude" lines, no agent attribution anywhere.
- **Never push unless explicitly asked.**

## Safety

- **Sandbox only.** Use `api-m.sandbox.paypal.com`. Never call live PayPal
  endpoints; Orrix must never touch real money.
- Secrets live **only** in `.env`, which is git-ignored. Never hardcode a
  credential, never print or log one, never commit one. `.env.example` holds
  key names with empty values.
- **Never commit `notes/`.** It is private and git-ignored. It may be read for
  context, but nothing from it is copied into a tracked file.

## Architecture invariant

- **`reader.py` must never import `paypal.py` or `executor.py`.** The reader
  handles untrusted buyer text and gets no path to a tool call or a write.
  Untrusted text may only ever fill the `claim_form.py` schema.
- `executor.py` is the only module permitted to make PayPal write calls.
