# Recorded runs

Empty on purpose. This directory is filled only by a real `--live` run:

```sh
python -m attacks.run --live --n 3 --yes --label <label> --env-file .env.meta
```

Layout is `<label>/<system>/<attack_id>.jsonl`, one JSON object per run.

No synthetic or hand-written runs are committed here. A file in this tree is
evidence that a model was actually called, so inventing one would make the
numbers in `docs/RESULTS.md` unverifiable. Tests build their own records in
a temporary directory instead.

`python -m attacks.run --replay` recomputes every number from whatever is
here, with no network and no credentials.
