"""Evaluation harness CLI.

    python -m attacks.run --replay
    python -m attacks.run --live --n 3 --yes --label <label> [--env-file <path>] [--max-calls <k>]

Replay needs no network and no credentials. Live mode requires --yes, prints
the planned call count first, backs off on 429s, skips combinations already
recorded for the label, and stops cleanly when --max-calls is reached.

Credentials are read from the env file in this module and passed down as a
config object. They are never logged.
"""

from __future__ import annotations

import argparse
import logging
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from attacks.chat import (
    EVAL_TIMEOUT_SECONDS,
    BudgetExhausted,
    CallBudget,
    ChatClient,
    ChatConfig,
)
from attacks.corpus import Attack, load_corpus
from attacks.metrics import build_label_report
from attacks.recorder import DEFAULT_RECORDED_DIR, Recorder
from attacks.report import build_report, write_results_md, write_summary
from attacks.status import STATUS_ERRORED
from attacks.systems import (
    SYSTEM_DEFENDED,
    SYSTEM_NAIVE,
    SYSTEM_ORRIX,
    SYSTEMS,
    run_baseline,
    run_orrix,
)
from orrix.reader import ReaderConfig

logger = logging.getLogger("attacks.run")

DEFAULT_N = 3
DEFAULT_SUMMARY = Path("results/summary.json")
DEFAULT_RESULTS_MD = Path("docs/RESULTS.md")

#: Model calls one run of each system costs, used for the plan estimate.
#: Orrix makes one Reader call (plus at most one retry); the agent loops are
#: bounded by their step limit.
CALLS_PER_RUN = {SYSTEM_ORRIX: 1, SYSTEM_NAIVE: 3, SYSTEM_DEFENDED: 3}

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_BUDGET = 3
EXIT_UNHEALTHY = 4

#: Stop a run after this many errored runs in a row. A dead endpoint should
#: cost minutes, not the three hours the first run took.
CONSECUTIVE_ERROR_LIMIT = 5


@dataclass(frozen=True)
class ModelSettings:
    """What the env file supplied. The key is never printed."""

    base_url: str
    api_key: str
    model: str
    #: A hard per-request ceiling for evaluation calls. Short on purpose: the
    #: first live run spent about three hours on silent connect timeouts.
    #: This is the harness's own setting and does not change the production
    #: Reader, whose default stays at 30s.
    timeout: float = EVAL_TIMEOUT_SECONDS
    max_retries: int = 3

    def chat_config(self) -> ChatConfig:
        return ChatConfig(
            base_url=self.base_url,
            api_key=self.api_key,
            model=self.model,
            timeout=self.timeout,
            max_retries=self.max_retries,
        )

    def reader_config(self) -> ReaderConfig:
        return ReaderConfig(
            base_url=self.base_url,
            api_key=self.api_key,
            model=self.model,
            timeout=self.timeout,
            max_retries=self.max_retries,
        )


def parse_env_file(path: str | Path) -> dict[str, str]:
    """Read KEY=VALUE lines. Values are returned, never logged."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"no env file at {path}")

    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        value = value.strip().strip('"').strip("'")
        if value:
            values[key.strip()] = value
    return values


def model_settings_from(values: dict[str, str]) -> ModelSettings:
    missing = [
        key for key in ("READER_BASE_URL", "READER_API_KEY", "READER_MODEL") if not values.get(key)
    ]
    if missing:
        raise ValueError(f"env file is missing: {', '.join(missing)}")

    def number(key: str, default: float) -> float:
        try:
            return float(values.get(key, default))
        except (TypeError, ValueError):
            return default

    # The 20s ceiling is hard: an env file asking for 60 is capped, because
    # a long timeout is exactly what turned a dead endpoint into a
    # three-hour run. A shorter value from the env file is honoured.
    requested_timeout = number("READER_TIMEOUT", EVAL_TIMEOUT_SECONDS)
    timeout = min(requested_timeout, EVAL_TIMEOUT_SECONDS)
    if requested_timeout > EVAL_TIMEOUT_SECONDS:
        logger.info(
            "capping per-request timeout at %ss for the harness (env file asked for %ss)",
            EVAL_TIMEOUT_SECONDS,
            requested_timeout,
        )

    return ModelSettings(
        base_url=values["READER_BASE_URL"],
        api_key=values["READER_API_KEY"],
        model=values["READER_MODEL"],
        timeout=timeout,
        max_retries=int(number("READER_MAX_RETRIES", 3)),
    )


# -- planning -----------------------------------------------------------


@dataclass(frozen=True)
class PlannedWork:
    """What is left to do, after skipping runs that already succeeded."""

    items: tuple[tuple[str, Attack, int], ...]
    skipped: int
    #: How many of the planned items are reruns of errored records.
    retrying: int = 0

    @property
    def estimated_calls(self) -> int:
        return sum(CALLS_PER_RUN.get(system, 1) for system, _, _ in self.items)

    def __len__(self) -> int:
        return len(self.items)


def plan_work(
    attacks: Sequence[Attack],
    systems: Sequence[str],
    n: int,
    recorder: Recorder,
    label: str,
    retry_errors: bool = True,
) -> PlannedWork:
    """Everything still to do for this label, in a stable order.

    Only runs with status "ok" are skipped. An errored run is not a result,
    so by default it is planned again; pass retry_errors=False to leave
    errored slots alone.
    """
    items: list[tuple[str, Attack, int]] = []
    skipped = 0
    retrying = 0

    for system in systems:
        for attack in attacks:
            done_ok = recorder.ok_run_indices(label, system, attack.id)
            errored = recorder.errored_run_indices(label, system, attack.id)
            for run_index in range(n):
                if run_index in done_ok:
                    skipped += 1
                    continue
                if run_index in errored:
                    if not retry_errors:
                        skipped += 1
                        continue
                    retrying += 1
                items.append((system, attack, run_index))

    return PlannedWork(items=tuple(items), skipped=skipped, retrying=retrying)


# -- live ---------------------------------------------------------------


@dataclass(frozen=True)
class LiveOutcome:
    """What a live run actually did, including why it stopped."""

    recorded: int
    planned: int
    aborted: bool = False
    consecutive_errors: int = 0
    last_failure: dict[str, Any] | None = None
    calls_used: int = 0


def run_live(
    attacks: Sequence[Attack],
    systems: Sequence[str],
    n: int,
    label: str,
    settings: ModelSettings,
    recorder: Recorder,
    max_calls: int | None,
    session: Any | None = None,
    retry_errors: bool = True,
) -> LiveOutcome:
    """Record runs until the work, the budget, or the endpoint runs out.

    Sequential by design: these are someone's paid credits, and a burst of
    parallel calls is how a rate limit and a wasted budget happen at the
    same time. Aborts after CONSECUTIVE_ERROR_LIMIT errored runs in a row,
    keeping everything recorded so far.
    """
    work = plan_work(attacks, systems, n, recorder, label, retry_errors=retry_errors)
    budget = CallBudget(max_calls=max_calls)
    recorded = 0
    consecutive_errors = 0
    last_failure: dict[str, Any] | None = None
    aborted = False

    # ignore_cleanup_errors: a leftover scratch file must never fail a run
    # whose records are already safely on disk.
    with tempfile.TemporaryDirectory(
        prefix="orrix-eval-", ignore_cleanup_errors=True
    ) as tmp:
        tmp_dir = Path(tmp)

        for system, attack, run_index in work.items:
            if budget.exhausted:
                logger.info("call budget reached; stopping cleanly")
                break
            try:
                if system == SYSTEM_ORRIX:
                    client = ChatClient(
                        settings.chat_config(), session=session, budget=budget
                    )
                    record = run_orrix(
                        attack,
                        settings.reader_config(),
                        run_index,
                        label,
                        tmp_dir,
                        chat_session=_ReaderSession(client),
                    )
                else:
                    client = ChatClient(
                        settings.chat_config(), session=session, budget=budget
                    )
                    record = run_baseline(
                        system, attack, settings.chat_config(), client, run_index, label
                    )
            except BudgetExhausted:
                logger.info("call budget reached mid-run; stopping cleanly")
                break

            recorder.append(record.as_dict())
            recorded += 1

            if record.status == STATUS_ERRORED:
                consecutive_errors += 1
                last_failure = record.failure or {
                    "exception_class": "unknown",
                    "message": record.error_reason or "no usable response",
                }
                logger.warning(
                    "errored run %s/%s in a row system=%s attack=%s run=%s reason=%s "
                    "elapsed=%.2fs calls_used=%s",
                    consecutive_errors,
                    CONSECUTIVE_ERROR_LIMIT,
                    system,
                    attack.id,
                    run_index,
                    record.error_reason,
                    record.elapsed_seconds,
                    budget.used,
                )
                if consecutive_errors >= CONSECUTIVE_ERROR_LIMIT:
                    aborted = True
                    break
            else:
                consecutive_errors = 0
                logger.info(
                    "recorded system=%s attack=%s run=%s unauthorized=%s "
                    "elapsed=%.2fs calls_used=%s",
                    system,
                    attack.id,
                    run_index,
                    record.unauthorized_actions,
                    record.elapsed_seconds,
                    budget.used,
                )

    return LiveOutcome(
        recorded=recorded,
        planned=len(work),
        aborted=aborted,
        consecutive_errors=consecutive_errors,
        last_failure=last_failure,
        calls_used=budget.used,
    )


class _ReaderSession:
    """Adapts orrix.reader's requests-style client onto the budgeted client.

    The Reader posts through `session.post(...)`; routing it through the
    shared ChatClient keeps every model call inside one budget.
    """

    def __init__(self, client: ChatClient):
        self._client = client

    def post(self, url, **kwargs):
        self._client.budget.consume()
        session = self._client._client()
        return session.post(url, **kwargs)


# -- replay -------------------------------------------------------------


def run_replay(recorder: Recorder) -> list[Any]:
    """Build a report per label from recorded runs. No network at all."""
    reports = []
    for label, records in recorder.all_records().items():
        if not records:
            continue
        reports.append(build_label_report(label, records))
    return reports


# -- CLI ----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m attacks.run",
        description="Orrix evaluation harness. Sandbox and offline by default.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--live", action="store_true", help="call a model and record runs")
    mode.add_argument(
        "--replay", action="store_true", help="recompute from recorded runs (default)"
    )
    parser.add_argument("--n", type=int, default=DEFAULT_N, help="runs per attack per system")
    parser.add_argument("--yes", action="store_true", help="confirm the planned model calls")
    parser.add_argument("--label", help="names the provider and model, e.g. featherless-<model>")
    parser.add_argument("--env-file", help="file holding READER_BASE_URL/API_KEY/MODEL")
    parser.add_argument("--max-calls", type=int, help="hard ceiling on model calls")
    parser.add_argument(
        "--retry-errors",
        action="store_true",
        help="rerun records whose model call errored (default for --live)",
    )
    parser.add_argument(
        "--no-retry-errors",
        action="store_true",
        help="leave errored records alone instead of rerunning them",
    )
    parser.add_argument(
        "--purge-errors",
        action="store_true",
        help="delete errored records for --label and report how many went",
    )
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="print the plan and exit without calling a model",
    )
    parser.add_argument(
        "--systems", default=",".join(SYSTEMS), help="comma-separated systems to run"
    )
    parser.add_argument("--corpus", help="path to corpus.yaml")
    parser.add_argument("--recorded-dir", help="where recorded runs live")
    parser.add_argument("--summary", help="path for results/summary.json")
    parser.add_argument("--results-md", help="path for docs/RESULTS.md")
    return parser


def main(argv: Sequence[str] | None = None, session: Any | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    args = build_parser().parse_args(list(argv) if argv is not None else None)

    attacks = load_corpus(args.corpus) if args.corpus else load_corpus()
    recorder = Recorder(
        root=Path(args.recorded_dir) if args.recorded_dir else DEFAULT_RECORDED_DIR
    )
    summary_path = Path(args.summary) if args.summary else DEFAULT_SUMMARY
    results_md_path = Path(args.results_md) if args.results_md else DEFAULT_RESULTS_MD

    requested = [name.strip() for name in args.systems.split(",") if name.strip()]
    unknown = [name for name in requested if name not in SYSTEMS]
    if unknown:
        print(f"unknown system(s): {', '.join(unknown)}", file=sys.stderr)
        return EXIT_USAGE

    if args.purge_errors:
        if not args.label:
            print("--purge-errors needs --label", file=sys.stderr)
            return EXIT_USAGE

        reclassified = recorder.reclassified_count(args.label)
        before = len(recorder.raw_records_for_label(args.label))
        removed, kept = recorder.purge_errored(args.label)

        print(f"label:                 {args.label}")
        print(f"records before:        {before}")
        if reclassified:
            print(
                f"reclassified:          {reclassified} record(s) had no status field "
                f"and were classified from their recorded model_error"
            )
        print(f"errored removed:       {removed}")
        print(f"valid records kept:    {kept}")

    if args.live:
        if not args.label:
            print("--live needs --label to name the provider and model", file=sys.stderr)
            return EXIT_USAGE
        if not args.env_file:
            print("--live needs --env-file holding the model credentials", file=sys.stderr)
            return EXIT_USAGE

        try:
            settings = model_settings_from(parse_env_file(args.env_file))
        except (FileNotFoundError, ValueError) as error:
            # The message names the file and the missing keys, never a value.
            print(str(error), file=sys.stderr)
            return EXIT_USAGE

        retry_errors = not args.no_retry_errors
        reclassified = recorder.reclassified_count(args.label)
        work = plan_work(
            attacks, requested, args.n, recorder, args.label, retry_errors=retry_errors
        )

        print(f"label:            {args.label}")
        print(f"model:            {settings.model}")
        print(f"attacks:          {len(attacks)}")
        print(f"systems:          {', '.join(requested)}")
        print(f"runs per combo:   {args.n}")
        print(f"already ok:       {work.skipped} (skipped)")
        print(f"errored to rerun: {work.retrying}")
        print(f"runs to do:       {len(work)}")
        print(f"planned calls:    ~{work.estimated_calls}")
        print(f"per-call timeout: {settings.timeout}s")
        if reclassified:
            print(
                f"reclassified:     {reclassified} legacy record(s) classified from "
                f"their recorded model_error"
            )
        if args.max_calls is not None:
            print(f"call ceiling:     {args.max_calls}")

        if args.plan_only:
            print("\nplan only; no model was called")
        elif not len(work):
            print("nothing to do; every run for this label already succeeded")
        elif not args.yes:
            print(
                "\nrefusing to spend credits without --yes. Re-run with --yes to proceed.",
                file=sys.stderr,
            )
            return EXIT_USAGE
        else:
            outcome = run_live(
                attacks,
                requested,
                args.n,
                args.label,
                settings,
                recorder,
                args.max_calls,
                session=session,
                retry_errors=retry_errors,
            )
            print(f"\nrecorded {outcome.recorded} of {outcome.planned} planned runs")
            print(f"model calls used: {outcome.calls_used}")

            if outcome.aborted:
                failure = outcome.last_failure or {}
                print(
                    f"\nlast error: {failure.get('exception_class', 'unknown')}: "
                    f"{failure.get('message', '')}"
                )
                print(
                    "endpoint unhealthy, recorded runs are kept, rerun later"
                )
                _write_report(recorder, summary_path, results_md_path)
                return EXIT_UNHEALTHY

            if outcome.recorded < outcome.planned:
                print("stopped early: call budget reached. Re-run to resume.")

    # Both modes report from what is on disk, so the output always matches
    # the recorded evidence rather than this process's memory.
    _write_report(recorder, summary_path, results_md_path)
    return EXIT_OK


def _write_report(recorder: Recorder, summary_path: Path, results_md_path: Path) -> None:
    """Rebuild both reports from disk and print the headline figures."""
    report = build_report(run_replay(recorder))
    write_summary(report, summary_path)
    write_results_md(report, results_md_path)

    warning = report.warning_line()
    if warning:
        print(f"\n{warning}")

    print(f"\nlabels reported:  {len(report.labels)}")
    for label in report.labels:
        blanked = label.systems_without_valid_runs()
        print(
            f"  {label.label}: {label.total_valid_runs} valid run(s), "
            f"{label.total_errored_runs} errored, "
            f"{label.total_unauthorized} unauthorized, "
            f"{label.total_soft_failures} soft failures"
        )
        for system in sorted(set(label.runs_by_system()) | set(label.errored_by_system())):
            print(
                f"    {system}: valid={label.runs_by_system().get(system, 0)} "
                f"errored={label.errored_by_system().get(system, 0)} "
                f"unauthorized={label.unauthorized_display(system)}"
            )
        if blanked:
            print(f"    no valid runs for: {', '.join(blanked)}")

    print(f"combined unauthorized actions: {report.combined_unauthorized}")
    print(f"wrote {summary_path} and {results_md_path}")


if __name__ == "__main__":
    raise SystemExit(main())
