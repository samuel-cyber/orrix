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

from attacks.chat import BudgetExhausted, CallBudget, ChatClient, ChatConfig
from attacks.corpus import Attack, load_corpus
from attacks.metrics import build_label_report
from attacks.recorder import DEFAULT_RECORDED_DIR, Recorder
from attacks.report import build_report, write_results_md, write_summary
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


@dataclass(frozen=True)
class ModelSettings:
    """What the env file supplied. The key is never printed."""

    base_url: str
    api_key: str
    model: str
    timeout: float = 60.0
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

    return ModelSettings(
        base_url=values["READER_BASE_URL"],
        api_key=values["READER_API_KEY"],
        model=values["READER_MODEL"],
        timeout=number("READER_TIMEOUT", 60.0),
        max_retries=int(number("READER_MAX_RETRIES", 3)),
    )


# -- planning -----------------------------------------------------------


@dataclass(frozen=True)
class PlannedWork:
    """What is left to do, after skipping what is already recorded."""

    items: tuple[tuple[str, Attack, int], ...]
    skipped: int

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
) -> PlannedWork:
    """Everything not already recorded for this label, in a stable order."""
    items: list[tuple[str, Attack, int]] = []
    skipped = 0

    for system in systems:
        for attack in attacks:
            done = recorder.runs_recorded(label, system, attack.id)
            for run_index in range(n):
                if run_index < done:
                    skipped += 1
                    continue
                items.append((system, attack, run_index))

    return PlannedWork(items=tuple(items), skipped=skipped)


# -- live ---------------------------------------------------------------


def run_live(
    attacks: Sequence[Attack],
    systems: Sequence[str],
    n: int,
    label: str,
    settings: ModelSettings,
    recorder: Recorder,
    max_calls: int | None,
    session: Any | None = None,
) -> tuple[int, int]:
    """Record runs until the work or the budget runs out.

    Returns (recorded, attempted). Sequential by design: these are someone's
    paid credits, and a burst of parallel calls is how a rate limit and a
    wasted budget happen at the same time.
    """
    work = plan_work(attacks, systems, n, recorder, label)
    budget = CallBudget(max_calls=max_calls)
    recorded = 0

    with tempfile.TemporaryDirectory(prefix="orrix-eval-") as tmp:
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
            logger.info(
                "recorded system=%s attack=%s run=%s unauthorized=%s calls_used=%s",
                system,
                attack.id,
                run_index,
                record.unauthorized_actions,
                budget.used,
            )

    return recorded, len(work)


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

        work = plan_work(attacks, requested, args.n, recorder, args.label)

        print(f"label:            {args.label}")
        print(f"model:            {settings.model}")
        print(f"attacks:          {len(attacks)}")
        print(f"systems:          {', '.join(requested)}")
        print(f"runs per combo:   {args.n}")
        print(f"already recorded: {work.skipped} (skipped)")
        print(f"runs to do:       {len(work)}")
        print(f"planned calls:    ~{work.estimated_calls}")
        if args.max_calls is not None:
            print(f"call ceiling:     {args.max_calls}")

        if not len(work):
            print("nothing to do; everything is already recorded for this label")
        elif not args.yes:
            print(
                "\nrefusing to spend credits without --yes. Re-run with --yes to proceed.",
                file=sys.stderr,
            )
            return EXIT_USAGE
        else:
            recorded, attempted = run_live(
                attacks,
                requested,
                args.n,
                args.label,
                settings,
                recorder,
                args.max_calls,
                session=session,
            )
            print(f"\nrecorded {recorded} of {attempted} planned runs")
            if recorded < attempted:
                print("stopped early: call budget reached. Re-run to resume.")

    # Both modes report from what is on disk, so the output always matches
    # the recorded evidence rather than this process's memory.
    reports = run_replay(recorder)
    report = build_report(reports)
    write_summary(report, summary_path)
    write_results_md(report, results_md_path)

    print(f"\nlabels reported:  {len(report.labels)}")
    for label in report.labels:
        print(
            f"  {label.label}: {label.record_count} runs, "
            f"{label.total_unauthorized} unauthorized, "
            f"{label.total_soft_failures} soft failures"
        )
    print(f"combined unauthorized actions: {report.combined_unauthorized}")
    print(f"wrote {summary_path} and {results_md_path}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
