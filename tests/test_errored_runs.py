"""Errored runs must never count as results.

A run where the model never answered says nothing about the system under
test. These tests pin that: exclusion from counts, the zero-valid-runs case,
retry and backoff, the resume and purge paths, legacy reclassification, the
abort after repeated failures, and that none of it logs a secret.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from attacks.chat import (
    EVAL_TIMEOUT_SECONDS,
    CallBudget,
    ChatClient,
    ChatConfig,
)
from attacks.corpus import load_corpus
from attacks.metrics import aggregate, build_label_report
from attacks.recorder import Recorder
from attacks.report import build_report, render_results_md, summary_payload
from attacks.run import (
    CONSECUTIVE_ERROR_LIMIT,
    EXIT_OK,
    EXIT_UNHEALTHY,
    EXIT_USAGE,
    main,
    model_settings_from,
    parse_env_file,
    plan_work,
    run_live,
)
from attacks.status import STATUS_ERRORED, STATUS_OK, classify, is_errored
from attacks.systems import SYSTEM_ORRIX, run_orrix
from orrix.errors import describe, host_of, scrub
from orrix.reader import ReaderConfig, read_claim

SECRET_KEY = "sk-errored-DO-NOT-LOG-abcdef123456"
HOST = "model.example.invalid"
BASE_URL = f"https://{HOST}/v1"


def record(system="orrix", run_index=0, errored=False, label="lbl", **overrides):
    base = {
        "label": label,
        "system": system,
        "attack_id": "override_refund_in_full",
        "category": "direct_override",
        "run_index": run_index,
        "model": "test-model",
        "recorded_at": "2026-11-07T12:00:00+00:00",
        "unauthorized_actions": 0,
        "writes": [],
        "tool_calls": [],
        "schema_valid": not errored,
        "needs_review": errored,
        "approval_created": False,
        "soft_failures": [],
        "refused": False,
        "model_error": "transport_error" if errored else None,
        "status": STATUS_ERRORED if errored else STATUS_OK,
        "error_reason": "transport_error" if errored else None,
    }
    base.update(overrides)
    return base


def env_file(tmp_path, **extra):
    lines = [
        f"READER_BASE_URL={BASE_URL}",
        f"READER_API_KEY={SECRET_KEY}",
        "READER_MODEL=test-model",
    ]
    lines += [f"{key}={value}" for key, value in extra.items()]
    path = tmp_path / ".env.model"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# -- classification ------------------------------------------------------


def test_transport_errors_classify_as_errored():
    for reason in (
        "transport_error",
        "transport_error:ConnectTimeout",
        "http_error",
        "http_500",
        "rate_limited",
        "empty_response",
        "retries_exhausted",
    ):
        status, stored = classify({"model_error": reason})
        assert status == STATUS_ERRORED, reason
        assert stored == reason


def test_bad_model_output_is_a_result_not_an_error():
    """A model that answered badly still measured something."""
    for reason in ("invalid_json", "schema_invalid", "reader_not_configured"):
        status, _ = classify({"model_error": reason})
        assert status == STATUS_OK, reason


def test_a_stored_status_is_authoritative():
    assert classify({"status": "ok", "model_error": "transport_error"})[0] == STATUS_OK
    assert classify({"status": "errored", "model_error": None})[0] == STATUS_ERRORED


# -- exclusion from counts -----------------------------------------------


def test_errored_runs_are_in_no_numerator_and_no_denominator():
    records = [
        record(errored=True),
        record(run_index=1, errored=True),
        record(run_index=2, unauthorized_actions=0),
        record(run_index=3, unauthorized_actions=1),
    ]

    cell = aggregate(records)[0]

    assert cell.runs == 2, "only the runs that answered"
    assert cell.errored_runs == 2
    assert cell.attempted_runs == 4
    assert cell.unauthorized_actions == 1
    assert cell.resisted == 1
    assert cell.rate(cell.unauthorized_actions) == 0.5


def test_an_errored_run_never_counts_as_resisted():
    """The bug: 135 failures read as 135 attacks survived."""
    records = [record(errored=True) for _ in range(5)]

    cell = aggregate(records)[0]

    assert cell.errored_runs == 5
    assert cell.resisted == 0
    assert cell.runs == 0


def test_errored_runs_do_not_count_toward_honest_metrics():
    records = [record(category="honest_vague", errored=True, needs_review=True)]

    cell = aggregate(records)[0]

    assert cell.honest_over_refusal == 0
    assert cell.honest_wrong_action == 0


def test_n_is_derived_from_valid_runs_only():
    records = [record(run_index=0), record(run_index=1, errored=True)]

    assert build_label_report("lbl", records).n == 1


# -- the zero-valid-runs case -------------------------------------------


def test_a_system_with_no_valid_runs_reports_an_absence():
    records = [record(system="orrix", run_index=i, errored=True) for i in range(3)]
    records.append(record(system="naive_agent", unauthorized_actions=1))

    report = build_label_report("lbl", records)

    assert report.systems_without_valid_runs() == ["orrix"]
    assert report.unauthorized_display("orrix") == "no valid runs"
    assert report.unauthorized_display("naive_agent") == "1"
    assert report.runs_by_system()["orrix"] == 0


def test_zero_valid_runs_never_renders_as_zero_unauthorized():
    records = [record(system="orrix", run_index=i, errored=True) for i in range(3)]
    text = render_results_md(build_report([build_label_report("lbl", records)]))

    assert "no valid runs" in text
    # The cell table must not show a bare 0 for a system that ran nothing.
    rows = [line for line in text.splitlines() if line.startswith("| orrix |")]
    assert rows
    for row in rows:
        assert "no valid runs" in row


def test_a_cell_with_no_valid_runs_has_no_rate():
    cell = aggregate([record(errored=True)])[0]

    assert cell.has_valid_runs is False
    assert cell.rate(cell.unauthorized_actions) is None


def test_the_warning_line_names_the_errored_count():
    records = [record(errored=True), record(run_index=1)]
    report = build_report([build_label_report("lbl", records)])

    warning = report.warning_line()

    assert warning is not None
    assert "1 of 2" in warning
    assert "excluded" in warning


def test_no_warning_when_nothing_errored():
    report = build_report([build_label_report("lbl", [record()])])

    assert report.warning_line() is None
    assert "WARNING" not in render_results_md(report)


def test_the_summary_payload_reports_valid_and_errored():
    records = [record(errored=True), record(run_index=1, unauthorized_actions=1)]
    payload = summary_payload(build_report([build_label_report("lbl", records)]))

    assert payload["combined_valid_runs"] == 1
    assert payload["combined_errored_runs"] == 1
    assert payload["has_errors"] is True
    assert payload["warning"]
    row = payload["rows"][0]
    assert row["valid_runs"] == 1
    assert row["errored_runs"] == 1
    # The soft-failures column is still there.
    assert "soft_failures" in row


# -- retry and backoff ---------------------------------------------------


class CountingSession:
    """Fails a set number of times, then answers."""

    def __init__(self, failures, final=None, exception=OSError):
        self.failures = failures
        self.final = final
        self.exception = exception
        self.posts = 0
        self.timeouts: list[float] = []

    def post(self, url, **kwargs):
        self.posts += 1
        self.timeouts.append(kwargs.get("timeout"))
        if self.posts <= self.failures:
            raise self.exception("connection reset by peer")
        if self.final is not None:
            return self.final

        class Response:
            status_code = 200
            headers: dict = {}

            def json(self_inner):
                return {"choices": [{"message": {"content": '{"action":"done"}'}}]}

        return Response()


def test_the_reader_retries_a_transport_error_three_times():
    session = CountingSession(failures=5)
    sleeps: list[float] = []
    config = ReaderConfig(base_url=BASE_URL, api_key=SECRET_KEY, model="m")

    result = read_claim("text", 20, config, session, sleep=sleeps.append)

    assert session.posts == 3
    assert sleeps == [1.0, 3.0]
    assert result.reason == "transport_error"
    assert result.model_never_answered is True


def test_the_reader_succeeds_on_a_later_attempt():
    good = json.dumps(
        {
            "claim_type": "NOT_RECEIVED",
            "claimed_amount": "20.00",
            "language": "en",
            "seller_summary": "Buyer reports non-delivery.",
        }
    )

    class Response:
        status_code = 200
        headers: dict = {}

        def json(self):
            return {"choices": [{"message": {"content": good}}]}

    session = CountingSession(failures=2, final=Response())
    result = read_claim("text", 20, ReaderConfig(BASE_URL, SECRET_KEY, "m"), session,
                        sleep=lambda _: None)

    assert session.posts == 3
    assert result.ok
    assert result.model_never_answered is False


def test_the_chat_client_retries_and_counts_every_attempt():
    session = CountingSession(failures=5)
    budget = CallBudget(max_calls=10)
    sleeps: list[float] = []
    client = ChatClient(
        ChatConfig(base_url=BASE_URL, api_key=SECRET_KEY, model="m"),
        session=session,
        budget=budget,
        sleep=sleeps.append,
    )

    result = client.complete([{"role": "user", "content": "hi"}])

    assert session.posts == 3
    assert sleeps == [1.0, 3.0]
    assert budget.used == 3, "a retry costs a call"
    assert result.error.startswith("transport_error:")
    assert result.model_never_answered is True


def test_a_five_hundred_is_retried_and_a_four_hundred_is_not():
    class Status:
        def __init__(self, code):
            self.status_code = code
            self.headers: dict = {}

        def json(self):
            return {}

    for code, expected_posts in ((500, 3), (503, 3), (400, 1), (404, 1)):
        session = CountingSession(failures=0, final=Status(code))
        client = ChatClient(
            ChatConfig(base_url=BASE_URL, api_key=SECRET_KEY, model="m"),
            session=session,
            budget=CallBudget(),
            sleep=lambda _: None,
        )
        client.complete([{"role": "user", "content": "hi"}])
        assert session.posts == expected_posts, code


def test_retry_after_is_honoured():
    from orrix.errors import retry_after_seconds

    class WithHeader:
        status_code = 429
        headers = {"Retry-After": "7"}

        def json(self):
            return {}

    assert retry_after_seconds(WithHeader(), 1.0) == 7.0
    assert retry_after_seconds(WithHeader(), 1.0) != 1.0

    class NoHeader:
        status_code = 429
        headers: dict = {}

        def json(self):
            return {}

    assert retry_after_seconds(NoHeader(), 2.5) == 2.5

    class Nonsense:
        headers = {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}

    assert retry_after_seconds(Nonsense(), 1.5) == 1.5

    class Huge:
        headers = {"Retry-After": "99999"}

    assert retry_after_seconds(Huge(), 1.0) == 60.0


def test_the_chat_client_waits_what_retry_after_asks():
    class Limited:
        status_code = 429
        headers = {"Retry-After": "4"}

        def json(self):
            return {}

    session = CountingSession(failures=0, final=Limited())
    sleeps: list[float] = []
    ChatClient(
        ChatConfig(base_url=BASE_URL, api_key=SECRET_KEY, model="m"),
        session=session,
        budget=CallBudget(),
        sleep=sleeps.append,
    ).complete([{"role": "user", "content": "hi"}])

    assert sleeps == [4.0, 4.0]


# -- the 20 second timeout ----------------------------------------------


def test_the_harness_timeout_is_twenty_seconds():
    assert EVAL_TIMEOUT_SECONDS == 20.0
    assert ChatConfig(base_url=BASE_URL, api_key=SECRET_KEY, model="m").timeout == 20.0


def test_the_timeout_is_applied_to_every_request():
    session = CountingSession(failures=5)
    ChatClient(
        ChatConfig(base_url=BASE_URL, api_key=SECRET_KEY, model="m"),
        session=session,
        budget=CallBudget(),
        sleep=lambda _: None,
    ).complete([{"role": "user", "content": "hi"}])

    assert session.timeouts == [20.0, 20.0, 20.0]


def test_an_env_file_cannot_raise_the_harness_timeout(tmp_path):
    settings = model_settings_from(parse_env_file(env_file(tmp_path, READER_TIMEOUT="600")))

    assert settings.timeout == 20.0
    assert settings.chat_config().timeout == 20.0
    assert settings.reader_config().timeout == 20.0


def test_an_env_file_may_lower_the_timeout(tmp_path):
    settings = model_settings_from(parse_env_file(env_file(tmp_path, READER_TIMEOUT="5")))

    assert settings.timeout == 5.0


def test_the_production_reader_default_is_unchanged():
    """Item 6 applies to the harness only."""
    assert ReaderConfig(base_url=BASE_URL, api_key="k", model="m").timeout == 30.0


# -- secrets never logged ------------------------------------------------


def test_transport_logging_names_the_host_not_the_url_or_key(caplog):
    session = CountingSession(failures=5)
    config = ReaderConfig(base_url=BASE_URL, api_key=SECRET_KEY, model="m")

    with caplog.at_level(logging.DEBUG):
        read_claim("buyer text here", 20, config, session, sleep=lambda _: None)

    text = caplog.text
    assert SECRET_KEY not in text
    assert "Bearer" not in text
    assert config.completions_url not in text
    assert HOST in text
    assert "OSError" in text
    assert "elapsed=" in text
    assert "attempt=" in text
    # And the buyer's words never appear either.
    assert "buyer text here" not in text


def test_chat_transport_logging_leaks_nothing(caplog):
    session = CountingSession(failures=5)
    config = ChatConfig(base_url=BASE_URL, api_key=SECRET_KEY, model="m")

    with caplog.at_level(logging.DEBUG):
        ChatClient(config, session=session, budget=CallBudget(), sleep=lambda _: None).complete(
            [{"role": "user", "content": "secret buyer message"}]
        )

    text = caplog.text
    assert SECRET_KEY not in text
    assert config.completions_url not in text
    assert "secret buyer message" not in text
    assert HOST in text
    assert "elapsed=" in text


def test_a_url_inside_an_exception_message_is_scrubbed():
    error = OSError(
        f"HTTPSConnectionPool(host='{HOST}', port=443): failed to reach "
        f"{BASE_URL}/chat/completions with Bearer {SECRET_KEY}"
    )

    detail = describe(error, BASE_URL, attempt=1, elapsed_seconds=1.5)

    assert SECRET_KEY not in detail.message
    assert "/chat/completions" not in detail.message
    assert "Bearer <redacted>" in detail.message or "<redacted>" in detail.message
    assert detail.host == HOST
    assert detail.exception_class == "OSError"


def test_scrub_and_host_helpers():
    assert scrub(f"see {BASE_URL}/x?key=abc") == "see <url>"
    assert scrub(None) == ""
    assert host_of(BASE_URL) == HOST
    assert host_of("not a url") == "unknown"
    assert host_of(None) == "unknown"
    assert len(scrub("x" * 5000)) < 300


# -- resume, retry-errors and purge -------------------------------------


def test_resume_skips_only_ok_records(tmp_path):
    recorder = Recorder(root=tmp_path)
    attacks = load_corpus()[:2]
    recorder.append(record(attack_id=attacks[0].id, run_index=0))
    recorder.append(record(attack_id=attacks[1].id, run_index=0, errored=True))

    work = plan_work(attacks, ["orrix"], 1, recorder, "lbl", retry_errors=True)

    planned = {(s, a.id, i) for s, a, i in work.items}
    assert (("orrix", attacks[0].id, 0)) not in planned, "a good run is not repeated"
    assert (("orrix", attacks[1].id, 0)) in planned, "an errored run is retried"
    assert work.skipped == 1
    assert work.retrying == 1


def test_no_retry_errors_leaves_errored_slots_alone(tmp_path):
    recorder = Recorder(root=tmp_path)
    attacks = load_corpus()[:1]
    recorder.append(record(attack_id=attacks[0].id, run_index=0, errored=True))

    work = plan_work(attacks, ["orrix"], 1, recorder, "lbl", retry_errors=False)

    assert len(work) == 0
    assert work.skipped == 1
    assert work.retrying == 0


def test_purge_errors_removes_only_errored_records(tmp_path):
    recorder = Recorder(root=tmp_path)
    recorder.append(record(run_index=0, errored=True))
    recorder.append(record(run_index=1))
    recorder.append(record(system="naive_agent", run_index=0, errored=True))

    removed, kept = recorder.purge_errored("lbl")

    assert removed == 2
    assert kept == 1
    survivors = recorder.records_for_label("lbl")
    assert len(survivors) == 1
    assert survivors[0]["run_index"] == 1
    assert not any(is_errored(r) for r in survivors)


def test_purge_deletes_a_file_left_with_nothing(tmp_path):
    recorder = Recorder(root=tmp_path)
    recorder.append(record(errored=True))
    path = recorder.path_for("lbl", "orrix", "override_refund_in_full")
    assert path.is_file()

    recorder.purge_errored("lbl")

    assert not path.is_file()


def test_purge_on_an_unknown_label_is_harmless(tmp_path):
    assert Recorder(root=tmp_path).purge_errored("nope") == (0, 0)


def test_the_purge_cli_reports_its_counts(tmp_path, capsys):
    recorded = tmp_path / "recorded"
    recorder = Recorder(root=recorded)
    recorder.append(record(run_index=0, errored=True))
    recorder.append(record(run_index=1))

    code = main(
        [
            "--purge-errors",
            "--label",
            "lbl",
            "--recorded-dir",
            str(recorded),
            "--summary",
            str(tmp_path / "s.json"),
            "--results-md",
            str(tmp_path / "R.md"),
        ]
    )

    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "errored removed:       1" in out
    assert "valid records kept:    1" in out


def test_purge_without_a_label_is_refused(tmp_path, capsys):
    code = main(["--purge-errors", "--recorded-dir", str(tmp_path)])

    assert code == EXIT_USAGE
    assert "--purge-errors needs --label" in capsys.readouterr().err


# -- legacy records ------------------------------------------------------


def test_legacy_records_are_reclassified_from_their_evidence(tmp_path):
    recorder = Recorder(root=tmp_path)
    # Written before `status` existed: no status key at all.
    legacy_bad = record(run_index=0)
    legacy_bad.pop("status")
    legacy_bad.pop("error_reason")
    legacy_bad["model_error"] = "transport_error:ConnectTimeout"

    legacy_good = record(run_index=1)
    legacy_good.pop("status")
    legacy_good.pop("error_reason")

    recorder.append(legacy_bad)
    recorder.append(legacy_good)

    assert recorder.reclassified_count("lbl") == 2

    records = {r["run_index"]: r for r in recorder.records_for_label("lbl")}
    assert records[0]["status"] == STATUS_ERRORED
    assert records[0]["error_reason"] == "transport_error:ConnectTimeout"
    assert records[0]["reclassified"] is True
    assert records[1]["status"] == STATUS_OK

    # And the counts follow the reclassification.
    cell = aggregate(recorder.records_for_label("lbl"))[0]
    assert cell.runs == 1
    assert cell.errored_runs == 1


def test_the_cli_reports_how_many_records_were_reclassified(tmp_path, capsys):
    recorded = tmp_path / "recorded"
    recorder = Recorder(root=recorded)
    legacy = record()
    legacy.pop("status")
    legacy.pop("error_reason")
    legacy["model_error"] = "transport_error"
    recorder.append(legacy)

    main(
        [
            "--purge-errors",
            "--label",
            "lbl",
            "--recorded-dir",
            str(recorded),
            "--summary",
            str(tmp_path / "s.json"),
            "--results-md",
            str(tmp_path / "R.md"),
        ]
    )

    out = capsys.readouterr().out
    assert "reclassified:          1 record(s) had no status field" in out


# -- fail fast -----------------------------------------------------------


def test_a_run_aborts_after_five_consecutive_errors(tmp_path, capsys):
    """A dead endpoint must cost minutes, not three hours."""
    recorded = tmp_path / "recorded"

    class AlwaysFails:
        def __init__(self):
            self.posts = 0

        def post(self, url, **kwargs):
            self.posts += 1
            raise OSError("connection timed out")

    session = AlwaysFails()
    code = main(
        [
            "--live",
            "--yes",
            "--label",
            "lbl",
            "--env-file",
            str(env_file(tmp_path)),
            "--systems",
            "orrix",
            "--n",
            "1",
            "--recorded-dir",
            str(recorded),
            "--summary",
            str(tmp_path / "s.json"),
            "--results-md",
            str(tmp_path / "R.md"),
        ],
        session=session,
    )

    out = capsys.readouterr().out
    assert code == EXIT_UNHEALTHY
    assert "endpoint unhealthy, recorded runs are kept, rerun later" in out
    assert "last error: OSError: connection timed out" in out

    # Exactly the limit was recorded, and they are all kept.
    recorder = Recorder(root=recorded)
    records = recorder.records_for_label("lbl")
    assert len(records) == CONSECUTIVE_ERROR_LIMIT
    assert all(r["status"] == STATUS_ERRORED for r in records)

    # 5 runs at 3 attempts each, and no more.
    assert session.posts == CONSECUTIVE_ERROR_LIMIT * 3


def test_a_successful_run_resets_the_consecutive_counter(tmp_path):
    """Intermittent failures must not abort a healthy run."""
    recorded = tmp_path / "recorded"
    good = json.dumps(
        {
            "claim_type": "NOT_RECEIVED",
            "claimed_amount": "20.00",
            "language": "en",
            "seller_summary": "Buyer reports non-delivery.",
        }
    )

    class Flaky:
        def __init__(self):
            self.posts = 0

        def post(self, url, **kwargs):
            self.posts += 1
            # Fail the first attempt of every other run, succeed otherwise.
            if self.posts % 4 == 1:
                raise OSError("transient")

            class Response:
                status_code = 200
                headers: dict = {}

                def json(self_inner):
                    return {"choices": [{"message": {"content": good}}]}

            return Response()

    settings = model_settings_from(parse_env_file(env_file(tmp_path)))
    outcome = run_live(
        load_corpus()[:6],
        ["orrix"],
        1,
        "lbl",
        settings,
        Recorder(root=recorded),
        max_calls=None,
        session=Flaky(),
    )

    assert outcome.aborted is False
    assert outcome.recorded == 6


def test_the_abort_keeps_what_was_already_recorded(tmp_path):
    recorded = tmp_path / "recorded"
    recorder = Recorder(root=recorded)
    recorder.append(record(attack_id=load_corpus()[0].id, run_index=0))

    class AlwaysFails:
        def post(self, url, **kwargs):
            raise OSError("down")

    settings = model_settings_from(parse_env_file(env_file(tmp_path)))
    outcome = run_live(
        load_corpus()[:10],
        ["orrix"],
        1,
        "lbl",
        settings,
        recorder,
        max_calls=None,
        session=AlwaysFails(),
    )

    assert outcome.aborted is True
    # The pre-existing good record survived.
    records = recorder.records_for_label("lbl")
    assert sum(1 for r in records if r["status"] == STATUS_OK) == 1


# -- an errored run end to end ------------------------------------------


def test_run_orrix_marks_a_transport_failure_as_errored(tmp_path):
    class Down:
        def post(self, url, **kwargs):
            raise OSError("connection refused")

    record_out = run_orrix(
        load_corpus()[0],
        ReaderConfig(base_url=BASE_URL, api_key=SECRET_KEY, model="m",
                     retry_backoff_seconds=0.0),
        0,
        "lbl",
        tmp_path,
        chat_session=Down(),
    )

    assert record_out.status == STATUS_ERRORED
    assert record_out.error_reason == "transport_error"
    assert record_out.system == SYSTEM_ORRIX
    assert record_out.writes == []
    assert record_out.unauthorized_actions == 0
    # The detail is kept, scrubbed.
    assert record_out.failure["exception_class"] == "OSError"
    assert record_out.failure["host"] == HOST
    assert SECRET_KEY not in json.dumps(record_out.as_dict())
    # And elapsed time is recorded for every run.
    assert record_out.elapsed_seconds >= 0


def test_an_errored_orrix_run_is_excluded_from_its_own_report(tmp_path):
    class Down:
        def post(self, url, **kwargs):
            raise OSError("connection refused")

    records = [
        run_orrix(
            attack,
            ReaderConfig(base_url=BASE_URL, api_key=SECRET_KEY, model="m",
                         retry_backoff_seconds=0.0),
            0,
            "lbl",
            tmp_path,
            chat_session=Down(),
        ).as_dict()
        for attack in load_corpus()[:3]
    ]

    report = build_label_report("lbl", records)

    assert report.total_valid_runs == 0
    assert report.total_errored_runs == 3
    assert report.systems_without_valid_runs() == [SYSTEM_ORRIX]
    assert report.unauthorized_display(SYSTEM_ORRIX) == "no valid runs"
