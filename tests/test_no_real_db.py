"""Proves the suite never opens the operational database.

The proof is a guard on sqlite3.connect, installed around every test by
conftest.forbid_the_real_database. That is checked at the connection rather
than by comparing orrix.db afterwards: the running application writes to it
on its own schedule, so a file-state comparison would fail for reasons that
have nothing to do with the test suite.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from .conftest import REAL_DB_PATH, _is_real_db

REPO_ROOT = Path(__file__).parent.parent

GUARDED_TABLES = (
    "audit_log",
    "audit_head",
    "events",
    "cases",
    "case_views",
    "executed_approvals",
)


# -- the guard is installed and fires ----------------------------------


def test_opening_the_real_database_fails_the_test():
    """The guard itself, exercised deliberately."""
    with pytest.raises(AssertionError, match="operational database"):
        sqlite3.connect(str(REAL_DB_PATH))


def test_the_guard_catches_a_relative_path():
    with pytest.raises(AssertionError, match="operational database"):
        sqlite3.connect("orrix.db")


def test_the_guard_catches_a_file_uri():
    with pytest.raises(AssertionError, match="operational database"):
        sqlite3.connect(f"file:{REAL_DB_PATH}?mode=ro", uri=True)


def test_the_guard_allows_temporary_databases(tmp_path):
    connection = sqlite3.connect(str(tmp_path / "fine.db"))
    connection.close()

    connection = sqlite3.connect(":memory:")
    connection.close()


def test_path_matching_handles_odd_inputs():
    assert _is_real_db(str(REAL_DB_PATH)) is True
    assert _is_real_db("orrix.db") is True
    assert _is_real_db(":memory:") is False
    assert _is_real_db("") is False
    assert _is_real_db(None) is False
    assert _is_real_db(42) is False
    assert _is_real_db("/tmp/other.db") is False


# -- the application's own components land in temporary files ----------


def test_the_configured_db_path_is_never_the_real_one():
    configured = os.environ.get("ORRIX_DB_PATH", "")

    assert configured, "ORRIX_DB_PATH must be set during tests"
    assert Path(configured).resolve() != REAL_DB_PATH


def test_store_writes_land_in_the_temporary_database():
    """A real write through the app's own store, with the guard watching."""
    from orrix import store

    store.init_db()
    store.save_case_snapshot("PP-R-GUARD-0001", {"dispute_id": "PP-R-GUARD-0001"})

    assert store.get_case("PP-R-GUARD-0001") is not None
    assert Path(store.db_path()).resolve() != REAL_DB_PATH


def test_an_audit_log_lands_in_its_own_file(tmp_path):
    from orrix.audit import AuditConfig, AuditLog, OriginTag

    log = AuditLog(AuditConfig(db_path=str(tmp_path / "audit.db")))
    log.append(actor="test", action="guard.check", origin_tag=OriginTag.SYSTEM)

    assert (tmp_path / "audit.db").is_file()
    assert log.verify_chain() is None
    assert Path(log.config.db_path).resolve() != REAL_DB_PATH


def test_the_web_app_under_test_uses_a_temporary_database(client):
    """The whole app, started through create_app, with the guard active."""
    assert client.get("/health").status_code == 200

    services = client.app.state.services
    assert Path(services.config.db_path).resolve() != REAL_DB_PATH
    assert Path(services.audit.config.db_path).resolve() != REAL_DB_PATH


def test_an_evaluation_run_uses_a_temporary_directory(tmp_path):
    """run_orrix must keep its audit and approval stores under tmp_dir."""
    from attacks.corpus import load_corpus
    from attacks.systems import run_orrix
    from orrix.policy import PolicyConfig
    from datetime import datetime, timezone
    import json

    class StubSession:
        def post(self, url, **kwargs):
            class Response:
                status_code = 200
                headers: dict = {}

                def json(self_inner):
                    return {
                        "choices": [
                            {
                                "message": {
                                    "content": json.dumps(
                                        {
                                            "claim_type": "NOT_RECEIVED",
                                            "claimed_amount": "20.00",
                                            "language": "en",
                                            "seller_summary": "Buyer reports non-delivery.",
                                        }
                                    )
                                }
                            }
                        ]
                    }

            return Response()

    record = run_orrix(
        load_corpus()[0],
        __import__("orrix.reader", fromlist=["ReaderConfig"]).ReaderConfig(
            base_url="https://model.example.invalid/v1", api_key="sk-x", model="m"
        ),
        0,
        "guard",
        tmp_path,
        chat_session=StubSession(),
        policy_config=PolicyConfig(clock=lambda: datetime(2026, 10, 30, tzinfo=timezone.utc)),
    )

    # The guard would have failed the test if anything touched orrix.db.
    assert record.unauthorized_actions == 0
    assert any(tmp_path.rglob("audit.db"))
    assert any(tmp_path.rglob("executed.db"))


# -- static checks -----------------------------------------------------


def test_the_harness_never_names_the_real_database():
    offenders: list[str] = []
    for directory in ("attacks", "baselines"):
        for path in sorted((REPO_ROOT / directory).rglob("*.py")):
            if "orrix.db" in path.read_text(encoding="utf-8"):
                offenders.append(str(path.relative_to(REPO_ROOT)))

    assert not offenders, (
        f"the harness names the operational database: {offenders}. Evaluation "
        f"runs must use a temporary directory."
    )


def test_no_test_module_names_the_real_database_except_this_guard():
    # test_empty_db_sync.py is about the path resolution itself, so it has
    # to name the file; it only ever uses paths under tmp_path.
    allowed = {"test_no_real_db.py", "conftest.py", "test_empty_db_sync.py"}
    offenders: list[str] = []

    for path in sorted((REPO_ROOT / "tests").rglob("*.py")):
        if path.name in allowed:
            continue
        if "orrix.db" in path.read_text(encoding="utf-8"):
            offenders.append(path.name)

    assert not offenders, f"test modules naming the real database: {offenders}"
