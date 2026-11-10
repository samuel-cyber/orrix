"""The safety rule: with CARRIER_ENABLED off, nothing changed.

The guarantee this file enforces is stronger than "the flag gates the
feature". It is that a deployment with the flag off is indistinguishable from
one in which orrix/carrier.py does not exist: same facts, same policy
decision, same approval id, no network call, and no new element on the page.

The comparison is made against a real subprocess in which importing
orrix.carrier raises ImportError, so the claim is tested rather than
asserted. If any module in the trusted core -- facts, policy, approval,
executor, config -- ever grows a top-level import of orrix.carrier, the
subprocess fails to build the case and this file goes red.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from .conftest import actionable_snapshot, build_app_config

REPO_ROOT = Path(__file__).parent.parent

# Builds one case and prints a digest of everything that must not move. Run
# both with orrix.carrier importable and with it blocked; the two outputs must
# be byte-identical.
PROBE = """
import json, sys

BLOCK = {blocked!r}

if BLOCK:
    class Blocker:
        def find_module(self, name, path=None):
            return self.find_spec(name, path)

        def find_spec(self, name, path=None, target=None):
            if name == "orrix.carrier" or name.startswith("orrix.carrier."):
                raise ImportError("orrix.carrier is removed from the import path")
            return None

    sys.meta_path.insert(0, Blocker())

from datetime import datetime, timezone

from orrix.approval import DisputeVersion, create_approval
from orrix.executor import build_evidence_payload
from orrix.facts import build_facts
from orrix.policy import PROVIDE_EVIDENCE, CaseState, decide

if BLOCK:
    # Prove the block is real: the module must be unreachable.
    try:
        import orrix.carrier  # noqa: F401
    except ImportError:
        pass
    else:
        print(json.dumps({{"error": "orrix.carrier was importable despite the block"}}))
        raise SystemExit(1)

snapshot = json.load(open(sys.argv[1], encoding="utf-8"))
retrieved = datetime(2026, 10, 30, tzinfo=timezone.utc)

facts = build_facts(
    snapshot, expected_dispute_id=snapshot["dispute_id"], retrieved_at=retrieved
)
payload = build_evidence_payload(facts)
decision = decide(
    facts,
    None,
    CaseState(dispute_id=snapshot["dispute_id"]),
    None,
)
approval = create_approval(
    dispute_id=snapshot["dispute_id"],
    action=PROVIDE_EVIDENCE,
    payload=payload,
    dispute_version=DisputeVersion.from_snapshot(snapshot),
)

print(
    json.dumps(
        {{
            "fact_names": sorted(facts.facts),
            "facts": json.loads(facts.model_dump_json()),
            "payload": payload,
            "allowed_actions": sorted(decision.allowed_actions),
            "reasons": list(decision.reasons),
            "flags": sorted(decision.flags),
            "approval_id": approval.approval_id,
        }},
        sort_keys=True,
    )
)
"""


def run_probe(snapshot_path: Path, blocked: bool) -> dict:
    script = PROBE.format(blocked=blocked)
    completed = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script), str(snapshot_path)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=120,
    )
    assert completed.returncode == 0, (
        f"probe failed (blocked={blocked}):\n{completed.stdout}\n{completed.stderr}"
    )
    return json.loads(completed.stdout.strip().splitlines()[-1])


@pytest.fixture
def snapshot_file(tmp_path):
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(actionable_snapshot()), encoding="utf-8")
    return path


# -- the central guarantee ------------------------------------------------


def test_facts_policy_and_approval_id_survive_removing_the_carrier_module(snapshot_file):
    """The whole safety rule, in one comparison."""
    with_module = run_probe(snapshot_file, blocked=False)
    without_module = run_probe(snapshot_file, blocked=True)

    assert "error" not in without_module
    assert with_module == without_module


def test_the_approval_id_is_identical_either_way(snapshot_file):
    """Called out separately so a failure names the thing that matters."""
    with_module = run_probe(snapshot_file, blocked=False)
    without_module = run_probe(snapshot_file, blocked=True)

    assert with_module["approval_id"] == without_module["approval_id"]
    assert with_module["facts"] == without_module["facts"]
    assert with_module["allowed_actions"] == without_module["allowed_actions"]
    assert with_module["reasons"] == without_module["reasons"]


def test_no_carrier_fact_exists_on_a_case_built_without_a_lookup(snapshot_file):
    names = run_probe(snapshot_file, blocked=False)["fact_names"]

    assert "carrier_status" not in names
    assert "carrier_delivered_at" not in names


# -- the trusted core does not depend on the module -----------------------


CORE_MODULES = (
    "facts.py",
    "policy.py",
    "approval.py",
    "executor.py",
    "discrepancy.py",
    "config.py",
    "pipeline.py",
    "reader.py",
)


@pytest.mark.parametrize("filename", CORE_MODULES)
def test_no_core_module_imports_the_carrier_at_module_scope(filename):
    """A top-level import here would break the removal guarantee.

    config.py is allowed to build a CarrierConfig, but only through a
    function-scope import, which is why this check is textual and anchored to
    the top level of the file.
    """
    import ast

    source = (REPO_ROOT / "orrix" / filename).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=filename)

    offenders = []
    for node in tree.body:  # module scope only
        if isinstance(node, ast.Import):
            offenders += [a.name for a in node.names if "carrier" in a.name]
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.endswith("carrier") or module == "carrier":
                offenders.append(module)

    assert not offenders, (
        f"{filename} imports the carrier module at module scope: {offenders}. "
        f"The trusted core must build identically with orrix/carrier.py deleted."
    )


def test_the_reader_never_sees_a_carrier_module():
    """The Reader has no tools, and the carrier is not an exception."""
    import ast

    source = (REPO_ROOT / "orrix" / "reader.py").read_text(encoding="utf-8")
    assert "carrier" not in source.lower()


# -- the flag off, through the real app -----------------------------------


def test_the_case_page_shows_no_carrier_card_with_the_flag_off(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from orrix import store
    from orrix.carrier import FakeCarrierClient
    from orrix.main import create_app

    monkeypatch.setenv("ORRIX_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("POLLER_ENABLED", "false")
    store.init_db()

    snapshot = actionable_snapshot()
    store.save_case_snapshot(snapshot["dispute_id"], snapshot)

    spy = FakeCarrierClient({"tag": "Delivered"})
    config = build_app_config(tmp_path, carrier_enabled=False)

    with TestClient(create_app(config=config, carrier_client=spy)) as client:
        client.post("/login", data={"password": "test-admin-password"}, follow_redirects=False)
        page = client.get(f"/cases/{snapshot['dispute_id']}")

    assert page.status_code == 200
    assert "Carrier check" not in page.text
    assert "carrier_reported" not in page.text
    assert "carrier-reported" not in page.text
    # And nothing was asked of the provider.
    assert spy.call_count == 0


def test_a_disabled_connector_refuses_the_check_endpoint(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from orrix import store
    from orrix.carrier import FakeCarrierClient
    from orrix.main import create_app
    from orrix.web.security import CSRF_FIELD

    monkeypatch.setenv("ORRIX_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("POLLER_ENABLED", "false")
    store.init_db()

    snapshot = actionable_snapshot()
    store.save_case_snapshot(snapshot["dispute_id"], snapshot)

    spy = FakeCarrierClient({"tag": "Delivered"})
    config = build_app_config(tmp_path, carrier_enabled=False)

    with TestClient(create_app(config=config, carrier_client=spy)) as client:
        client.post("/login", data={"password": "test-admin-password"}, follow_redirects=False)
        page = client.get(f"/cases/{snapshot['dispute_id']}")
        token = _csrf_from(page.text)
        posted = client.post(
            f"/cases/{snapshot['dispute_id']}/check-carrier",
            data={CSRF_FIELD: token},
            follow_redirects=False,
        )

    assert posted.status_code == 303
    assert spy.call_count == 0


def _csrf_from(html: str) -> str:
    import re

    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return match.group(1) if match else ""
