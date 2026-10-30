"""Static checks on the trust boundary.

These read the source with ast rather than importing it, so a violation is
caught even if the offending import sits behind a condition or a function.
The rule in CLAUDE.md is prose; this file is what makes it enforceable.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ORRIX_DIR = Path(__file__).parent.parent / "orrix"

# Modules the untrusted-text side may never reach. paypal and executor give a
# path to PayPal; store, poller and webhooks give a path to persisted state
# and to the ingest loop.
FORBIDDEN_FOR_UNTRUSTED = (
    "orrix.paypal",
    "orrix.executor",
    "orrix.store",
    "orrix.poller",
    "orrix.webhooks",
)

# Modules that handle untrusted buyer text.
UNTRUSTED_SIDE = ("reader.py", "claim_form.py")

# Any of these in reader.py or claim_form.py means credentials are being read
# somewhere they should not be.
CREDENTIAL_READERS = ("os.environ", "os.getenv", "dotenv", "load_dotenv")
CREDENTIAL_NAMES = (
    "PAYPAL_CLIENT_ID",
    "PAYPAL_CLIENT_SECRET",
    "PAYPAL_WEBHOOK_ID",
)


def parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def imported_modules(tree: ast.Module, package: str = "orrix") -> set[str]:
    """Every module name imported, with relative imports resolved."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # `from . import store` / `from .paypal import X`
                base = package if node.module is None else f"{package}.{node.module}"
                found.add(base)
                for alias in node.names:
                    found.add(f"{base}.{alias.name}")
            elif node.module:
                found.add(node.module)
                for alias in node.names:
                    found.add(f"{node.module}.{alias.name}")
    return found


def dotted_attribute_calls(tree: ast.Module) -> set[str]:
    """Dotted names used anywhere, e.g. `os.environ`, `os.getenv`."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            found.add(f"{node.value.id}.{node.attr}")
    return found


def string_constants(tree: ast.Module) -> set[str]:
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }


@pytest.mark.parametrize("filename", UNTRUSTED_SIDE)
def test_untrusted_modules_import_no_privileged_module(filename):
    path = ORRIX_DIR / filename
    imports = imported_modules(parse(path))

    offenders = sorted(
        name
        for name in imports
        if any(name == bad or name.startswith(bad + ".") for bad in FORBIDDEN_FOR_UNTRUSTED)
    )
    assert not offenders, (
        f"{filename} imports {', '.join(offenders)}. Modules handling untrusted "
        f"buyer text must not import any of: {', '.join(FORBIDDEN_FOR_UNTRUSTED)}."
    )


@pytest.mark.parametrize("filename", UNTRUSTED_SIDE)
def test_untrusted_modules_never_read_credentials(filename):
    path = ORRIX_DIR / filename
    tree = parse(path)
    imports = imported_modules(tree)
    attributes = dotted_attribute_calls(tree)
    constants = string_constants(tree)

    offenders = sorted(
        {name for name in attributes if name in CREDENTIAL_READERS}
        | {name for name in imports if any(bad in name for bad in CREDENTIAL_READERS)}
        | {name for name in constants if name in CREDENTIAL_NAMES}
    )
    assert not offenders, (
        f"{filename} reaches for credentials via {', '.join(offenders)}. It must take a "
        f"config object from its caller instead of reading the environment."
    )


@pytest.mark.parametrize("filename", UNTRUSTED_SIDE)
def test_untrusted_modules_make_no_paypal_request(filename):
    path = ORRIX_DIR / filename
    tree = parse(path)
    constants = string_constants(tree)

    offenders = sorted(
        value
        for value in constants
        if "paypal.com" in value.lower() or "/v1/customer/disputes" in value
    )
    assert not offenders, (
        f"{filename} references a PayPal endpoint: {', '.join(offenders)}. "
        f"Only orrix.paypal may address PayPal, and only orrix.executor may write."
    )


def test_facts_never_imports_the_reader():
    imports = imported_modules(parse(ORRIX_DIR / "facts.py"))

    offenders = sorted(
        name for name in imports if name == "orrix.reader" or name.startswith("orrix.reader.")
    )
    assert not offenders, (
        f"facts.py imports {', '.join(offenders)}. Facts are built from PayPal records "
        f"only; pulling in the reader would let model output become a fact."
    )


def test_reader_does_not_import_facts_either():
    """Symmetry: the reader has no business seeing trusted facts."""
    imports = imported_modules(parse(ORRIX_DIR / "reader.py"))

    assert not [n for n in imports if n.startswith("orrix.facts")], (
        "reader.py imports orrix.facts. The reader receives only buyer text and "
        "the amount ceiling."
    )


def test_buyer_text_is_read_in_exactly_one_module():
    """Only reader.py may name the keys that hold buyer prose."""
    buyer_text_keys = {"posted_by", "SUBMITTED_BY_BUYER"}
    offenders: dict[str, set[str]] = {}

    for path in sorted(ORRIX_DIR.glob("*.py")):
        if path.name == "reader.py":
            continue
        found = string_constants(parse(path)) & buyer_text_keys
        if found:
            offenders[path.name] = found

    assert not offenders, (
        f"Buyer-text keys appear outside reader.py: {offenders}. extract_buyer_text "
        f"must be the only place that reads buyer prose."
    )


def test_reader_requests_no_tools_or_function_calling():
    """The reader's request must offer the model no way to act."""
    tree = parse(ORRIX_DIR / "reader.py")
    constants = string_constants(tree)

    forbidden = {"tools", "tool_choice", "functions", "function_call", "tool_calls"}
    offenders = sorted(constants & forbidden)
    assert not offenders, (
        f"reader.py mentions {', '.join(offenders)}. The reader sends one "
        f"chat-completions request with no tools and no function calling."
    )


# -- write capability ---------------------------------------------------

# Modules that must never be able to write to PayPal.
NO_WRITE_CAPABILITY = (
    "reader.py",
    "facts.py",
    "claim_form.py",
    "investigator.py",
    "policy.py",
    "approval.py",
    "audit.py",
    "webhooks.py",
    "poller.py",
    "store.py",
)


def test_only_the_executor_imports_write_capability():
    """orrix.paypal_write may have exactly one importer."""
    importers = []
    for path in sorted(ORRIX_DIR.glob("*.py")):
        imports = imported_modules(parse(path))
        if any(name.startswith("orrix.paypal_write") for name in imports):
            importers.append(path.name)

    assert importers == ["executor.py"], (
        f"orrix.paypal_write is imported by {importers}. Only executor.py may hold "
        f"write capability."
    )


@pytest.mark.parametrize("filename", NO_WRITE_CAPABILITY)
def test_modules_without_write_capability_do_not_import_it(filename):
    path = ORRIX_DIR / filename
    if not path.is_file():
        pytest.skip(f"{filename} does not exist yet")

    imports = imported_modules(parse(path))
    offenders = sorted(
        name
        for name in imports
        if name.startswith("orrix.paypal_write") or name.startswith("orrix.executor")
    )
    assert not offenders, (
        f"{filename} imports {', '.join(offenders)}. Write capability belongs to "
        f"executor.py alone."
    )


@pytest.mark.parametrize("filename", ("reader.py", "investigator.py"))
def test_reader_and_investigator_cannot_create_an_approval(filename):
    """Granting authority is a human act, not something a model path reaches."""
    path = ORRIX_DIR / filename
    if not path.is_file():
        pytest.skip(f"{filename} does not exist yet")

    tree = parse(path)
    imports = imported_modules(tree)
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    } | {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }

    offenders = sorted(
        {name for name in imports if name.startswith("orrix.approval")}
        | ({"create_approval"} if "create_approval" in called else set())
    )
    assert not offenders, (
        f"{filename} reaches approval creation via {', '.join(offenders)}. Only a path "
        f"a human actually travelled may create an Approval."
    )


def test_the_writer_module_names_no_live_paypal_host():
    constants = string_constants(parse(ORRIX_DIR / "paypal_write.py"))

    offenders = sorted(
        value
        for value in constants
        if "paypal.com" in value.lower() and "api-m.sandbox.paypal.com" not in value
    )
    assert not offenders, f"paypal_write.py names a non-sandbox host: {offenders}"


def test_policy_consults_no_model():
    """Policy is plain code; it may not reach any model client."""
    tree = parse(ORRIX_DIR / "policy.py")
    imports = imported_modules(tree)

    offenders = sorted(
        name
        for name in imports
        if any(
            bad in name.lower()
            for bad in ("anthropic", "openai", "orrix.reader", "requests", "httpx")
        )
    )
    assert not offenders, f"policy.py imports {offenders}; it must be plain code."


def test_only_paypal_write_names_a_write_endpoint():
    """One module may address a PayPal action endpoint, and only one."""
    write_paths = (
        "provide-evidence",
        "accept-claim",
        "make-offer",
        "/escalate",
        "send-message",
    )
    offenders: dict[str, list[str]] = {}

    for path in sorted(ORRIX_DIR.glob("*.py")):
        if path.name == "paypal_write.py":
            continue
        constants = string_constants(parse(path))
        hits = sorted(
            value for value in constants if any(write in value for write in write_paths)
        )
        if hits:
            offenders[path.name] = hits

    assert not offenders, (
        f"PayPal write endpoints referenced outside paypal_write.py: {offenders}"
    )


def test_the_only_write_endpoint_is_provide_evidence():
    """paypal_write.py must offer no money-moving endpoint."""
    constants = string_constants(parse(ORRIX_DIR / "paypal_write.py"))
    forbidden = ("accept-claim", "make-offer", "/escalate", "send-message", "/refund")

    offenders = sorted(
        value for value in constants if any(bad in value for bad in forbidden)
    )
    assert not offenders, (
        f"paypal_write.py names a money-moving endpoint: {offenders}. v3 submits "
        f"evidence and nothing else."
    )
