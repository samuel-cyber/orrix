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


def test_no_module_outside_executor_and_paypal_names_a_write_endpoint():
    """Nothing may address a PayPal action endpoint yet."""
    write_paths = (
        "provide-evidence",
        "accept-claim",
        "make-offer",
        "/escalate",
        "send-message",
    )
    offenders: dict[str, list[str]] = {}

    for path in sorted(ORRIX_DIR.glob("*.py")):
        constants = string_constants(parse(path))
        hits = sorted(
            value for value in constants if any(write in value for write in write_paths)
        )
        if hits:
            offenders[path.name] = hits

    assert not offenders, f"PayPal write endpoints referenced: {offenders}"
