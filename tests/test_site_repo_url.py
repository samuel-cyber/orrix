"""The repository links must point at the real repository.

The landing page and the evaluation page both link to the project's
repository. The URL used to default to a placeholder, repeated as a literal
in two places in orrix/config.py, so any deployment without SITE_REPO_URL set
advertised github.com/example/orrix.

The default is now the real URL, SITE_REPO_URL remains an optional override
for a fork, and the last test here fails if the placeholder reappears
anywhere in tracked files.
"""

from __future__ import annotations

import re
import subprocess

import pytest
from fastapi.testclient import TestClient

from orrix import store
from orrix.config import DEFAULT_SITE_REPO_URL, AppConfig, load_config
from orrix.main import create_app

from .conftest import ADMIN_PASSWORD, build_app_config

REAL_URL = "https://github.com/samuel-cyber/orrix"
PLACEHOLDER = "example/orrix"


# -- the default ----------------------------------------------------------


def test_the_default_is_the_real_repository():
    assert DEFAULT_SITE_REPO_URL == REAL_URL
    assert AppConfig().site_repo_url == REAL_URL


def test_the_default_applies_with_no_environment_variable(monkeypatch):
    monkeypatch.delenv("SITE_REPO_URL", raising=False)

    assert load_config().site_repo_url == REAL_URL


def test_the_environment_variable_still_overrides(monkeypatch):
    monkeypatch.setenv("SITE_REPO_URL", "https://github.com/someone/fork")

    assert load_config().site_repo_url == "https://github.com/someone/fork"


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_a_blank_value_is_treated_as_unset(monkeypatch, blank):
    """A variable left empty in a dashboard must not blank the href."""
    monkeypatch.setenv("SITE_REPO_URL", blank)

    assert load_config().site_repo_url == REAL_URL


def test_a_value_with_stray_whitespace_is_trimmed(monkeypatch):
    monkeypatch.setenv("SITE_REPO_URL", "  https://github.com/someone/fork  ")

    assert load_config().site_repo_url == "https://github.com/someone/fork"


# -- the pages ------------------------------------------------------------


@pytest.fixture
def pages(tmp_path, monkeypatch):
    monkeypatch.setenv("ORRIX_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("POLLER_ENABLED", "false")
    store.init_db()

    def render(**overrides):
        config = build_app_config(tmp_path, **overrides)
        with TestClient(create_app(config=config)) as client:
            landing = client.get("/")
            client.post(
                "/login", data={"password": ADMIN_PASSWORD}, follow_redirects=False
            )
            evaluation = client.get("/evaluation")
        return landing, evaluation

    return render


def github_links(html: str) -> set[str]:
    return set(re.findall(r'href="(https://github\.com[^"]*)"', html))


def test_the_landing_page_links_to_the_real_repository(pages):
    landing, _ = pages()

    links = github_links(landing.text)

    assert links, "the landing page carries no repository link at all"
    assert all(link.startswith(REAL_URL) for link in links), links
    assert PLACEHOLDER not in landing.text


def test_both_the_repository_and_source_links_are_correct(pages):
    """Two separate links on the landing page, and both were wrong."""
    landing, _ = pages()

    assert landing.text.count(REAL_URL) >= 2
    for label in ("Repository", "Source"):
        assert label in landing.text


def test_the_evaluation_page_links_to_the_real_repository(pages):
    _, evaluation = pages()

    links = github_links(evaluation.text)

    assert links
    assert all(link.startswith(REAL_URL) for link in links), links
    assert PLACEHOLDER not in evaluation.text


def test_an_override_reaches_every_page(pages):
    """Proof the plumbing works, which is why the default mattered."""
    forked = "https://github.com/someone/fork"
    landing, evaluation = pages(site_repo_url=forked)

    assert github_links(landing.text) == {forked}
    assert all(link.startswith(forked) for link in github_links(evaluation.text))


# -- the placeholder may not come back ------------------------------------


def tracked_files() -> list[str]:
    """Every file git tracks. notes/ is git-ignored, so it is never listed."""
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        capture_output=True,
        text=True,
        cwd=str(_repo_root()),
        timeout=120,
        check=True,
    )
    return [name for name in completed.stdout.split("\0") if name]


def _repo_root():
    from pathlib import Path

    return Path(__file__).parent.parent


def test_the_placeholder_appears_in_no_tracked_file():
    """Fails if github.com/example/orrix reappears anywhere.

    Covers templates, static assets, docs, README, pyproject, render.yaml,
    the LICENSE and the tests themselves -- this file excepted, since it has
    to name the string in order to forbid it. notes/ is git-ignored and
    therefore outside the scan by construction.
    """
    root = _repo_root()
    this_file = "tests/" + __file__.replace("\\", "/").rsplit("/", 1)[-1]

    offenders: dict[str, list[int]] = {}
    for name in tracked_files():
        if name == this_file:
            continue
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # a binary file cannot carry the placeholder readably

        hits = [
            number
            for number, line in enumerate(text.splitlines(), start=1)
            if PLACEHOLDER in line or "github.com/example" in line
        ]
        if hits:
            offenders[name] = hits

    assert not offenders, (
        f"the placeholder repository URL is back in: {offenders}. Use "
        f"{REAL_URL}, or orrix.config.DEFAULT_SITE_REPO_URL."
    )


def test_the_scan_actually_reads_files():
    """A scan that silently matched nothing would pass forever."""
    names = tracked_files()

    assert "README.md" in names
    assert "orrix/config.py" in names
    assert "render.yaml" in names
    assert "orrix/web/templates/landing.html" in names
    # And notes/ is git-ignored, so it is outside the scan.
    assert not any(name.startswith("notes/") for name in names)


def test_no_tracked_file_names_another_placeholder_owner():
    """The obvious neighbours of example/orrix."""
    root = _repo_root()
    this_file = "tests/" + __file__.replace("\\", "/").rsplit("/", 1)[-1]
    patterns = ("your-org/", "YOUR_ORG", "<owner>", "example.com/orrix")

    offenders: dict[str, list[str]] = {}
    for name in tracked_files():
        if name == this_file:
            continue
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        found = [pattern for pattern in patterns if pattern in text]
        if found:
            offenders[name] = found

    assert not offenders, f"placeholder owner names present: {offenders}"
