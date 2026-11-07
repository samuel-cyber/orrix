"""Describing a failed HTTP call without leaking anything.

A transport exception's message routinely quotes the full URL, and some
clients include request headers. Both are unsafe to log here: the URL can
carry a query string and the headers carry the bearer token. Everything in
this module reduces a failure to the host, a class name, and a scrubbed
message, so a log line is useful without being dangerous.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

MAX_MESSAGE_CHARS = 200

# Anything that looks like a credential or a full URL is removed before a
# message is logged. Order matters: URLs first, then bearer tokens, then
# long opaque strings that could be a key.
_SCRUBBERS = (
    (re.compile(r"https?://[^\s'\"]+", re.IGNORECASE), "<url>"),
    (re.compile(r"\b[Bb]earer\s+\S+"), "Bearer <redacted>"),
    (re.compile(r"\b(?:sk|api|key|token)[-_][A-Za-z0-9_\-]{8,}\b", re.IGNORECASE), "<redacted>"),
    (re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"), "<redacted>"),
)


def host_of(url: Any) -> str:
    """Just the host. Never the path, the query, or the scheme's userinfo."""
    if not isinstance(url, str) or not url.strip():
        return "unknown"
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return "unknown"
    host = parts.hostname or ""
    return host or "unknown"


def scrub(message: Any) -> str:
    """A message safe to log: no URLs, no tokens, length-capped."""
    text = "" if message is None else str(message)
    for pattern, replacement in _SCRUBBERS:
        text = pattern.sub(replacement, text)
    text = " ".join(text.split())
    if len(text) > MAX_MESSAGE_CHARS:
        text = text[:MAX_MESSAGE_CHARS] + "…"
    return text


def status_of(error: BaseException) -> int | None:
    """An HTTP status carried on the exception, if the client attached one."""
    response = getattr(error, "response", None)
    status = getattr(response, "status_code", None)
    return status if isinstance(status, int) else None


@dataclass(frozen=True)
class FailureDetail:
    """What a failed call is allowed to say about itself."""

    exception_class: str
    message: str
    http_status: int | None
    host: str
    attempt: int
    elapsed_seconds: float

    def log_fields(self) -> str:
        """A fixed-shape fragment for a log line."""
        return (
            "exception=%s message=%r http_status=%s host=%s attempt=%s elapsed=%.2fs"
            % (
                self.exception_class,
                self.message,
                self.http_status,
                self.host,
                self.attempt,
                self.elapsed_seconds,
            )
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "exception_class": self.exception_class,
            "message": self.message,
            "http_status": self.http_status,
            "host": self.host,
            "attempt": self.attempt,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }


def describe(
    error: BaseException, url: Any, attempt: int, elapsed_seconds: float
) -> FailureDetail:
    """Reduce an exception to the facts that are safe to record."""
    return FailureDetail(
        exception_class=type(error).__name__,
        message=scrub(error),
        http_status=status_of(error),
        host=host_of(url),
        attempt=attempt,
        elapsed_seconds=elapsed_seconds,
    )


def retry_after_seconds(response: Any, default: float) -> float:
    """Honour a Retry-After header when the server sends a usable one."""
    headers = getattr(response, "headers", None)
    if not headers:
        return default
    try:
        raw = headers.get("Retry-After")
    except Exception:
        return default
    if raw is None:
        return default
    try:
        seconds = float(str(raw).strip())
    except (TypeError, ValueError):
        # An HTTP-date form is valid but not worth parsing here; the caller's
        # own backoff is a safe answer.
        return default
    if seconds < 0:
        return default
    # Cap it: a server asking for an hour should not hang an evaluation run.
    return min(seconds, 60.0)
