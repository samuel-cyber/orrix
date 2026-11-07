"""Whether a recorded run is a result or an endpoint failure.

A run where the model never answered says nothing about the system under
test. Counting it as a result is how 135 connect timeouts turned into a
clean scorecard, so classification lives here and is applied everywhere.
"""

from __future__ import annotations

from typing import Any, Mapping

STATUS_OK = "ok"
STATUS_ERRORED = "errored"

#: Reader reasons that mean no usable response arrived.
READER_NO_RESPONSE = (
    "transport_error",
    "http_error",
    "rate_limited",
    "empty_response",
)

#: Chat errors that mean the same for the baseline agents.
CHAT_NO_RESPONSE = (
    "transport_error",
    "rate_limited",
    "unreadable_response",
    "empty_response",
    "retries_exhausted",
    "http_",
)


def error_reason_of(record: Mapping[str, Any]) -> str | None:
    """The reason a record is errored, or None if it is a usable result.

    Works on records written before `status` existed: it reads the same
    `model_error` field those records already carry, so a legacy record is
    classified by evidence rather than by assumption.
    """
    raw = record.get("model_error")
    if not isinstance(raw, str) or not raw.strip():
        return None

    reason = raw.strip()
    # Chat errors carry the exception class, e.g. transport_error:ConnectTimeout.
    head = reason.split(":", 1)[0]

    if head in READER_NO_RESPONSE:
        return reason
    if any(head.startswith(prefix) for prefix in CHAT_NO_RESPONSE):
        return reason

    # A model that answered badly (invalid_json, schema_invalid) is a result:
    # the system under test handled real output, so the run counts.
    return None


def classify(record: Mapping[str, Any]) -> tuple[str, str | None]:
    """Return (status, error_reason) for a record, stored or legacy."""
    stored = record.get("status")
    if stored in (STATUS_OK, STATUS_ERRORED):
        return stored, record.get("error_reason")

    reason = error_reason_of(record)
    return (STATUS_ERRORED, reason) if reason else (STATUS_OK, None)


def is_errored(record: Mapping[str, Any]) -> bool:
    return classify(record)[0] == STATUS_ERRORED


def is_ok(record: Mapping[str, Any]) -> bool:
    return classify(record)[0] == STATUS_OK


def needs_reclassification(record: Mapping[str, Any]) -> bool:
    """True for a record written before `status` was recorded."""
    return record.get("status") not in (STATUS_OK, STATUS_ERRORED)


def with_status(record: dict[str, Any]) -> dict[str, Any]:
    """A copy carrying an explicit status and error_reason."""
    status, reason = classify(record)
    updated = dict(record)
    updated["status"] = status
    updated["error_reason"] = reason
    return updated
