"""One OpenAI-compatible chat client for every system under test.

Takes a config object; reads no environment. The API key is held with
repr=False and never logged, and every call goes through a budget so a run
cannot quietly spend more credits than the operator authorised.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from orrix.errors import FailureDetail, describe, host_of, retry_after_seconds

logger = logging.getLogger("attacks.chat")

#: A hard ceiling for evaluation calls. Deliberately short: a three-hour run
#: of silent connect timeouts is worse than a fast, visible failure. This is
#: the harness's own default and does not change the production Reader.
EVAL_TIMEOUT_SECONDS = 20.0


@dataclass(frozen=True)
class ChatConfig:
    """Model access for the harness. Built by the CLI from an env file."""

    base_url: str
    api_key: str = field(repr=False)
    model: str
    timeout: float = EVAL_TIMEOUT_SECONDS
    max_retries: int = 3
    backoff_seconds: float = 1.0
    #: Delay before each retry, in order; three attempts in total.
    retry_backoff_schedule: tuple[float, ...] = (1.0, 3.0)
    temperature: float = 0.0

    @property
    def max_attempts(self) -> int:
        return len(self.retry_backoff_schedule) + 1

    def backoff_for(self, retry_number: int) -> float:
        if retry_number < 1 or not self.retry_backoff_schedule:
            return 0.0
        index = min(retry_number, len(self.retry_backoff_schedule)) - 1
        return self.retry_backoff_schedule[index] * self.backoff_seconds

    @property
    def completions_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/chat/completions"


class BudgetExhausted(RuntimeError):
    """The authorised call budget is spent. Stop cleanly, do not continue."""


@dataclass
class CallBudget:
    """Hard ceiling on model calls for one invocation of the harness."""

    max_calls: int | None = None
    used: int = 0

    @property
    def remaining(self) -> int | None:
        if self.max_calls is None:
            return None
        return max(self.max_calls - self.used, 0)

    @property
    def exhausted(self) -> bool:
        return self.max_calls is not None and self.used >= self.max_calls

    def consume(self) -> None:
        if self.exhausted:
            raise BudgetExhausted(f"call budget of {self.max_calls} is spent")
        self.used += 1


#: Errors that mean the endpoint never gave a usable answer.
NO_RESPONSE_ERRORS = ("transport_error", "rate_limited", "unreadable_response",
                      "empty_response", "retries_exhausted")


@dataclass(frozen=True)
class ChatResult:
    text: str | None
    status_code: int | None
    attempts: int
    error: str | None = None
    #: Scrubbed detail of the last transport failure, when there was one.
    failure: FailureDetail | None = None

    @property
    def ok(self) -> bool:
        return self.text is not None and self.error is None

    @property
    def model_never_answered(self) -> bool:
        """True when nothing usable came back, including any HTTP error."""
        if self.ok:
            return False
        reason = self.error or ""
        return reason.startswith("http_") or reason.startswith(NO_RESPONSE_ERRORS)


class ChatClient:
    """Sends one chat-completions request, with 429 backoff.

    `session` is injectable so tests never touch the network. Errors are
    reported as codes: no response body reaches a log line, because a body
    can echo the prompt and the prompt contains attack text.
    """

    def __init__(
        self,
        config: ChatConfig,
        session: Any | None = None,
        budget: CallBudget | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.config = config
        self.budget = budget or CallBudget()
        self._session = session
        self._sleep = sleep

    def _client(self) -> Any:
        if self._session is None:
            import requests

            self._session = requests.Session()
        return self._session

    def complete(self, messages: Sequence[dict[str, str]]) -> ChatResult:
        payload = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "messages": list(messages),
        }
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

        attempts = 0
        transport_retries = 0
        rate_limited = 0
        server_errors = 0
        ceiling = self.config.max_attempts
        host = host_of(self.config.completions_url)
        last_failure: FailureDetail | None = None

        while attempts < ceiling:
            # Every attempt costs a call, including a retry.
            self.budget.consume()
            attempts += 1
            started = time.monotonic()
            try:
                response = self._client().post(
                    self.config.completions_url,
                    headers=headers,
                    json=payload,
                    timeout=self.config.timeout,
                )
            except Exception as error:
                elapsed = time.monotonic() - started
                last_failure = describe(
                    error, self.config.completions_url, attempts, elapsed
                )
                logger.warning(
                    "chat status=transport_error " + last_failure.log_fields()
                )
                transport_retries += 1
                if transport_retries < ceiling:
                    delay = self.config.backoff_for(transport_retries)
                    logger.info("chat backoff=%ss before attempt=%s", delay, attempts + 1)
                    self._sleep(delay)
                    continue
                return ChatResult(
                    text=None,
                    status_code=None,
                    attempts=attempts,
                    error=f"transport_error:{last_failure.exception_class}",
                    failure=last_failure,
                )

            elapsed = time.monotonic() - started
            status = getattr(response, "status_code", None)

            if status == 429:
                if rate_limited < ceiling - 1:
                    rate_limited += 1
                    delay = retry_after_seconds(
                        response, self.config.backoff_for(rate_limited)
                    )
                    logger.info(
                        "chat http_status=429 backoff=%ss attempt=%s host=%s elapsed=%.2fs",
                        delay,
                        attempts,
                        host,
                        elapsed,
                    )
                    self._sleep(delay)
                    continue
                logger.warning(
                    "chat status=rate_limited attempts=%s host=%s elapsed=%.2fs",
                    attempts,
                    host,
                    elapsed,
                )
                return ChatResult(None, 429, attempts, error="rate_limited")

            # 5xx is the server failing; worth another attempt. 4xx is not.
            if isinstance(status, int) and 500 <= status < 600 and server_errors < ceiling - 1:
                server_errors += 1
                delay = retry_after_seconds(response, self.config.backoff_for(server_errors))
                logger.info(
                    "chat http_status=%s backoff=%ss attempt=%s host=%s elapsed=%.2fs",
                    status,
                    delay,
                    attempts,
                    host,
                    elapsed,
                )
                self._sleep(delay)
                continue

            if status != 200:
                logger.warning(
                    "chat status=http_error http_status=%s attempts=%s host=%s elapsed=%.2fs",
                    status,
                    attempts,
                    host,
                    elapsed,
                )
                return ChatResult(None, status, attempts, error=f"http_{status}")

            try:
                body = response.json()
                text = body["choices"][0]["message"]["content"]
            except Exception:
                logger.warning("chat unreadable_response attempts=%s", attempts)
                return ChatResult(None, status, attempts, error="unreadable_response")

            if not isinstance(text, str):
                return ChatResult(None, status, attempts, error="empty_response")

            return ChatResult(text=text, status_code=status, attempts=attempts)

        return ChatResult(None, None, attempts, error="retries_exhausted")


_FENCE_PREFIXES = ("```json", "```")


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Best-effort JSON object from a model reply.

    Strips a code fence and, failing that, takes the first balanced brace
    span. This is deliberately generous: the point of the baselines is to
    give a weaker design its best shot, so a formatting slip is not counted
    as a refusal.
    """
    if not isinstance(text, str):
        return None

    candidate = text.strip()
    for prefix in _FENCE_PREFIXES:
        if candidate.startswith(prefix):
            candidate = candidate[len(prefix) :]
            if candidate.endswith("```"):
                candidate = candidate[:-3]
            candidate = candidate.strip()
            break

    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else None
    except ValueError:
        pass

    start = candidate.find("{")
    while start != -1:
        depth = 0
        for index in range(start, len(candidate)):
            if candidate[index] == "{":
                depth += 1
            elif candidate[index] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(candidate[start : index + 1])
                        if isinstance(parsed, dict):
                            return parsed
                    except ValueError:
                        break
        start = candidate.find("{", start + 1)
    return None
