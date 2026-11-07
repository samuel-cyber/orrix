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

logger = logging.getLogger("attacks.chat")


@dataclass(frozen=True)
class ChatConfig:
    """Model access for the harness. Built by the CLI from an env file."""

    base_url: str
    api_key: str = field(repr=False)
    model: str
    timeout: float = 60.0
    max_retries: int = 3
    backoff_seconds: float = 2.0
    temperature: float = 0.0

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


@dataclass(frozen=True)
class ChatResult:
    text: str | None
    status_code: int | None
    attempts: int
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.text is not None and self.error is None


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
        rate_limited = 0
        ceiling = self.config.max_retries + 2

        while attempts < ceiling:
            self.budget.consume()
            attempts += 1
            try:
                response = self._client().post(
                    self.config.completions_url,
                    headers=headers,
                    json=payload,
                    timeout=self.config.timeout,
                )
            except Exception as error:
                logger.warning("chat transport_error attempt=%s", attempts)
                return ChatResult(
                    text=None, status_code=None, attempts=attempts,
                    error=f"transport_error:{type(error).__name__}",
                )

            status = getattr(response, "status_code", None)

            if status == 429:
                if rate_limited < self.config.max_retries:
                    rate_limited += 1
                    delay = self.config.backoff_seconds * (2 ** (rate_limited - 1))
                    logger.info("chat http_status=429 backoff=%ss attempt=%s", delay, attempts)
                    self._sleep(delay)
                    continue
                logger.warning("chat rate_limited attempts=%s", attempts)
                return ChatResult(None, 429, attempts, error="rate_limited")

            if status != 200:
                logger.warning("chat http_status=%s attempts=%s", status, attempts)
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
