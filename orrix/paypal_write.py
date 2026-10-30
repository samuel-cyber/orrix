"""Sandbox PayPal write capability. Imported only by orrix.executor."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping

SANDBOX_BASE_URL = "https://api-m.sandbox.paypal.com"
_DEFAULT_TIMEOUT = 60


class PayPalWriteError(RuntimeError):
    """A write call failed. Carries status and debug id, never credentials."""

    def __init__(self, message: str, status_code: int | None = None, debug_id: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.debug_id = debug_id


@dataclass(frozen=True)
class PayPalWriteConfig:
    """Passed in by the caller. No environment is read here."""

    base_url: str = SANDBOX_BASE_URL
    timeout: float = _DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        if not self.base_url.rstrip("/").endswith("api-m.sandbox.paypal.com"):
            raise ValueError("Orrix is sandbox only; refusing a non-sandbox write base URL")


@dataclass(frozen=True)
class WriteResult:
    status_code: int
    debug_id: str | None
    request_id: str


class SandboxPayPalWriter:
    """The only object in Orrix that can change anything at PayPal.

    Takes a token provider rather than credentials, so it never reads the
    environment and never holds a secret of its own.
    """

    def __init__(
        self,
        config: PayPalWriteConfig,
        token_provider: Callable[[], str],
        session: Any | None = None,
    ):
        self.config = config
        self._token_provider = token_provider
        self._session = session

    def _client(self) -> Any:
        if self._session is None:
            import requests

            self._session = requests.Session()
        return self._session

    def provide_evidence(
        self, dispute_id: str, payload: Mapping[str, Any], request_id: str
    ) -> WriteResult:
        """Submit evidence as multipart with a JSON `input` part.

        PayPal-Request-Id is the approval id, which makes the call idempotent
        at PayPal's end as well as ours: a replay of the same approval cannot
        become a second submission.
        """
        if not isinstance(dispute_id, str) or not dispute_id.strip():
            raise PayPalWriteError("dispute_id is required")
        if not isinstance(request_id, str) or not request_id.strip():
            raise PayPalWriteError("request_id (approval id) is required")

        url = f"{self.config.base_url.rstrip('/')}/v1/customer/disputes/{dispute_id}/provide-evidence"
        headers = {
            "Authorization": f"Bearer {self._token_provider()}",
            "PayPal-Request-Id": request_id,
        }
        files = {"input": (None, json.dumps(payload), "application/json")}

        response = self._client().post(
            url, headers=headers, files=files, timeout=self.config.timeout
        )
        status_code = getattr(response, "status_code", None)
        debug_id = None
        response_headers = getattr(response, "headers", None)
        if isinstance(response_headers, Mapping):
            debug_id = response_headers.get("Paypal-Debug-Id")

        if status_code is None or not 200 <= status_code < 300:
            raise PayPalWriteError(
                "provide_evidence failed", status_code=status_code, debug_id=debug_id
            )

        return WriteResult(status_code=status_code, debug_id=debug_id, request_id=request_id)
