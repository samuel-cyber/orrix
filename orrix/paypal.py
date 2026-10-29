"""Sandbox PayPal client."""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Mapping

import requests
from dotenv import load_dotenv

load_dotenv()

SANDBOX_BASE_URL = "https://api-m.sandbox.paypal.com"

# Refresh a little before the token actually expires so an in-flight call
# never races the expiry.
_EXPIRY_SKEW_SECONDS = 60
_DEFAULT_TIMEOUT = 30

# PAYPAL-* headers that carry the signature, mapped to the field names the
# verify-webhook-signature endpoint expects.
_SIGNATURE_HEADERS = {
    "auth_algo": "paypal-auth-algo",
    "cert_url": "paypal-cert-url",
    "transmission_id": "paypal-transmission-id",
    "transmission_sig": "paypal-transmission-sig",
    "transmission_time": "paypal-transmission-time",
}


class PayPalError(RuntimeError):
    """A PayPal call failed. Carries status and debug id only, never credentials."""

    def __init__(self, message: str, status_code: int | None = None, debug_id: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.debug_id = debug_id


class MissingSignatureHeaders(ValueError):
    """The request did not carry the full set of PAYPAL-* signature headers."""


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of a verify-webhook-signature call.

    Truthy only when PayPal said SUCCESS, so `if verify(...)` stays correct.
    Holds nothing derived from the request body or any credential.
    """

    verified: bool
    verification_status: str | None = None
    debug_id: str | None = None

    def __bool__(self) -> bool:
        return self.verified


class SandboxPayPalClient:
    """Read-only sandbox client. No write endpoints live in this module.

    Writes belong to orrix.executor; nothing here may POST an action to a
    dispute. The verify-webhook-signature call is a POST, but it is a
    verification read: it changes nothing on the account.
    """

    def __init__(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
        webhook_id: str | None = None,
        base_url: str = SANDBOX_BASE_URL,
        session: requests.Session | None = None,
    ):
        if not base_url.rstrip("/").endswith("api-m.sandbox.paypal.com"):
            raise ValueError("Orrix is sandbox only; refusing a non-sandbox base URL")
        self.base_url = base_url.rstrip("/")
        self._client_id = client_id if client_id is not None else os.environ.get("PAYPAL_CLIENT_ID")
        self._client_secret = (
            client_secret if client_secret is not None else os.environ.get("PAYPAL_CLIENT_SECRET")
        )
        self._webhook_id = webhook_id if webhook_id is not None else os.environ.get("PAYPAL_WEBHOOK_ID")
        self._session = session or requests.Session()
        self._lock = threading.Lock()
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    # -- auth ------------------------------------------------------------

    def _credentials(self) -> tuple[str, str]:
        if not self._client_id or not self._client_secret:
            raise PayPalError(
                "PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET must be set in .env"
            )
        return self._client_id, self._client_secret

    def token(self) -> str:
        """Return a cached access token, fetching a new one shortly before expiry."""
        with self._lock:
            if self._token and time.monotonic() < self._token_expires_at:
                return self._token

            client_id, client_secret = self._credentials()
            response = self._session.post(
                f"{self.base_url}/v1/oauth2/token",
                auth=(client_id, client_secret),
                data={"grant_type": "client_credentials"},
                timeout=_DEFAULT_TIMEOUT,
            )
            if response.status_code != 200:
                # Body may echo the client id; never surface it.
                raise PayPalError(
                    "OAuth token request failed",
                    status_code=response.status_code,
                    debug_id=response.headers.get("Paypal-Debug-Id"),
                )
            payload = response.json()
            expires_in = float(payload.get("expires_in", 0) or 0)
            self._token = payload["access_token"]
            self._token_expires_at = time.monotonic() + max(expires_in - _EXPIRY_SKEW_SECONDS, 0.0)
            return self._token

    def invalidate_token(self) -> None:
        """Drop the cached token so the next call fetches a fresh one."""
        with self._lock:
            self._token = None
            self._token_expires_at = 0.0

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token()}", "Content-Type": "application/json"}

    # -- reads -----------------------------------------------------------

    def get_dispute(self, dispute_id: str) -> dict[str, Any]:
        """Fetch the current state of a dispute. This is the only source of truth."""
        response = self._session.get(
            f"{self.base_url}/v1/customer/disputes/{dispute_id}",
            headers=self._auth_headers(),
            timeout=_DEFAULT_TIMEOUT,
        )
        if response.status_code != 200:
            raise PayPalError(
                f"get_dispute({dispute_id}) failed",
                status_code=response.status_code,
                debug_id=response.headers.get("Paypal-Debug-Id"),
            )
        return response.json()

    # -- webhook verification --------------------------------------------

    @staticmethod
    def _signature_fields(headers: Mapping[str, str]) -> dict[str, str]:
        lowered = {str(key).lower(): value for key, value in headers.items()}
        fields: dict[str, str] = {}
        missing: list[str] = []
        for field, header in _SIGNATURE_HEADERS.items():
            value = lowered.get(header)
            if not value:
                missing.append(header)
            else:
                fields[field] = value
        if missing:
            raise MissingSignatureHeaders(f"missing signature headers: {', '.join(sorted(missing))}")
        return fields

    @property
    def webhook_id_is_set(self) -> bool:
        return bool(self._webhook_id)

    @property
    def webhook_id_suffix(self) -> str | None:
        """Last 4 characters of the configured webhook id, for diagnostics.

        Enough to tell two registrations apart when verification fails; never
        enough to reconstruct the id. The full value is never returned or logged.
        """
        if not self._webhook_id:
            return None
        return self._webhook_id[-4:]

    def verify_webhook_signature(
        self, headers: Mapping[str, str], event: Mapping[str, Any]
    ) -> VerificationResult:
        """Verify an event. Truthy only when PayPal answers SUCCESS.

        Raises MissingSignatureHeaders when the PAYPAL-* headers are incomplete.
        Any other outcome is falsy: unverified is never treated as verified.
        The result carries PayPal's verification_status and debug id so the
        rejection path can say why without touching the body or any secret.
        """
        if not self._webhook_id:
            raise PayPalError("PAYPAL_WEBHOOK_ID must be set in .env")

        body = self._signature_fields(headers)
        body["webhook_id"] = self._webhook_id
        body["webhook_event"] = event

        response = self._session.post(
            f"{self.base_url}/v1/notifications/verify-webhook-signature",
            headers=self._auth_headers(),
            json=body,
            timeout=_DEFAULT_TIMEOUT,
        )
        if response.status_code != 200:
            raise PayPalError(
                "verify-webhook-signature call failed",
                status_code=response.status_code,
                debug_id=response.headers.get("Paypal-Debug-Id"),
            )

        status = response.json().get("verification_status")
        return VerificationResult(
            verified=status == "SUCCESS",
            verification_status=status,
            debug_id=response.headers.get("Paypal-Debug-Id"),
        )
