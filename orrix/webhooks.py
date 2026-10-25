"""Receives and verifies PayPal events."""

from __future__ import annotations

import json
import logging
from typing import Any, Mapping

from fastapi import APIRouter, BackgroundTasks, Request, Response

from . import store
from .paypal import MissingSignatureHeaders, PayPalError, SandboxPayPalClient

logger = logging.getLogger("orrix.webhooks")

router = APIRouter()

# Field names the dispute id has been seen under, in order of preference.
_DISPUTE_ID_FIELDS = ("dispute_id", "id", "disputeId")

_client: SandboxPayPalClient | None = None


def get_client() -> SandboxPayPalClient:
    """Lazily built so importing this module never requires credentials."""
    global _client
    if _client is None:
        _client = SandboxPayPalClient()
    return _client


def set_client(client: SandboxPayPalClient | None) -> None:
    """Swap the client. Used by tests; PayPal is never contacted in them."""
    global _client
    _client = client


def extract_dispute_id(event: Mapping[str, Any]) -> str | None:
    """Pull the dispute id and nothing else out of the payload.

    This is the single field we are willing to read from an event. Every
    other value is attacker-influenced as far as Orrix is concerned, and the
    real state always comes from a fresh get_dispute.
    """
    resource = event.get("resource")
    if not isinstance(resource, dict):
        return None
    for field in _DISPUTE_ID_FIELDS:
        value = resource.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _refresh_case(event_id: str, event_type: str | None, dispute_id: str) -> None:
    """Background work: re-fetch the dispute and store the fetched state."""
    try:
        snapshot = get_client().get_dispute(dispute_id)
    except PayPalError as error:
        store.set_event_status(event_id, "fetch_failed")
        logger.warning(
            "event_id=%s event_type=%s dispute_id=%s status=fetch_failed http_status=%s debug_id=%s",
            event_id,
            event_type,
            dispute_id,
            error.status_code,
            error.debug_id,
        )
        return

    store.save_case_snapshot(dispute_id, snapshot)
    store.set_event_status(event_id, "processed")
    logger.info(
        "event_id=%s event_type=%s dispute_id=%s status=processed",
        event_id,
        event_type,
        dispute_id,
    )


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/webhooks/paypal")
async def receive_paypal_event(request: Request, background: BackgroundTasks) -> Response:
    raw_body = await request.body()

    try:
        event = json.loads(raw_body)
    except (ValueError, UnicodeDecodeError):
        logger.warning("status=rejected reason=malformed_json")
        return _json_response(400, {"status": "rejected", "reason": "malformed_json"})
    if not isinstance(event, dict):
        logger.warning("status=rejected reason=malformed_json")
        return _json_response(400, {"status": "rejected", "reason": "malformed_json"})

    # Verification happens before anything is stored or fetched.
    try:
        verified = get_client().verify_webhook_signature(request.headers, event)
    except MissingSignatureHeaders:
        logger.warning("status=rejected reason=missing_signature_headers")
        return _json_response(400, {"status": "rejected", "reason": "missing_signature_headers"})
    except PayPalError as error:
        # Upstream problem, not a bad caller. Nothing stored; PayPal retries.
        logger.warning(
            "status=rejected reason=verification_unavailable http_status=%s debug_id=%s",
            error.status_code,
            error.debug_id,
        )
        return _json_response(503, {"status": "rejected", "reason": "verification_unavailable"})

    if not verified:
        logger.warning("status=rejected reason=invalid_signature")
        return _json_response(400, {"status": "rejected", "reason": "invalid_signature"})

    event_id = event.get("id")
    if not isinstance(event_id, str) or not event_id.strip():
        logger.warning("status=rejected reason=missing_event_id")
        return _json_response(400, {"status": "rejected", "reason": "missing_event_id"})
    event_id = event_id.strip()

    event_type = event.get("event_type")
    if not isinstance(event_type, str):
        event_type = None
    dispute_id = extract_dispute_id(event)

    # Atomic claim. A replay loses the race and does no work at all.
    is_new = store.insert_event_if_absent(
        event_id, event_type, dispute_id, status="received" if dispute_id else "no_dispute_id"
    )
    if not is_new:
        logger.info(
            "event_id=%s event_type=%s dispute_id=%s status=duplicate",
            event_id,
            event_type,
            dispute_id,
        )
        return _json_response(200, {"status": "duplicate"})

    if dispute_id is None:
        # Unknown shape. Recorded so we can learn what sandbox really sends.
        logger.info(
            "event_id=%s event_type=%s dispute_id=None status=no_dispute_id",
            event_id,
            event_type,
        )
        return _json_response(200, {"status": "accepted"})

    # Respond fast; the fetch happens after the response is sent.
    background.add_task(_refresh_case, event_id, event_type, dispute_id)
    return _json_response(200, {"status": "accepted"})


def _json_response(status_code: int, payload: dict[str, Any]) -> Response:
    return Response(
        content=json.dumps(payload),
        status_code=status_code,
        media_type="application/json",
    )
