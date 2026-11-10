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
_sync_deps: Any | None = None


def set_sync_deps(deps: Any) -> None:
    """Inject the PipelineDeps used when a synced dispute is indexed.

    The app sets this at startup so the sync path shares the console's
    audit log and database. Its reader_config is always None: a sync must
    never be able to call the model, even by accident.
    """
    global _sync_deps
    _sync_deps = deps


def get_sync_deps() -> Any:
    """Deps for indexing a synced dispute, built from the config if unset.

    Falls back to building them so a poll driven outside the app (a test, a
    one-off script) still indexes what it fetches.
    """
    global _sync_deps
    if _sync_deps is None:
        from .audit import AuditConfig, AuditLog
        from .config import load_config
        from .pipeline import CaseViewStore, PipelineDeps

        config = load_config()
        _sync_deps = PipelineDeps(
            audit=AuditLog(config.audit_config()),
            case_views=CaseViewStore(config.db_path),
            policy_config=config.policy_config(),
            reader_config=None,
        )
    return _sync_deps


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


def _safe_str(value: Any) -> str | None:
    """Only pass through a plain string; never a nested structure."""
    return value.strip() if isinstance(value, str) and value.strip() else None


def _diagnostic_fields(event: Mapping[str, Any], client: Any) -> dict[str, Any]:
    """Identifiers safe to log on a rejection.

    Deliberately excludes the request body, the signature headers, the token
    and the full webhook id. The event id and type are untrusted strings used
    purely as correlation labels, and resource id is whatever identifier the
    caller claimed, logged as-is only to help match against PayPal's dashboard.
    """
    resource = event.get("resource")
    resource_id = None
    if isinstance(resource, dict):
        resource_id = _safe_str(resource.get("id")) or _safe_str(resource.get("dispute_id"))

    return {
        "event_id": _safe_str(event.get("id")),
        "event_type": _safe_str(event.get("event_type")),
        "resource_id": resource_id,
        "webhook_id_set": getattr(client, "webhook_id_is_set", None),
        "webhook_id_last4": getattr(client, "webhook_id_suffix", None),
    }


def refresh_case(event_id: str, event_type: str | None, dispute_id: str) -> bool:
    """Re-fetch a dispute and store the fetched state. Returns True on success.

    The single ingest path. Both the webhook background task and the poller
    call this, so a snapshot can only ever come from get_dispute.
    """
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
        return False

    # Never regress the stored record. The executor's confirming re-fetch is
    # the newest truth about a dispute it just answered; a poll or a webhook
    # that arrives with an older view of the same dispute must not undo it.
    if not store.save_case_snapshot_if_not_older(dispute_id, snapshot):
        store.set_event_status(event_id, "processed")
        logger.info(
            "event_id=%s event_type=%s dispute_id=%s status=processed indexed=%s "
            "update_time=%s",
            event_id,
            event_type,
            dispute_id,
            "skipped_older_record",
            snapshot.get("update_time"),
        )
        return True

    # Index it for the queue straight away. Storing the snapshot alone left
    # the console with nothing to list, which is how a poll reporting five
    # disputes produced an empty grid. This builds facts and a policy
    # decision; it does not run the Reader.
    try:
        from .pipeline import sync_case

        view = sync_case(snapshot, get_sync_deps())
        indexed_status = view.status
    except Exception as error:
        # Never silent: the dispute is stored, so say loudly that the
        # console will not see it until this is fixed.
        logger.warning(
            "indexing failed dispute_id=%s step=sync_case exception=%s message=%s",
            dispute_id,
            type(error).__name__,
            error,
        )
        indexed_status = "index_failed"

    store.set_event_status(event_id, "processed")
    logger.info(
        "event_id=%s event_type=%s dispute_id=%s status=processed indexed=%s",
        event_id,
        event_type,
        dispute_id,
        indexed_status,
    )
    return True


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
    client = get_client()
    diagnostics = _diagnostic_fields(event, client)
    try:
        result = client.verify_webhook_signature(request.headers, event)
    except MissingSignatureHeaders as error:
        logger.warning(
            "status=rejected reason=missing_signature_headers event_id=%s event_type=%s "
            "resource_id=%s detail=%s webhook_id_set=%s webhook_id_last4=%s",
            diagnostics["event_id"],
            diagnostics["event_type"],
            diagnostics["resource_id"],
            error,
            diagnostics["webhook_id_set"],
            diagnostics["webhook_id_last4"],
        )
        return _json_response(400, {"status": "rejected", "reason": "missing_signature_headers"})
    except PayPalError as error:
        # Upstream problem, not a bad caller. Nothing stored; PayPal retries.
        logger.warning(
            "status=rejected reason=verification_unavailable event_id=%s event_type=%s "
            "resource_id=%s http_status=%s debug_id=%s webhook_id_set=%s webhook_id_last4=%s",
            diagnostics["event_id"],
            diagnostics["event_type"],
            diagnostics["resource_id"],
            error.status_code,
            error.debug_id,
            diagnostics["webhook_id_set"],
            diagnostics["webhook_id_last4"],
        )
        return _json_response(503, {"status": "rejected", "reason": "verification_unavailable"})

    if not result:
        logger.warning(
            "status=rejected reason=invalid_signature event_id=%s event_type=%s resource_id=%s "
            "verification_status=%s debug_id=%s webhook_id_set=%s webhook_id_last4=%s",
            diagnostics["event_id"],
            diagnostics["event_type"],
            diagnostics["resource_id"],
            getattr(result, "verification_status", None),
            getattr(result, "debug_id", None),
            diagnostics["webhook_id_set"],
            diagnostics["webhook_id_last4"],
        )
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
    background.add_task(refresh_case, event_id, event_type, dispute_id)
    return _json_response(200, {"status": "accepted"})


def _json_response(status_code: int, payload: dict[str, Any]) -> Response:
    return Response(
        content=json.dumps(payload),
        status_code=status_code,
        media_type="application/json",
    )
