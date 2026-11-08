"""Server-rendered UI for Orrix.

Every route except /health and /webhooks/paypal requires a session. POSTs
require a CSRF token. Buyer text reaches a template only through Jinja's
autoescaping and only inside its own quoted block, never merged into another
section.

This module holds no write capability: approvals go to orrix.executor, which
is the only importer of orrix.paypal_write.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from ..approval import ApprovalError, DisputeVersion, create_approval
from ..audit import OriginTag
from ..executor import build_evidence_payload, execute
from ..facts import FactStatus, build_facts
from ..evaluation import load_results
from ..pipeline import process_case, status_label
from ..policy import PROVIDE_EVIDENCE
from ..reader import extract_buyer_text
from ..seller_input import DeliveryStatus, SellerInputError, parse_seller_input
from .security import (
    CSRF_FIELD,
    CSRF_HEADER,
    SECURITY_HEADERS,
    SESSION_COOKIE,
)

logger = logging.getLogger("orrix.web")

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

# Pinned CDN versions. Bumping these is a deliberate edit, not a float.
AG_GRID_VERSION = "32.3.3"
HTMX_VERSION = "2.0.3"

PUBLIC_PATHS = ("/health", "/webhooks/paypal", "/login", "/static")

ORIGIN_LABELS = {
    "paypal_record": "PayPal record",
    "seller_input": "Seller input",
    "derived": "Orrix (derived)",
    "buyer_text": "Buyer text (untrusted, display only)",
}

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
router = APIRouter()


def is_public(path: str) -> bool:
    return any(path == public or path.startswith(public + "/") for public in PUBLIC_PATHS)


# -- helpers ------------------------------------------------------------


def _services(request: Request):
    return request.app.state.services


def _session_id(request: Request) -> str | None:
    return request.cookies.get(SESSION_COOKIE)


def _csrf_ok(request: Request, submitted: str | None) -> bool:
    services = _services(request)
    token = submitted or request.headers.get(CSRF_HEADER)
    return services.sessions.verify_csrf(_session_id(request), token)


def _context(request: Request, **extra: Any) -> dict[str, Any]:
    services = _services(request)
    session_id = _session_id(request)
    return {
        "request": request,
        "csrf_token": services.sessions.csrf_token(session_id) if session_id else "",
        "ag_grid_version": AG_GRID_VERSION,
        "htmx_version": HTMX_VERSION,
        "origin_labels": ORIGIN_LABELS,
        # Injected into a data attribute at render time and read by the
        # static grid scripts. Never inlined into a script body, never
        # logged. Absent is fine: the grid runs with a watermark.
        "ag_grid_license_key": services.config.ag_grid_license_key or "",
        **extra,
    }


def _deadline_info(due: Any) -> dict[str, Any]:
    """Hours and days left until the seller response deadline."""
    if not isinstance(due, str):
        return {"iso": None, "hours_left": None, "label": "unknown", "urgent": False}
    text = due.replace("Z", "+00:00")
    try:
        deadline = datetime.fromisoformat(text)
    except ValueError:
        return {"iso": due, "hours_left": None, "label": "unknown", "urgent": False}
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)

    remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
    hours = remaining / 3600.0
    if remaining <= 0:
        label = "passed"
    elif hours < 48:
        label = f"{int(hours)}h left"
    else:
        label = f"{int(hours // 24)}d left"
    return {
        "iso": due,
        "hours_left": round(hours, 1),
        "label": label,
        "urgent": remaining <= 0 or hours < 48,
    }


def _evidence_completeness(facts) -> str:
    """has tracking? yes / seller-asserted / no."""
    if facts is None:
        return "no"
    status = facts.status("tracking_number")
    if status is FactStatus.CONFIRMED:
        return "yes"
    if status is FactStatus.SELLER_ASSERTED:
        return "seller-asserted"
    return "no"


def _load_case(request: Request, dispute_id: str) -> dict[str, Any] | None:
    services = _services(request)
    snapshot = services.case_snapshot(dispute_id)
    if snapshot is None:
        return None

    seller_input = services.get_seller_input(dispute_id)
    view = process_case(snapshot, services.pipeline_deps, seller_input=seller_input)

    facts = view.facts
    payload = None
    payload_error = None
    if facts is not None:
        try:
            payload = build_evidence_payload(facts)
        except ValueError as error:
            payload_error = str(error)

    fact_rows = []
    if facts is not None:
        for name, fact in facts.facts.items():
            fact_rows.append(
                {
                    "name": name,
                    "value": "" if fact.value is None else str(fact.value),
                    "status": fact.status.value,
                    "source": fact.source,
                    "origin_label": ORIGIN_LABELS.get(fact.source, fact.source),
                }
            )
        fact_rows.sort(key=lambda row: row["name"])

    return {
        "dispute_id": dispute_id,
        "snapshot": snapshot,
        "view": view,
        "facts": facts,
        "fact_rows": fact_rows,
        # Buyer text is carried as a single escaped string and rendered only
        # inside its own labelled block.
        "buyer_text": extract_buyer_text(snapshot),
        "deadline": _deadline_info(facts.value("seller_response_due_date") if facts else None),
        "payload": payload,
        "payload_json": json.dumps(payload, indent=2) if payload else None,
        "payload_error": payload_error,
        "seller_input": seller_input,
        "completeness": _evidence_completeness(facts),
        "delivery_statuses": [status.value for status in DeliveryStatus],
        "can_approve": PROVIDE_EVIDENCE in view.decision.allowed_actions and payload is not None,
        "last_result": services.get_result(dispute_id),
    }


# -- auth ---------------------------------------------------------------


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request) -> Response:
    return templates.TemplateResponse(request, "login.html", _context(request, error=None))


def _client_address(request: Request) -> str:
    """The address to throttle on.

    Render terminates TLS and forwards the caller in X-Forwarded-For, so the
    first entry there is the client when the app sits behind that proxy. It
    is caller-supplied and therefore spoofable: the throttle raises the cost
    of guessing from one host, it does not stop a distributed attempt.
    """
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded.strip():
        return forwarded.split(",")[0].strip()
    client = request.client
    return client.host if client else "unknown"


@router.post("/login")
def login_submit(request: Request, password: str = Form("")) -> Response:
    services = _services(request)
    client = _client_address(request)

    if services.login_throttle.is_locked(client):
        retry_after = services.login_throttle.retry_after(client)
        logger.warning(
            "login throttled client=%s failures=%s retry_after=%ss",
            client,
            services.login_throttle.failures(client),
            retry_after,
        )
        response = templates.TemplateResponse(
            request,
            "login.html",
            _context(
                request,
                error=(
                    f"Too many failed attempts. Try again in "
                    f"{max(retry_after // 60, 1)} minute(s)."
                ),
            ),
            status_code=429,
        )
        response.headers["Retry-After"] = str(retry_after)
        return response

    if not services.admin_password_hash:
        return templates.TemplateResponse(
            request,
            "login.html",
            _context(request, error="No admin password is configured. Set ADMIN_PASSWORD."),
            status_code=503,
        )

    if not services.check_password(password):
        failures = services.login_throttle.record_failure(client)
        logger.warning(
            "login failed client=%s failures=%s/%s",
            client,
            failures,
            services.login_throttle.max_failures,
        )
        return templates.TemplateResponse(
            request,
            "login.html",
            _context(request, error="Incorrect password."),
            status_code=401,
        )

    # A correct password clears the tally, so one mistyped attempt costs
    # nothing once the right one lands.
    services.login_throttle.clear(client)
    session = services.sessions.create()
    services.audit.append(
        actor="admin", action="web.login", origin_tag=OriginTag.SYSTEM, payload=None
    )
    response = RedirectResponse("/cases", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        session.session_id,
        httponly=True,
        samesite="lax",
        secure=services.secure_cookies,
        path="/",
        max_age=services.sessions.ttl_seconds,
    )
    return response


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form("")) -> Response:
    if not _csrf_ok(request, csrf_token):
        return _csrf_failure(request)
    services = _services(request)
    services.sessions.destroy(_session_id(request))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


def _csrf_failure(request: Request) -> Response:
    logger.warning("csrf check failed path=%s", request.url.path)
    return JSONResponse({"error": "csrf_failed"}, status_code=403)


# -- queue --------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
def index(request: Request) -> Response:
    return RedirectResponse("/cases", status_code=303)


@router.get("/cases", response_class=HTMLResponse)
def cases_page(request: Request) -> Response:
    return templates.TemplateResponse(request, "cases.html", _context(request))


@router.get("/api/cases")
def api_cases(request: Request) -> Response:
    """Queue data for the grid.

    Reads the persisted case views. It does NOT run the Reader: listing the
    queue must cost nothing, or every page load would spend model credits on
    every dispute. A dispute with no view yet is indexed here, still without
    the Reader, so a database written by an older build still lists.

    Carries no buyer text and no free text of any kind: every field is an
    identifier, a code, an amount or a derived label.
    """
    services = _services(request)
    rows = []

    for dispute_id in services.list_dispute_ids():
        view = services.case_view(dispute_id)
        if view is None:
            continue
        facts = view.facts
        deadline = _deadline_info(facts.value("seller_response_due_date") if facts else None)

        rows.append(
            {
                "dispute_id": dispute_id,
                "amount": str(facts.value("dispute_amount") or "") if facts else "",
                "currency": (facts.value("dispute_currency") or "") if facts else "",
                "reason": (facts.value("reason") or "") if facts else "",
                "state": (facts.value("dispute_state") or "") if facts else "",
                "status": (facts.value("status") or "") if facts else "",
                "due_date": deadline["iso"] or "",
                "due_label": deadline["label"],
                "hours_left": deadline["hours_left"],
                "urgent": deadline["urgent"],
                "completeness": _evidence_completeness(facts),
                "flags": ", ".join(sorted(view.decision.flags)),
                "orrix_status": view.status,
                "orrix_status_label": status_label(view.status),
                "reader_pending": view.reader_pending,
                "allowed_actions": ", ".join(sorted(view.decision.allowed_actions)),
                # Master/detail payload. Facts are codes; the discrepancy is
                # the module's fixed sentence. No buyer text anywhere.
                "detail": {
                    "facts": _detail_rows(facts),
                    "discrepancy": view.discrepancy.message if view.discrepancy else "",
                    "completeness": _evidence_completeness(facts),
                    "evidence_submitted": bool(
                        facts.value("evidence_submitted")
                    )
                    if facts
                    else False,
                    "reasons": list(view.decision.reasons),
                    "reader_pending": view.reader_pending,
                    "case_url": f"/cases/{dispute_id}",
                },
            }
        )

    rows.sort(key=lambda row: (row["hours_left"] is None, row["hours_left"]))
    return JSONResponse(rows)


def _detail_rows(facts) -> list[dict[str, str]]:
    """Facts for the master/detail panel. Codes and labels only."""
    if facts is None:
        return []
    rows = [
        {
            "name": name,
            "value": "" if fact.value is None else str(fact.value),
            "status": fact.status.value,
            "source": fact.source,
            "origin_label": ORIGIN_LABELS.get(fact.source, fact.source),
        }
        for name, fact in facts.facts.items()
    ]
    rows.sort(key=lambda row: row["name"])
    return rows


# -- one case -----------------------------------------------------------


@router.get("/cases/{dispute_id}", response_class=HTMLResponse)
def case_page(request: Request, dispute_id: str) -> Response:
    case = _load_case(request, dispute_id)
    if case is None:
        return templates.TemplateResponse(
            request, "not_found.html", _context(request, dispute_id=dispute_id), status_code=404
        )
    return templates.TemplateResponse(request, "case.html", _context(request, **case))


@router.post("/cases/{dispute_id}/seller-input", response_class=HTMLResponse)
def submit_seller_input(
    request: Request,
    dispute_id: str,
    csrf_token: str = Form(""),
    carrier: str = Form(""),
    tracking_number: str = Form(""),
    delivery_status: str = Form("UNKNOWN"),
    delivered_on: str = Form(""),
) -> Response:
    if not _csrf_ok(request, csrf_token):
        return _csrf_failure(request)

    services = _services(request)
    submitted: dict[str, Any] = {
        "carrier": carrier,
        "tracking_number": tracking_number,
        "delivery_status": delivery_status,
    }
    if delivered_on.strip():
        submitted["delivered_on"] = delivered_on.strip()

    try:
        parsed = parse_seller_input(submitted)
    except (ValidationError, SellerInputError) as error:
        errors = _readable_errors(error)
        case = _load_case(request, dispute_id) or {"dispute_id": dispute_id}
        return templates.TemplateResponse(
            request,
            "case.html",
            _context(request, seller_errors=errors, **case),
            status_code=400,
        )

    services.set_seller_input(dispute_id, parsed)
    # Rebuild the stored view so the queue reflects the new tracking. No
    # model call: a cached Reader result is reused, or the case stays
    # pending.
    services.reindex(dispute_id)
    services.audit.append(
        actor="admin",
        action="web.seller_input_saved",
        origin_tag=OriginTag.SELLER_APPROVAL,
        dispute_id=dispute_id,
        payload=json.loads(parsed.model_dump_json()),
    )
    return RedirectResponse(f"/cases/{dispute_id}", status_code=303)


@router.post("/cases/{dispute_id}/approve", response_class=HTMLResponse)
def approve(
    request: Request,
    dispute_id: str,
    csrf_token: str = Form(""),
    dispute_update_time: str = Form(""),
    dispute_status: str = Form(""),
) -> Response:
    """Create an approval bound to this dispute, payload and version, execute it."""
    if not _csrf_ok(request, csrf_token):
        return _csrf_failure(request)

    services = _services(request)
    snapshot = services.case_snapshot(dispute_id)
    if snapshot is None:
        return templates.TemplateResponse(
            request, "not_found.html", _context(request, dispute_id=dispute_id), status_code=404
        )

    # The version the operator saw must still be the version on record.
    # Anything else and they are approving something they did not read.
    current = DisputeVersion.from_snapshot(snapshot)
    if (dispute_update_time, dispute_status) != current.as_tuple():
        services.audit.append(
            actor="admin",
            action="web.approve_refused:stale_view",
            origin_tag=OriginTag.SELLER_APPROVAL,
            dispute_id=dispute_id,
            payload=None,
        )
        services.set_result(
            dispute_id,
            {
                "status": "refused",
                "reason": "stale_view",
                "message": (
                    "The dispute changed after this page was loaded. "
                    "Review the updated case and approve again."
                ),
                "stale": True,
            },
        )
        return RedirectResponse(f"/cases/{dispute_id}", status_code=303)

    seller_input = services.get_seller_input(dispute_id)
    facts = build_facts(snapshot, seller_input=seller_input, expected_dispute_id=dispute_id)

    try:
        payload = build_evidence_payload(facts)
    except ValueError as error:
        services.set_result(
            dispute_id, {"status": "refused", "reason": "no_payload", "message": str(error)}
        )
        return RedirectResponse(f"/cases/{dispute_id}", status_code=303)

    try:
        approval = create_approval(
            dispute_id=dispute_id,
            action=PROVIDE_EVIDENCE,
            payload=payload,
            dispute_version=current,
        )
    except ApprovalError as error:
        services.set_result(
            dispute_id, {"status": "refused", "reason": "approval_error", "message": str(error)}
        )
        return RedirectResponse(f"/cases/{dispute_id}", status_code=303)

    services.audit.append(
        actor="admin",
        action="web.approval_created",
        origin_tag=OriginTag.SELLER_APPROVAL,
        dispute_id=dispute_id,
        payload=approval.approval_id,
    )

    result = execute(approval, services.executor_deps(seller_input=seller_input))

    confirmation = services.case_snapshot(dispute_id)
    services.set_result(
        dispute_id,
        {
            "status": result.status,
            "reason": result.reason,
            "approval_id": result.approval_id,
            "writes_attempted": result.writes_attempted,
            "requires_review": result.requires_review,
            "debug_id": result.debug_id,
            "stale": result.reason == "stale_approval",
            "message": _result_message(result),
            "confirmed_evidence": _confirmation_rows(confirmation),
        },
    )
    return RedirectResponse(f"/cases/{dispute_id}", status_code=303)


def _result_message(result) -> str:
    if result.status == "executed":
        return "Evidence submitted and confirmed on the re-fetched dispute."
    if result.reason == "stale_approval":
        return (
            "The dispute changed between approval and execution. Nothing was sent. "
            "Review the updated case and approve again."
        )
    if result.status == "unconfirmed":
        return "The write returned success but the evidence was not found on re-fetch."
    return f"Refused: {result.reason}."


def _confirmation_rows(snapshot: Any) -> list[dict[str, str]]:
    """Seller-submitted proof entries on the re-fetched record."""
    if not isinstance(snapshot, dict):
        return []
    rows = []
    for evidence in snapshot.get("evidences", []) or []:
        if not isinstance(evidence, dict):
            continue
        if evidence.get("source") != "SUBMITTED_BY_SELLER":
            continue
        info = evidence.get("evidence_info") or {}
        for entry in (info.get("tracking_info") or []) if isinstance(info, dict) else []:
            if isinstance(entry, dict):
                rows.append(
                    {
                        "carrier": str(entry.get("carrier_name", "")),
                        "tracking_number": str(entry.get("tracking_number", "")),
                        "date": str(evidence.get("date", "")),
                    }
                )
    return rows


def _readable_errors(error: Exception) -> list[str]:
    if isinstance(error, ValidationError):
        messages = []
        for item in error.errors():
            location = ".".join(str(part) for part in item.get("loc", ())) or "input"
            messages.append(f"{location}: {item.get('msg', 'invalid')}")
        return messages
    return [str(error)]


# -- audit --------------------------------------------------------------


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request) -> Response:
    return templates.TemplateResponse(request, "audit.html", _context(request, verification=None))


@router.get("/api/audit")
def api_audit(request: Request) -> Response:
    """Audit rows with chain integrity decided server-side.

    The browser is told whether each row verifies; it never recomputes a
    hash itself, so the grid cannot disagree with the server about what is
    intact.
    """
    services = _services(request)
    entries = services.audit.entries()
    bad_seq = services.audit.verify_chain()

    rows = []
    for entry in entries:
        # Everything from the first bad sequence onward is suspect: the
        # chain cannot vouch for anything after the break.
        chain_ok = bad_seq is None or entry.seq < bad_seq
        rows.append(
            {
                "seq": entry.seq,
                "ts": entry.ts,
                "actor": entry.actor,
                "action": entry.action,
                "dispute_id": entry.dispute_id or "",
                "origin_tag": entry.origin_tag,
                "origin_label": ORIGIN_LABELS.get(entry.origin_tag, entry.origin_tag),
                "payload_hash": entry.payload_hash[:16],
                "entry_hash": entry.entry_hash[:16],
                "chain_ok": chain_ok,
                "chain_label": "ok" if chain_ok else "broken",
                "is_first_bad": bad_seq is not None and entry.seq == bad_seq,
            }
        )

    return JSONResponse(
        {
            "rows": rows,
            "chain_ok": bad_seq is None,
            "first_bad_seq": bad_seq,
            "keyed": bool(services.audit.config.hmac_key),
            "entries": len(entries),
        }
    )


# -- evaluation ---------------------------------------------------------


@router.get("/evaluation", response_class=HTMLResponse)
def evaluation_page(request: Request) -> Response:
    services = _services(request)
    results = load_results(
        services.config.results_path, services.config.results_notes_path
    )
    return templates.TemplateResponse(
        request, "evaluation.html", _context(request, results=results)
    )


@router.get("/api/evaluation")
def api_evaluation(request: Request) -> Response:
    """Harness output. Counts and labels only; no dispute data at all."""
    services = _services(request)
    results = load_results(
        services.config.results_path, services.config.results_notes_path
    )
    return JSONResponse(results.as_dict())


@router.post("/audit/verify", response_class=HTMLResponse)
def verify_audit(request: Request, csrf_token: str = Form("")) -> Response:
    if not _csrf_ok(request, csrf_token):
        return _csrf_failure(request)

    services = _services(request)
    bad_seq = services.audit.verify_chain()
    verification = {
        "ok": bad_seq is None,
        # Read by audit.js from a data attribute to highlight the row. A
        # data attribute is not a script, so the CSP stays strict.
        "bad_seq": bad_seq,
        "keyed": bool(services.audit.config.hmac_key),
        "entries": len(services.audit.entries()),
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return templates.TemplateResponse(
        request, "partials/verification.html", _context(request, verification=verification)
    )
