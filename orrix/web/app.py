"""Server-rendered UI for Orrix.

Every route except /health and /webhooks/paypal requires a session. POSTs
require a CSRF token. Buyer text reaches a template only through Jinja's
autoescaping and only inside its own quoted block, never merged into another
section.

This module holds no write capability: approvals go to orrix.executor, which
is the only importer of orrix.paypal_write.
"""

from __future__ import annotations

import csv
import hmac
import json
import logging
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from io import StringIO
from pathlib import Path
from typing import Any, Mapping

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from ..approval import ApprovalError, DisputeVersion, create_approval
from ..audit import OriginTag, canonical_json, sha256_hex
from ..carrier import CARRIER_DELIVERED_CODE, apply_carrier
from ..discrepancy import detect_discrepancy
from ..errors import host_of
from ..evidence_pack import EvidencePackError, build_pack, render_pdf
from ..executor import build_evidence_payload, execute
from ..facts import CARRIER_STATUS, SOURCE_CARRIER_API, FactStatus, build_facts
from ..evaluation import load_results
from ..orders import (
    ITEM_LABEL_MAX_LENGTH,
    ORDER_SOURCES,
    SOURCE_SELLER_LEDGER,
    OrderLedgerError,
    apply_matched,
    evidence_checklist,
    match_for_facts,
    parse_order,
)
from ..pipeline import process_case, status_label
from ..policy import PROVIDE_EVIDENCE
from ..reader import STATUS_NEEDS_REVIEW, extract_buyer_text
from ..seller_input import DeliveryStatus, SellerInputError, parse_seller_input
from .lab import LAB_MESSAGE_MAX_CHARS
from .security import (
    CSRF_FIELD,
    CSRF_HEADER,
    SECURITY_HEADERS,
    SESSION_COOKIE,
)
from .services import CARRIER_CHECK_COOLDOWN_SECONDS, RERUN_COOLDOWN_SECONDS

logger = logging.getLogger("orrix.web")

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

# Pinned CDN versions. Bumping these is a deliberate edit, not a float.
AG_GRID_VERSION = "32.3.3"
HTMX_VERSION = "2.0.3"

# The unauthenticated surface, pinned. "/" is exact: is_public("/") is true
# only for the root, so every deeper route still needs a session. /api/orders
# is machine ingest: it authenticates with a bearer token, not a session.
PUBLIC_PATHS = ("/", "/health", "/webhooks/paypal", "/login", "/static", "/api/orders")

ORIGIN_LABELS = {
    "paypal_record": "PayPal record",
    "seller_input": "Seller input",
    SOURCE_SELLER_LEDGER: "Seller ledger",
    SOURCE_CARRIER_API: "Carrier API (reported, not verified)",
    "derived": "Orrix (derived)",
    "buyer_text": "Buyer text (untrusted, display only)",
}

# The ledger CSV importer. Columns beyond this set are ignored so an export
# from a spreadsheet with extra columns still imports; the required columns
# must all be present or the whole file is refused.
ORDER_CSV_COLUMNS = (
    "seller_transaction_id",
    "order_ref",
    "carrier",
    "tracking_number",
    "shipped_at",
    "delivered_at",
    "amount",
    "currency",
    "item_label",
)
ORDER_CSV_REQUIRED = ("seller_transaction_id", "order_ref", "carrier", "tracking_number")
ORDER_CSV_MAX_ROWS = 500
ORDER_CSV_MAX_CHARS = 200_000

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
    poll = None
    if session_id:
        # The topbar's "polled Ns ago" reads a stored timestamp; it never
        # makes a network call. The public landing page has no session, so
        # it skips this entirely.
        try:
            poll = services.poll_status()
        except Exception:  # noqa: BLE001 - the indicator is cosmetic
            poll = None
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
        # The repo link in the footer. A setting, so no literal host is
        # baked into a template (only the one CDN host may ever appear).
        "site_repo_url": services.config.site_repo_url,
        # Which nav item is current. The shell compares this to each href.
        "active": request.url.path,
        "poll": poll,
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


def _reader_summary_text(result) -> str:
    """Plain-text status line for the Reader summary box.

    Carries only the fixed status/reason codes and an HTTP status code when
    one exists -- never raw model output, a URL, or a key.
    """
    if result.status != STATUS_NEEDS_REVIEW:
        return result.status
    text = result.status
    if result.reason:
        text += f" · {result.reason}"
    if result.http_status:
        text += f" (HTTP {result.http_status})"
    return text


def _reader_endpoint_host(config) -> str | None:
    """The reader's endpoint host, stripped of path, query and credentials."""
    if not config.reader_is_configured:
        return None
    return host_of(config.reader_base_url)


def _display_timestamp(value: Any) -> str | None:
    """A readable local-style rendering of a stored UTC timestamp.

    e.g. "8 Nov 2026, 14:47 UTC". The raw value is kept separately (in a
    title attribute) so nothing is lost, only reformatted.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    return f"{parsed.day} {parsed.strftime('%b %Y, %H:%M')} UTC"


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


def _pack_retrieved_at(snapshot: Mapping[str, Any]) -> datetime:
    """The timestamp the evidence pack's facts are stamped with.

    Taken from the dispute record rather than the clock, so downloading the
    same unchanged case twice produces the same bytes and the same hash, and
    so the digest shown on the page is the digest inside the file. A record
    with no usable time falls back to a fixed epoch rather than to now().
    """
    for key in ("update_time", "create_time"):
        value = snapshot.get(key)
        if isinstance(value, str) and value.strip():
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
    return datetime(2000, 1, 1, tzinfo=timezone.utc)


def _pack_facts(request: Request, dispute_id: str, snapshot: Mapping[str, Any]):
    """The Facts the evidence pack is built from, or None.

    One function for both the page's hash and the download, so the two can
    never disagree. It makes no carrier lookup: whatever reading is already
    on hand is used, and nothing is spent.
    """
    services = _services(request)
    try:
        facts = build_facts(
            snapshot,
            seller_input=services.get_seller_input(dispute_id),
            expected_dispute_id=dispute_id,
            retrieved_at=_pack_retrieved_at(snapshot),
        )
    except ValueError:
        return None

    facts, _ = apply_matched(services.order_ledger, facts)
    result = services.get_carrier_result(dispute_id) if services.carrier_enabled else None
    if result is not None:
        facts = apply_carrier(facts, result)
    return facts


def _carrier_support(facts) -> dict[str, Any] | None:
    """The carrier_reported fact, for the readiness checklist, or None.

    Only ever describes the fact as carrier-reported. It is listed as
    *supporting* PROOF_OF_FULFILLMENT, which is not the same as satisfying
    it: the payload is still built from the tracking facts alone.
    """
    if facts is None:
        return None
    fact = facts.facts.get(CARRIER_STATUS)
    if fact is None or fact.status is not FactStatus.CARRIER_REPORTED:
        return None
    return {
        "status": fact.value,
        "label": "carrier-reported",
        "origin": SOURCE_CARRIER_API,
        "delivered": fact.value == CARRIER_DELIVERED_CODE,
    }


def _evidence_pack_hash(facts) -> str | None:
    """The evidence pack's content hash, or None when no pack can be built."""
    if facts is None:
        return None
    try:
        return build_pack(facts).content_hash
    except EvidencePackError:
        return None


def _carrier_tracking(facts, ledger_row, seller_input=None) -> tuple[str, str] | None:
    """The (carrier, number) to look up, or None when there is nothing to ask.

    A lookup happens only when the seller supplied the shipment -- through
    the order ledger or through their own form. Tracking that exists only
    inside the PayPal record is not re-checked: Orrix did not put it there
    and the seller has not asked about it.

    The question is who supplied the number, not what the resolved fact's
    source ended up being. When the seller's entry and the PayPal record
    agree, the fact is stamped `paypal_record` because it is corroborated --
    but the seller did supply it, so a lookup is still in scope.
    """
    if facts is None:
        return None

    if ledger_row is not None:
        pair = (ledger_row.carrier, ledger_row.tracking_number)
    elif getattr(seller_input, "tracking_number", None):
        pair = (getattr(seller_input, "carrier", None), seller_input.tracking_number)
    else:
        return None

    if not all(isinstance(item, str) and item.strip() for item in pair):
        return None
    return pair[0].strip(), pair[1].strip()


def _carrier_context(
    request: Request,
    dispute_id: str,
    facts,
    ledger_row,
    seller_input=None,
    force: bool = False,
) -> dict[str, Any]:
    """Everything the Carrier check card needs, or {} when the flag is off.

    Returns an empty mapping when CARRIER_ENABLED is false, so the template
    renders no card and every downstream branch is skipped. This is the one
    place the console decides to spend a carrier lookup.

    `force` is the "Check carrier" button: it bypasses the already-looked-up
    check for this page load, but not the cache, the hourly cap or the
    per-case cooldown, all of which live below this.
    """
    services = _services(request)
    if not services.carrier_enabled:
        return {}

    tracking = _carrier_tracking(facts, ledger_row, seller_input)
    result = services.get_carrier_result(dispute_id)

    # Opening the page looks up once; afterwards the stored reading is
    # shown until the seller asks for a fresh one.
    if tracking is not None and (result is None or force):
        result = services.lookup_carrier(dispute_id, *tracking)

    return {
        "enabled": True,
        "provider": services.carrier.provider,
        "result": result,
        "status": result.status.value if result else None,
        "delivered_at": result.delivered_at if result else None,
        "checked_label": _display_timestamp(result.checked_at) if result else None,
        "lookups_this_hour": services.carrier.lookups_this_hour(),
        "cap": services.carrier_config.max_lookups_per_hour,
        "has_tracking": tracking is not None,
        "notice": services.get_carrier_notice(dispute_id),
    }


def _load_case(
    request: Request, dispute_id: str, force_carrier: bool = False
) -> dict[str, Any] | None:
    services = _services(request)
    snapshot = services.case_snapshot(dispute_id)
    if snapshot is None:
        # Not synced yet, or its artifacts went missing. Fetch it once,
        # read-only, rather than telling the operator a real dispute does
        # not exist. A PayPal 404 still falls through to "No such case".
        snapshot = services.fetch_and_store(dispute_id)
    if snapshot is None:
        return None

    seller_input = services.get_seller_input(dispute_id)
    view = process_case(snapshot, services.pipeline_deps, seller_input=seller_input)

    facts = view.facts

    # The ledger row this dispute's seller transaction matches, if any. Read
    # before the carrier step because it is what supplies the tracking
    # number a lookup would use. A pure read; the approval is what binds to
    # the row and its version.
    ledger_row = match_for_facts(services.order_ledger, facts)

    # The carrier connector. Lazy by construction: this runs when a case page
    # is opened, never on a poll, and only when the seller's ledger or the
    # seller's own form supplied a tracking number. The lookup goes through a
    # per-number cache and an hourly cap, so re-opening a case is free. With
    # CARRIER_ENABLED off this is an empty mapping and nothing below it runs.
    carrier = _carrier_context(
        request, dispute_id, facts, ledger_row, seller_input, force=force_carrier
    )
    if carrier.get("result") is not None and facts is not None:
        facts = apply_carrier(facts, carrier["result"])
        # The carrier may raise the same fixed discrepancy sentence a seller
        # assertion raises, and nothing else. The policy decision is
        # deliberately *not* recomputed: the action set a carrier reading
        # produces is the action set it produced without one.
        view = replace(view, facts=facts, discrepancy=detect_discrepancy(facts))

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

    # A read-only readiness view of the matched row.
    ledger_checklist = (
        evidence_checklist(facts, ledger_row, snapshot.get("create_time"))
        if facts is not None
        else None
    )

    return {
        "dispute_id": dispute_id,
        "snapshot": snapshot,
        "view": view,
        "facts": facts,
        "fact_rows": fact_rows,
        "ledger_row": ledger_row,
        "ledger_checklist": ledger_checklist,
        # Buyer text is carried as a single escaped string and rendered only
        # inside its own labelled block.
        "buyer_text": extract_buyer_text(snapshot),
        "deadline": _deadline_info(facts.value("seller_response_due_date") if facts else None),
        "payload": payload,
        "payload_json": json.dumps(payload, indent=2) if payload else None,
        "payload_error": payload_error,
        # The same canonical digest the approval id is built from. Shown so
        # the operator can see that what they read is what will be sent.
        "payload_hash": sha256_hex(canonical_json(payload)) if payload else None,
        "seller_input": seller_input,
        "completeness": _evidence_completeness(facts),
        "status_label": status_label(view.status),
        "delivery_statuses": [status.value for status in DeliveryStatus],
        "can_approve": PROVIDE_EVIDENCE in view.decision.allowed_actions and payload is not None,
        "last_result": services.get_result(dispute_id),
        "reader_summary_text": _reader_summary_text(view.reader_result),
        "reader_endpoint_host": _reader_endpoint_host(services.config),
        "reader_started_label": _display_timestamp(view.reader_started_at),
        "reader_finished_label": _display_timestamp(view.reader_finished_at),
        "rerun_notice": services.get_rerun_notice(dispute_id),
        # Empty mapping when CARRIER_ENABLED is off, which is what the
        # template tests to decide whether the card exists at all.
        "carrier": carrier,
        # The evidence pack's hash, shown beside the download button. Built
        # from the same facts the PDF is built from, so the number on the
        # page is the number inside the file.
        "evidence_pack_hash": _evidence_pack_hash(_pack_facts(request, dispute_id, snapshot)),
        # Shown in the readiness checklist as supporting evidence, labelled
        # "carrier-reported" and never "verified". Present only when a
        # carrier_reported fact actually exists.
        "carrier_support": _carrier_support(facts),
    }


def _amount_of(value: Any) -> Decimal:
    """A dispute amount as a Decimal, or zero when it is absent or unusable."""
    if value is None or isinstance(value, bool):
        return Decimal("0")
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return Decimal("0")


def _money(amount: Decimal, currency: str = "") -> str:
    text = f"{amount:,.2f}"
    return f"{text} {currency}".strip() if currency else text


def _deadline_ring(deadline: dict[str, Any]) -> str:
    """CSS modifier for the deadline ring: critical, soon, ok or unknown."""
    hours = deadline.get("hours_left")
    if hours is None:
        return "unknown"
    if hours <= 0:
        return "critical"
    if hours < 48:
        return "soon"
    return "ok"


def _due_week(value: Any) -> str | None:
    """The ISO week a deadline falls in, e.g. "W07 2026", for exposure bars."""
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    year, week, _ = stamp.isocalendar()
    return f"W{week:02d} {year}"


def _bars(values: dict[str, Decimal], currency: str = "") -> list[dict[str, Any]]:
    """Labeled bars scaled to the largest value, for the inline SVG charts.

    Counts are shown as integers; pass a currency to show money instead.
    """
    items = sorted(values.items())
    top = max((value for _, value in items), default=Decimal("0"))
    bars = []
    for label, value in items:
        pct = 0.0 if top == 0 else float(value / top) * 100.0
        shown = _money(value, currency) if currency else str(int(value))
        bars.append({"label": label, "value": shown, "pct": round(pct, 1)})
    return bars


def _overview_data(request: Request) -> dict[str, Any]:
    """Everything the overview tiles, lists and charts need.

    Reads persisted case views and the audit log only: no Reader run, no
    PayPal call, no model call. Opening the overview costs nothing.
    """
    services = _services(request)
    cases: list[dict[str, Any]] = []
    currency = ""

    for dispute_id in services.list_dispute_ids():
        view = services.case_view(dispute_id)
        if view is None:
            continue
        facts = view.facts
        deadline = _deadline_info(facts.value("seller_response_due_date") if facts else None)
        if facts is not None and not currency and facts.value("dispute_currency"):
            currency = str(facts.value("dispute_currency"))
        cases.append(
            {
                "dispute_id": dispute_id,
                "amount": _amount_of(facts.value("dispute_amount") if facts else None),
                "currency": str(facts.value("dispute_currency") or "") if facts else "",
                "reason": str(facts.value("reason") or "") if facts else "",
                "deadline": deadline,
                "awaiting_approval": PROVIDE_EVIDENCE in view.decision.allowed_actions,
                "reader_pending": view.reader_pending,
                "status_label": status_label(view.status),
            }
        )

    at_risk = sum((case["amount"] for case in cases), Decimal("0"))
    awaiting = sum(1 for case in cases if case["awaiting_approval"])

    soonest = None
    for case in cases:
        if case["deadline"]["hours_left"] is None:
            continue
        if soonest is None or case["deadline"]["hours_left"] < soonest["deadline"]["hours_left"]:
            soonest = case

    needs_you = []
    for case in cases:
        urgent = case["deadline"]["urgent"]
        if not (urgent or case["awaiting_approval"] or case["reader_pending"]):
            continue
        if case["awaiting_approval"] and urgent:
            why = "Approve before the deadline"
        elif case["awaiting_approval"]:
            why = "Evidence ready to approve"
        elif case["reader_pending"]:
            why = "Reader still needs a look"
        else:
            why = "Deadline approaching"
        hours = case["deadline"]["hours_left"]
        # Fraction of a week still on the clock, clamped. Rendered as an SVG
        # arc length so the ring carries no inline style.
        fraction = 0.0 if hours is None else max(min(hours / 168.0, 1.0), 0.0)
        needs_you.append(
            {
                **case,
                "ring": _deadline_ring(case["deadline"]),
                "ring_arc": round(100.53 * fraction, 1),
                "why": why,
            }
        )
    needs_you.sort(
        key=lambda case: (case["deadline"]["hours_left"] is None, case["deadline"]["hours_left"])
    )

    reasons: dict[str, Decimal] = {}
    weeks: dict[str, Decimal] = {}
    for case in cases:
        if case["reason"]:
            reasons[case["reason"]] = reasons.get(case["reason"], Decimal("0")) + 1
        week = _due_week(case["deadline"]["iso"])
        if week:
            weeks[week] = weeks.get(week, Decimal("0")) + case["amount"]

    feed = []
    for entry in services.audit.entries()[-14:]:
        feed.append(
            {
                "ts": _display_timestamp(entry.ts),
                "actor": entry.actor,
                "action": entry.action,
                "dispute_id": entry.dispute_id or "",
                "origin": ORIGIN_LABELS.get(entry.origin_tag, entry.origin_tag),
            }
        )
    feed.reverse()

    return {
        "tiles": {
            "open": len(cases),
            "at_risk": _money(at_risk, currency),
            "at_risk_raw": float(at_risk),
            "currency": currency,
            "awaiting_approval": awaiting,
            "next_deadline": soonest["deadline"]["label"] if soonest else "none",
            "next_deadline_id": soonest["dispute_id"] if soonest else "",
        },
        "needs_you": needs_you[:8],
        "reason_bars": _bars(reasons),
        "week_bars": _bars(weeks, currency),
        "feed": feed,
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
    response = RedirectResponse("/overview", status_code=303)
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
def landing_page(request: Request) -> Response:
    """The public landing page. No session required.

    Proof numbers come from the evaluation summary on disk. When it is
    absent the page says so plainly rather than showing invented numbers.
    """
    services = _services(request)
    results = load_results(
        services.config.results_path, services.config.results_notes_path
    )
    return templates.TemplateResponse(
        request, "landing.html", _context(request, results=results)
    )


@router.get("/overview", response_class=HTMLResponse)
def overview_page(request: Request) -> Response:
    return templates.TemplateResponse(
        request, "overview.html", _context(request, **_overview_data(request))
    )


@router.get("/cases", response_class=HTMLResponse)
def cases_page(request: Request) -> Response:
    return templates.TemplateResponse(request, "cases.html", _context(request))


# -- order ledger -------------------------------------------------------


def _order_rows(records) -> list[dict[str, Any]]:
    """Display rows for the ledger table. Codes, ids and amounts only."""
    rows = []
    for record in records:
        rows.append(
            {
                "row_id": record.row_id,
                "version": record.version,
                "seller_transaction_id": record.seller_transaction_id,
                "order_ref": record.order_ref,
                "carrier": record.carrier,
                "tracking_number": record.tracking_number,
                "shipped_at": record.shipped_at,
                "delivered_at": record.delivered_at,
                "amount": record.amount,
                "currency": record.currency,
                "item_label": record.item_label,
                "source": record.source,
                "recorded_at": _display_timestamp(record.recorded_at),
            }
        )
    return rows


def _orders_context(
    request: Request,
    *,
    notice: str | None = None,
    errors: list[str] | None = None,
    preview: list[dict[str, Any]] | None = None,
    csv_text: str = "",
    form: dict[str, str] | None = None,
) -> dict[str, Any]:
    services = _services(request)
    return _context(
        request,
        orders=_order_rows(services.list_orders()),
        notice=notice,
        errors=errors or [],
        preview=preview,
        csv_text=csv_text,
        form=form or {},
        item_label_max=ITEM_LABEL_MAX_LENGTH,
        csv_columns=list(ORDER_CSV_COLUMNS),
        ledger_api_key_set=services.config.ledger_api_key_is_set,
    )


_FORM_FIELDS = (
    "seller_transaction_id",
    "order_ref",
    "carrier",
    "tracking_number",
    "shipped_at",
    "delivered_at",
    "amount",
    "currency",
    "item_label",
)


def _submitted_order(form: Mapping[str, str]) -> dict[str, str]:
    return {name: (form.get(name, "") or "").strip() for name in _FORM_FIELDS}


@router.get("/orders", response_class=HTMLResponse)
def orders_page(request: Request) -> Response:
    return templates.TemplateResponse(request, "orders.html", _orders_context(request))


@router.post("/orders/add", response_class=HTMLResponse)
def orders_add(
    request: Request,
    seller_transaction_id: str = Form(""),
    order_ref: str = Form(""),
    carrier: str = Form(""),
    tracking_number: str = Form(""),
    shipped_at: str = Form(""),
    delivered_at: str = Form(""),
    amount: str = Form(""),
    currency: str = Form(""),
    item_label: str = Form(""),
    csrf_token: str = Form(""),
) -> Response:
    """Add or update one ledger row by hand.

    The row is validated to exactly the ledger schema before it is stored.
    recorded_at is set by the server, never accepted from the form, so the
    recorded_before_dispute test stays honest.
    """
    if not _csrf_ok(request, csrf_token):
        return _csrf_failure(request)

    services = _services(request)
    submitted = {
        "seller_transaction_id": seller_transaction_id,
        "order_ref": order_ref,
        "carrier": carrier,
        "tracking_number": tracking_number,
        "shipped_at": shipped_at,
        "delivered_at": delivered_at,
        "amount": amount,
        "currency": currency,
        "item_label": item_label,
    }
    submitted = _submitted_order(submitted)

    try:
        order = parse_order(submitted)
    except OrderLedgerError as error:
        return templates.TemplateResponse(
            request,
            "orders.html",
            _orders_context(
                request,
                errors=_readable_errors(error),
                form=submitted,
            ),
            status_code=400,
        )

    record, status = services.ingest_order(order, "manual")
    services.audit.append(
        actor="admin",
        action=f"web.order_{status}",
        origin_tag=OriginTag.SELLER_APPROVAL,
        payload={"row_id": record.row_id, "version": record.version},
    )
    return RedirectResponse("/orders", status_code=303)


@router.post("/orders/import", response_class=HTMLResponse)
def orders_import(
    request: Request,
    csv_text: str = Form(""),
    commit: str = Form(""),
    csrf_token: str = Form(""),
) -> Response:
    """Validate a pasted CSV, then import it once the operator confirms.

    Validation always runs first. Nothing is written until the same text is
    submitted again with commit=yes, so a bad file never half-imports.
    """
    if not _csrf_ok(request, csrf_token):
        return _csrf_failure(request)

    services = _services(request)
    text = csv_text or ""
    if len(text) > ORDER_CSV_MAX_CHARS:
        return templates.TemplateResponse(
            request,
            "orders.html",
            _orders_context(
                request,
                errors=[f"CSV is too large; keep it under {ORDER_CSV_MAX_CHARS} characters."],
                csv_text=text,
            ),
            status_code=400,
        )

    rows, errors = _parse_order_csv(text)
    if errors:
        return templates.TemplateResponse(
            request,
            "orders.html",
            _orders_context(request, errors=errors, csv_text=text),
            status_code=400,
        )
    if not rows:
        return templates.TemplateResponse(
            request,
            "orders.html",
            _orders_context(
                request, errors=["No data rows found in the CSV."], csv_text=text
            ),
            status_code=400,
        )

    if commit != "yes":
        preview = [
            {"line": line, **_submitted_order(row.model_dump())}
            for line, row in rows
        ]
        return templates.TemplateResponse(
            request,
            "orders.html",
            _orders_context(
                request,
                notice=f"{len(rows)} row(s) validated. Confirm to import.",
                preview=preview,
                csv_text=text,
            ),
        )

    counts = {"inserted": 0, "updated": 0, "unchanged": 0}
    for _line, order in rows:
        _record, status = services.ingest_order(order, "csv")
        counts[status] = counts.get(status, 0) + 1

    services.audit.append(
        actor="admin",
        action="web.orders_imported",
        origin_tag=OriginTag.SELLER_APPROVAL,
        payload=counts,
    )
    return templates.TemplateResponse(
        request,
        "orders.html",
        _orders_context(
            request,
            notice=(
                f"Imported {len(rows)} row(s): "
                f"{counts['inserted']} inserted, {counts['updated']} updated, "
                f"{counts['unchanged']} unchanged."
            ),
        ),
    )


def _parse_order_csv(text: str) -> tuple[list[tuple[int, Any]], list[str]]:
    """Parse pasted CSV into validated orders. Returns (rows, error strings).

    Errors name the line and the field, never the value, so a bad import
    cannot echo attacker-controlled text back into the page unquoted.
    """
    if not text.strip():
        return [], ["Paste CSV text to import."]

    reader = csv.DictReader(StringIO(text))
    if reader.fieldnames is None:
        return [], ["The CSV has no header row."]

    header = {(name or "").strip() for name in reader.fieldnames}
    missing = [name for name in ORDER_CSV_REQUIRED if name not in header]
    if missing:
        return [], [f"The CSV is missing required column(s): {', '.join(missing)}."]

    rows: list[tuple[int, Any]] = []
    errors: list[str] = []
    for line, raw in enumerate(reader, start=2):
        if line - 1 > ORDER_CSV_MAX_ROWS:
            errors.append(f"Too many rows; the limit is {ORDER_CSV_MAX_ROWS}.")
            break
        values = {name: (raw.get(name, "") or "").strip() for name in ORDER_CSV_COLUMNS}
        try:
            rows.append((line, parse_order(values)))
        except OrderLedgerError as error:
            for message in _readable_errors(error):
                errors.append(f"Row {line}: {message}")
    return rows, errors


def _orders_authorized(request: Request) -> bool:
    """Constant-time bearer check against the configured ingest key."""
    expected = _services(request).config.ledger_api_key
    if not expected:
        return False
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return False
    return hmac.compare_digest(token.strip(), expected)


@router.post("/api/orders")
async def api_orders(request: Request) -> Response:
    """Machine ingest for the ledger. Bearer token, constant-time, rate-limited.

    Never trusts a recorded_at from the caller: the ledger stamps it. The
    bearer key is compared with hmac.compare_digest and is never echoed.
    """
    services = _services(request)
    if not services.config.ledger_api_key_is_set:
        return JSONResponse({"error": "ledger_ingest_disabled"}, status_code=503)
    if not _orders_authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    client = _client_address(request)
    allowed, wait = services.order_limiter.check(client)
    if not allowed:
        response = JSONResponse({"error": "rate_limited"}, status_code=429)
        response.headers["Retry-After"] = str(wait)
        return response
    services.order_limiter.record(client)

    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - any malformed body is a bad request
        return JSONResponse({"error": "invalid_json"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "invalid_body"}, status_code=400)

    try:
        order = parse_order(body)
    except OrderLedgerError as error:
        return JSONResponse({"error": "invalid_order", "detail": _readable_errors(error)}, status_code=422)

    record, status = services.ingest_order(order, "api")
    services.audit.append(
        actor="api",
        action=f"api.order_{status}",
        origin_tag=OriginTag.SELLER_APPROVAL,
        payload={"row_id": record.row_id, "version": record.version},
    )
    code = 201 if status == "inserted" else 200
    return JSONResponse(
        {"status": status, "row_id": record.row_id, "version": record.version},
        status_code=code,
    )


def _lab_context(
    request: Request,
    *,
    result: dict[str, Any] | None = None,
    submitted: str = "",
    error: str | None = None,
    source: str = "custom",
    preset_id: str | None = None,
) -> dict[str, Any]:
    """Render context for the Attack Lab. Carries no buyer text but `submitted`."""
    services = _services(request)
    return _context(
        request,
        presets=services.lab_presets(),
        remaining=services.lab_daily_remaining(),
        daily_cap=services.config.lab_daily_cap,
        per_minute=services.config.lab_per_minute,
        message_max=LAB_MESSAGE_MAX_CHARS,
        reader_configured=services.config.reader_is_configured,
        result=result,
        submitted=submitted,
        error=error,
        source=source,
        preset_id=preset_id,
    )


@router.get("/lab", response_class=HTMLResponse)
def lab_page(request: Request) -> Response:
    return templates.TemplateResponse(request, "lab.html", _lab_context(request))


@router.post("/lab", response_class=HTMLResponse)
def lab_submit(
    request: Request,
    message: str = Form(""),
    preset: str = Form(""),
    csrf_token: str = Form(""),
) -> Response:
    """Run one comparison: a naive tool-calling agent beside Orrix.

    Guards, in order: CSRF, a non-empty message, the length ceiling on free
    text, the per-session per-minute limit, and the deployment-wide daily
    cap. Presets are author-written corpus text and bypass the length check;
    a free-text message is capped at LAB_MESSAGE_MAX_CHARS.
    """
    services = _services(request)
    if not _csrf_ok(request, csrf_token):
        return _csrf_failure(request)

    chosen = services.find_preset(preset)
    if chosen is not None:
        buyer_text = chosen["text"]
        source = "preset"
        preset_id = chosen["id"]
    else:
        buyer_text = (message or "").strip()
        source = "custom"
        preset_id = None

    if not buyer_text:
        return templates.TemplateResponse(
            request,
            "lab.html",
            _lab_context(
                request,
                submitted=message or "",
                error="Paste a buyer message or choose a preset.",
            ),
            status_code=400,
        )

    if source == "custom" and len(buyer_text) > LAB_MESSAGE_MAX_CHARS:
        return templates.TemplateResponse(
            request,
            "lab.html",
            _lab_context(
                request,
                submitted=buyer_text,
                error=f"Keep the message to {LAB_MESSAGE_MAX_CHARS} characters or fewer.",
            ),
            status_code=400,
        )

    session_id = _session_id(request) or ""
    allowed, wait = services.lab_limiter.check(session_id)
    if not allowed:
        response = templates.TemplateResponse(
            request,
            "lab.html",
            _lab_context(
                request,
                submitted=buyer_text,
                source=source,
                preset_id=preset_id,
                error=(
                    f"Limited to {services.config.lab_per_minute} runs per minute. "
                    f"Try again in {wait}s."
                ),
            ),
            status_code=429,
        )
        response.headers["Retry-After"] = str(wait)
        return response

    if services.lab_daily_remaining() <= 0:
        response = templates.TemplateResponse(
            request,
            "lab.html",
            _lab_context(
                request,
                submitted=buyer_text,
                source=source,
                preset_id=preset_id,
                error="The daily lab limit has been reached. Try again tomorrow (UTC).",
            ),
            status_code=429,
        )
        response.headers["Retry-After"] = "3600"
        return response

    result = services.run_lab(buyer_text, source=source, preset_id=preset_id)
    services.lab_limiter.record(session_id)

    return templates.TemplateResponse(
        request,
        "lab.html",
        _lab_context(
            request,
            result=result,
            submitted=buyer_text,
            source=source,
            preset_id=preset_id,
        ),
    )


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


@router.get("/cases/{dispute_id}/evidence.pdf")
def evidence_pack_pdf(request: Request, dispute_id: str) -> Response:
    """The one-page evidence pack, built from Facts through a fixed layout.

    Session-guarded like every other case route. Served uncached, as an
    attachment, with nosniff: it is a generated document, not a page, and
    nothing about it should be stored by an intermediary.

    This route makes no PayPal call and changes nothing. Attaching the file
    to the dispute itself is not implemented; see the README.
    """
    services = _services(request)
    snapshot = services.case_snapshot(dispute_id)
    if snapshot is None:
        return templates.TemplateResponse(
            request, "not_found.html", _context(request, dispute_id=dispute_id), status_code=404
        )

    # Built through the same helper the page's hash uses, so the digest shown
    # beside the button is always the digest inside the file. No carrier
    # lookup: a download must not be a way to spend the carrier budget.
    facts = _pack_facts(request, dispute_id, snapshot)
    if facts is None:
        return templates.TemplateResponse(
            request, "not_found.html", _context(request, dispute_id=dispute_id), status_code=404
        )

    try:
        pdf_bytes, content_hash = render_pdf(facts)
    except EvidencePackError as error:
        logger.warning("evidence pack unavailable dispute_id=%s: %s", dispute_id, error)
        return templates.TemplateResponse(
            request, "not_found.html", _context(request, dispute_id=dispute_id), status_code=404
        )

    services.audit.append(
        actor="admin",
        action="web.evidence_pack_downloaded",
        origin_tag=OriginTag.SYSTEM,
        dispute_id=dispute_id,
        payload=content_hash,
    )

    filename = f"orrix-evidence-{dispute_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
            # The hash is in the file; repeating it in a header lets a
            # script check the download without parsing the PDF.
            "X-Orrix-Content-Hash": content_hash,
        },
    )


@router.post("/cases/{dispute_id}/check-carrier", response_class=HTMLResponse)
def check_carrier(request: Request, dispute_id: str, csrf_token: str = Form("")) -> Response:
    """Ask the carrier for a fresh reading on this case.

    Refused when the connector is off, when there is no seller-supplied
    tracking number to ask about, or when this case was checked less than
    CARRIER_CHECK_COOLDOWN_SECONDS ago. Every refusal is a notice on the
    page, never an exception.
    """
    if not _csrf_ok(request, csrf_token):
        return _csrf_failure(request)

    services = _services(request)
    snapshot = services.case_snapshot(dispute_id)
    if snapshot is None:
        return templates.TemplateResponse(
            request, "not_found.html", _context(request, dispute_id=dispute_id), status_code=404
        )

    if not services.carrier_enabled:
        # Nothing to audit and nothing to spend: the connector is off.
        services.set_carrier_notice(
            dispute_id,
            {
                "status": "disabled",
                "message": "The carrier connector is off. Set CARRIER_ENABLED to use it.",
            },
        )
        return RedirectResponse(f"/cases/{dispute_id}", status_code=303)

    allowed, retry_after = services.carrier_check_ready(dispute_id)
    if not allowed:
        services.set_carrier_notice(
            dispute_id,
            {
                "status": "rate_limited",
                "message": (
                    f"A carrier check is limited to once every "
                    f"{CARRIER_CHECK_COOLDOWN_SECONDS} seconds for a case. "
                    f"Try again in {retry_after}s."
                ),
            },
        )
        services.audit.append(
            actor="admin",
            action="web.carrier_check_refused:rate_limited",
            origin_tag=OriginTag.SYSTEM,
            dispute_id=dispute_id,
            payload=None,
        )
        return RedirectResponse(f"/cases/{dispute_id}", status_code=303)

    services.record_carrier_check(dispute_id)
    case = _load_case(request, dispute_id, force_carrier=True)
    if case is None:
        return templates.TemplateResponse(
            request, "not_found.html", _context(request, dispute_id=dispute_id), status_code=404
        )

    carrier = case.get("carrier") or {}
    if not carrier.get("has_tracking"):
        services.set_carrier_notice(
            dispute_id,
            {
                "status": "no_tracking",
                "message": (
                    "No seller-supplied tracking number on this case, so there is "
                    "nothing to look up. Add the order to the ledger or enter "
                    "tracking above."
                ),
            },
        )
        return RedirectResponse(f"/cases/{dispute_id}", status_code=303)

    status = carrier.get("status") or "unavailable"
    services.set_carrier_notice(
        dispute_id,
        {
            "status": status,
            "message": f"Carrier reported: {status.replace('_', ' ')}.",
        },
    )
    return RedirectResponse(f"/cases/{dispute_id}", status_code=303)


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
    # Overlay the ledger the same way the executor will, so the payload shown
    # and approved is the payload the executor rebuilds and checks.
    facts, ledger_row = apply_matched(services.order_ledger, facts)

    try:
        payload = build_evidence_payload(facts)
    except ValueError as error:
        services.set_result(
            dispute_id, {"status": "refused", "reason": "no_payload", "message": str(error)}
        )
        return RedirectResponse(f"/cases/{dispute_id}", status_code=303)

    # The carrier reading the seller was looking at, if any. Bound into the
    # approval id, so a different reading at execution time refuses the
    # write. Both None whenever the connector is off, which leaves the id
    # exactly what it was before the connector existed.
    carrier_status, carrier_checked_at = services.carrier_binding_for(dispute_id)

    try:
        approval = create_approval(
            dispute_id=dispute_id,
            action=PROVIDE_EVIDENCE,
            payload=payload,
            dispute_version=current,
            ledger_row_id=ledger_row.row_id if ledger_row else None,
            ledger_row_version=ledger_row.version if ledger_row else None,
            carrier_status=carrier_status,
            carrier_checked_at=carrier_checked_at,
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

    result = execute(
        approval, services.executor_deps(seller_input=seller_input, dispute_id=dispute_id)
    )

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


@router.post("/cases/{dispute_id}/rerun-reader", response_class=HTMLResponse)
def rerun_reader(
    request: Request, dispute_id: str, csrf_token: str = Form("")
) -> Response:
    """Force a fresh Reader read for this case, bypassing the cached result.

    Rate-limited to one actual run per case per RERUN_COOLDOWN_SECONDS, so a
    stuck page cannot be used to spend the model budget by repeated clicks.
    An attempt while the Reader is not configured is refused before the
    rate limit is even checked, since it costs nothing and the operator
    should be told clearly rather than see a generic "needs_review".
    """
    if not _csrf_ok(request, csrf_token):
        return _csrf_failure(request)

    services = _services(request)
    snapshot = services.case_snapshot(dispute_id)
    if snapshot is None:
        return templates.TemplateResponse(
            request, "not_found.html", _context(request, dispute_id=dispute_id), status_code=404
        )

    if not services.config.reader_is_configured:
        services.set_rerun_notice(
            dispute_id,
            {
                "status": "not_configured",
                "message": "The Reader is not configured: set READER_API_KEY to enable it.",
            },
        )
        services.audit.append(
            actor="admin",
            action="web.reader_rerun_refused:reader_not_configured",
            origin_tag=OriginTag.SYSTEM,
            dispute_id=dispute_id,
            payload=None,
        )
        return RedirectResponse(f"/cases/{dispute_id}", status_code=303)

    allowed, retry_after = services.rerun_ready(dispute_id)
    if not allowed:
        services.set_rerun_notice(
            dispute_id,
            {
                "status": "rate_limited",
                "message": (
                    f"Re-run is limited to once every {RERUN_COOLDOWN_SECONDS} "
                    f"seconds. Try again in {retry_after}s."
                ),
            },
        )
        services.audit.append(
            actor="admin",
            action="web.reader_rerun_refused:rate_limited",
            origin_tag=OriginTag.SYSTEM,
            dispute_id=dispute_id,
            payload=None,
        )
        return RedirectResponse(f"/cases/{dispute_id}", status_code=303)

    services.record_rerun(dispute_id)
    seller_input = services.get_seller_input(dispute_id)
    # reuse_reader=False bypasses the cached result for this update_time, so
    # this is the one path that re-reads a dispute the model has already
    # seen.
    view = process_case(
        snapshot, services.pipeline_deps, seller_input=seller_input, reuse_reader=False
    )

    services.audit.append(
        actor="admin",
        action=f"web.reader_rerun:{view.reader_result.status}:{view.reader_result.reason or 'ok'}",
        origin_tag=OriginTag.READER_OUTPUT,
        dispute_id=dispute_id,
        payload=None,
    )
    services.set_rerun_notice(
        dispute_id,
        {"status": "ran", "message": "Reader re-run complete; the result below is new."},
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
    if result.reason == "stale_carrier":
        return (
            "The carrier reading changed between approval and execution. Nothing was "
            "sent. Review the updated case and approve again."
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
    # An OrderLedgerError already carries value-free "field: reason" lines.
    if isinstance(error, OrderLedgerError) and error.errors:
        return list(error.errors)
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


#: Entries per /api/audit page. The log reaches five figures on a running
#: deployment -- rendering it whole was a 1.6 MB response and a frozen page.
AUDIT_PAGE_SIZE = 100
AUDIT_MAX_PAGE_SIZE = 500


@router.get("/api/audit")
def api_audit(request: Request, limit: int = AUDIT_PAGE_SIZE, before_seq: int | None = None) -> Response:
    """One page of audit rows, newest first, with integrity decided server-side.

    The browser is told whether each row verifies; it never recomputes a
    hash itself, so the grid cannot disagree with the server about what is
    intact.

    Paging is display-only. `verify_chain` still walks the entire chain on
    every request, so `chain_ok` and `first_bad_seq` describe the whole log
    and not just the page -- a break below the page still reports as a
    break. `before_seq` is a keyset cursor: the lowest seq already held.
    """
    services = _services(request)

    try:
        page_size = max(1, min(int(limit), AUDIT_MAX_PAGE_SIZE))
    except (TypeError, ValueError):
        page_size = AUDIT_PAGE_SIZE

    cursor: int | None = None
    if before_seq is not None:
        try:
            cursor = int(before_seq)
        except (TypeError, ValueError):
            cursor = None

    entries = services.audit.recent(limit=page_size, before_seq=cursor)
    # The whole chain, every time: integrity is never inferred from a page.
    bad_seq = services.audit.verify_chain()
    total = services.audit.count()
    oldest = services.audit.oldest_seq()

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

    # Rows come back newest first, so the last one is the lowest seq on this
    # page and therefore the cursor for the page below it.
    lowest_seq = rows[-1]["seq"] if rows else None
    has_more = bool(rows) and oldest is not None and lowest_seq is not None and lowest_seq > oldest

    return JSONResponse(
        {
            "rows": rows,
            "chain_ok": bad_seq is None,
            "first_bad_seq": bad_seq,
            "keyed": bool(services.audit.config.hmac_key),
            # Rows on this page, and the size of the whole log. `entries`
            # keeps its old meaning of "rows in this response"; `total` is
            # what the chain banner counts as verified.
            "entries": len(rows),
            "total": total,
            "page_size": page_size,
            "has_more": has_more,
            "next_before_seq": lowest_seq if has_more else None,
            "oldest_seq": oldest,
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
