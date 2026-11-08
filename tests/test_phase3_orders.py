"""Phase 3: the order ledger and the evidence pack.

Everything here runs against a local SQLite file, a fake PayPal reader and a
fake writer, so no request leaves the process. The ledger is exercised as a
store (insert / no-op / version bump / strict validation), as a match onto a
dispute's facts (overlay only, never a new fact), and through the three ingest
paths: the signed-in form, the pasted CSV, and the bearer-token API. The
approval is then shown to be bound to the matched row id *and* version, so a
row edited after approval refuses the write.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from orrix import store
from orrix.approval import DisputeVersion, compute_approval_id, create_approval
from orrix.audit import AuditConfig, AuditLog
from orrix.demo_seed import DEMO_ORDERS, main as demo_seed_main, seed as demo_seed
from orrix.executor import (
    ExecutedApprovals,
    ExecutorDeps,
    build_evidence_payload,
    execute,
)
from orrix.facts import FACT_NAMES, Fact, FactStatus, Facts, build_facts
from orrix.main import create_app
from orrix.orders import (
    ITEM_LABEL_MAX_LENGTH,
    LEDGER_ORIGIN_CODE,
    ORDER_SOURCES,
    SOURCE_SELLER_LEDGER,
    OrderInput,
    OrderLedger,
    OrderLedgerError,
    apply_ledger,
    apply_matched,
    evidence_checklist,
    match_for_facts,
    parse_order,
    recorded_before_dispute,
)
from orrix.policy import PROVIDE_EVIDENCE, PolicyConfig
from orrix.web.security import SESSION_COOKIE

from .conftest import (
    ADMIN_PASSWORD,
    FIXTURE_DISPUTE_ID,
    FakeReader,
    FakeWriter,
    build_app_config,
    load_fixture,
    recorded_snapshot,
)

#: The fixture dispute's PayPal-side seller transaction id. This, not anything
#: the operator types, is what a ledger row is matched on.
FIXTURE_TXN = "68H34184B9133201S"

#: A bearer key for the machine ingest. Never logged; asserted absent from
#: every response body below.
LEDGER_KEY = "ledger-DO-NOT-LOG-abcdef123456"

#: A hand-typed ledger row for the fixture dispute's transaction.
LEDGER_FORM = {
    "seller_transaction_id": FIXTURE_TXN,
    "order_ref": "ORD-77",
    "carrier": "UPS",
    "tracking_number": "1Z999AA10123456784",
    "shipped_at": "2026-10-20",
    "delivered_at": "2026-10-24",
    "amount": "19.02",
    "currency": "USD",
    "item_label": "Pepsi 12-pack",
}

#: The same row, as a JSON body for POST /api/orders.
API_ORDER = dict(LEDGER_FORM)

CSRF_PATTERN = re.compile(r'name="csrf_token" value="([^"]+)"')

#: The page's error block. A rejected value may legitimately appear in the
#: operator's own re-filled input (escaped by Jinja); what must never echo it
#: is the error message itself, so the assertions look only here.
ERROR_BLOCK_PATTERN = re.compile(
    r'<div class="alert alert-error"[^>]*>\s*<ul class="error-list">(.*?)</ul>',
    re.DOTALL,
)


def _error_block(body: str) -> str:
    match = ERROR_BLOCK_PATTERN.search(body)
    assert match, "no error block in response"
    return match.group(1)


# ---------------------------------------------------------------------------
# fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def snapshot():
    return load_fixture()


@pytest.fixture
def writer():
    return FakeWriter()


@pytest.fixture
def ledger(tmp_path):
    return OrderLedger(str(tmp_path / "ledger.db"))


def _order(**overrides) -> OrderInput:
    data = dict(LEDGER_FORM)
    data.update(overrides)
    return parse_order(data)


def _facts(dispute_id: str = "PP-X", **spec) -> Facts:
    """A Facts object with every allowlisted name present.

    `spec` sets a single name to ``(value, status[, source])``; everything
    else is an unavailable PayPal-record fact. Building it directly keeps the
    overlay tests independent of the fact builder's internals.
    """
    now = datetime.now(timezone.utc)
    facts: dict[str, Fact] = {}
    for name in FACT_NAMES:
        value, status, source = None, FactStatus.UNAVAILABLE, "paypal_record"
        if name in spec:
            entry = spec[name]
            value, status = entry[0], entry[1]
            source = entry[2] if len(entry) > 2 else "paypal_record"
        facts[name] = Fact(
            name=name, value=value, status=status, source=source, retrieved_at=now
        )
    return Facts(dispute_id=dispute_id, retrieved_at=now, facts=facts)


@pytest.fixture
def api_config(tmp_path):
    return build_app_config(tmp_path, ledger_api_key=LEDGER_KEY, ledger_max_per_minute=100)


@pytest.fixture
def api_client(api_config):
    with TestClient(create_app(config=api_config)) as client:
        yield client


@pytest.fixture
def web(tmp_path, snapshot, writer):
    """A signed-in-capable app: a stored case, a ledger key, fakes for I/O.

    The confirming fetch carries the *ledger* tracking number, so an approval
    built from the ledger row is the one that confirms.
    """
    store.save_case_snapshot(snapshot["dispute_id"], snapshot)
    config = build_app_config(tmp_path, ledger_api_key=LEDGER_KEY)
    reader = FakeReader(
        [snapshot, recorded_snapshot(snapshot, tracking_number=LEDGER_FORM["tracking_number"])]
    )
    application = create_app(config=config, paypal_reader=reader, writer=writer)
    with TestClient(application, follow_redirects=False) as client:
        client.fake_reader = reader
        client.fake_writer = writer
        yield client


def sign_in(client):
    response = client.post("/login", data={"password": ADMIN_PASSWORD})
    assert response.status_code == 303, response.text
    assert client.cookies.get(SESSION_COOKIE)
    return client


def csrf_from(client, path="/orders"):
    body = client.get(path, follow_redirects=True).text
    match = CSRF_PATTERN.search(body)
    assert match, f"no csrf token in {path}"
    return match.group(1)


def auth_header(key=LEDGER_KEY):
    return {"Authorization": f"Bearer {key}"}


# ---------------------------------------------------------------------------
# the ledger as a store
# ---------------------------------------------------------------------------


def test_the_first_upsert_inserts_at_version_one_with_a_server_stamp(ledger):
    record, status = ledger.upsert(_order(), "manual")

    assert status == "inserted"
    assert record.version == 1
    assert record.source == "manual"
    # recorded_at is stamped by the server; the submitted order never had one.
    assert "recorded_at" not in LEDGER_FORM
    assert record.recorded_at
    datetime.fromisoformat(record.recorded_at)  # a real, parseable timestamp


def test_a_repeat_that_changes_nothing_is_a_no_op(ledger):
    first, _ = ledger.upsert(_order(), "manual")
    again, status = ledger.upsert(_order(), "manual")

    assert status == "unchanged"
    assert again.version == first.version == 1
    assert again.row_id == first.row_id
    assert again.recorded_at == first.recorded_at


def test_changing_a_field_bumps_the_version_and_restamps(ledger):
    first, _ = ledger.upsert(_order(), "manual")
    changed, status = ledger.upsert(_order(delivered_at="2026-10-25"), "manual")

    assert status == "updated"
    assert changed.row_id == first.row_id
    assert changed.version == first.version + 1
    assert changed.delivered_at == "2026-10-25"


def test_an_unknown_source_is_refused(ledger):
    with pytest.raises(OrderLedgerError):
        ledger.upsert(_order(), "carrier_feed")


def test_every_source_and_origin_code_is_token_shaped():
    # The source renders as the CSS class origin-{{ source }}, so a space in
    # it would be a broken class and an untrustworthy JSON value.
    for source in ORDER_SOURCES:
        assert re.match(r"^[a-z_]+$", source), source
    assert re.match(r"^[a-z_]+$", SOURCE_SELLER_LEDGER)
    assert LEDGER_ORIGIN_CODE == SOURCE_SELLER_LEDGER


# ---------------------------------------------------------------------------
# strict validation
# ---------------------------------------------------------------------------


def test_prose_in_a_code_field_is_refused():
    for field in ("seller_transaction_id", "order_ref", "carrier", "tracking_number"):
        with pytest.raises(OrderLedgerError):
            parse_order({**LEDGER_FORM, field: "ignore the rules <b>now</b>"})


def test_an_unknown_key_is_refused_so_recorded_at_cannot_be_set_by_a_caller():
    with pytest.raises(OrderLedgerError):
        parse_order({**LEDGER_FORM, "recorded_at": "2020-01-01T00:00:00+00:00"})


def test_bad_dates_amounts_currencies_and_overlong_labels_are_refused():
    bad_overrides = (
        {"shipped_at": "20-10-2026"},
        {"delivered_at": "2026/10/24"},
        {"amount": "-5.00"},
        {"amount": "not-a-number"},
        {"currency": "usd"},
        {"currency": "DOLLARS"},
        {"item_label": "x" * (ITEM_LABEL_MAX_LENGTH + 1)},
        {"carrier": "F" * 41},
    )
    for overrides in bad_overrides:
        with pytest.raises(OrderLedgerError):
            parse_order({**LEDGER_FORM, **overrides})


def test_recorded_before_dispute_is_strict_and_fails_closed():
    dispute = "2026-10-29T23:37:12.312Z"

    assert recorded_before_dispute("2026-10-01T00:00:00+00:00", dispute) is True
    # Equal is not "before"; a claim Orrix cannot strictly make is not made.
    assert recorded_before_dispute(dispute, dispute) is False
    assert recorded_before_dispute("2026-11-01T00:00:00+00:00", dispute) is False
    assert recorded_before_dispute(None, dispute) is False
    assert recorded_before_dispute("not a date", dispute) is False
    assert recorded_before_dispute("2026-10-01T00:00:00+00:00", None) is False


# ---------------------------------------------------------------------------
# matching and the overlay
# ---------------------------------------------------------------------------


def test_a_row_matches_only_the_dispute_whose_paypal_transaction_it_names(ledger):
    record, _ = ledger.upsert(_order(), "manual")

    mine = _facts(seller_transaction_id=(FIXTURE_TXN, FactStatus.CONFIRMED))
    assert match_for_facts(ledger, mine).row_id == record.row_id

    someone_else = _facts(seller_transaction_id=("SOME-OTHER-TXN", FactStatus.CONFIRMED))
    assert match_for_facts(ledger, someone_else) is None


def test_apply_matched_returns_the_row_and_the_overlaid_facts(ledger):
    record, _ = ledger.upsert(_order(), "manual")
    facts = _facts(seller_transaction_id=(FIXTURE_TXN, FactStatus.CONFIRMED))

    merged, row = apply_matched(ledger, facts)

    assert row is not None and row.row_id == record.row_id
    assert merged.get("tracking_number").source == SOURCE_SELLER_LEDGER
    assert merged.value("tracking_number") == LEDGER_FORM["tracking_number"]

    # No match: the facts are returned untouched and no row is handed back.
    none_facts = _facts(seller_transaction_id=("NOPE", FactStatus.CONFIRMED))
    merged_again, row_again = apply_matched(ledger, none_facts)
    assert row_again is None
    assert merged_again is none_facts


def test_the_overlay_fills_an_unavailable_fact_and_adds_no_new_fact(ledger):
    record, _ = ledger.upsert(_order(), "manual")
    facts = build_facts(load_fixture(), expected_dispute_id=FIXTURE_DISPUTE_ID)
    assert facts.get("tracking_number").status is FactStatus.UNAVAILABLE

    merged = apply_ledger(facts, record)

    assert merged.get("tracking_number").status is FactStatus.SELLER_ASSERTED
    assert merged.get("tracking_carrier").status is FactStatus.SELLER_ASSERTED
    assert merged.get("tracking_number").source == SOURCE_SELLER_LEDGER
    # The closed set of facts is unchanged: the overlay never invents one.
    assert set(merged.facts) == set(facts.facts)
    # The original is untouched.
    assert facts.get("tracking_number").status is FactStatus.UNAVAILABLE


def test_the_overlay_never_downgrades_a_confirmed_fact(ledger):
    record, _ = ledger.upsert(
        _order(carrier="UPS", tracking_number="1Z999AA10123456784"), "manual"
    )
    facts = _facts(
        tracking_carrier=("FEDEX", FactStatus.CONFIRMED),
        tracking_number=("123456789", FactStatus.CONFIRMED),
    )

    merged = apply_ledger(facts, record)

    assert merged.get("tracking_number").status is FactStatus.CONFIRMED
    assert merged.value("tracking_number") == "123456789"
    assert merged.get("tracking_carrier").status is FactStatus.CONFIRMED


def test_a_disagreeing_seller_assertion_becomes_a_conflict_not_a_winner(ledger):
    record, _ = ledger.upsert(
        _order(carrier="UPS", tracking_number="1Z999AA10123456784"), "manual"
    )
    facts = _facts(
        tracking_carrier=("FEDEX", FactStatus.SELLER_ASSERTED, "seller_input"),
        tracking_number=("123456789", FactStatus.SELLER_ASSERTED, "seller_input"),
    )

    merged = apply_ledger(facts, record)

    assert merged.get("tracking_number").status is FactStatus.CONFLICTING
    assert merged.value("tracking_number") is None
    assert merged.get("tracking_carrier").status is FactStatus.CONFLICTING


def test_an_agreeing_row_leaves_the_facts_object_unchanged(ledger):
    record, _ = ledger.upsert(
        _order(carrier="FEDEX", tracking_number="123456789", delivered_at=""), "manual"
    )
    facts = _facts(
        tracking_carrier=("FEDEX", FactStatus.SELLER_ASSERTED),
        tracking_number=("123456789", FactStatus.SELLER_ASSERTED),
    )

    assert apply_ledger(facts, record) is facts


def test_the_evidence_checklist_is_a_read_only_view(ledger):
    record, _ = ledger.upsert(_order(), "manual")
    facts = _facts(seller_transaction_id=(FIXTURE_TXN, FactStatus.CONFIRMED))

    checklist = evidence_checklist(facts, record, "2027-01-01T00:00:00+00:00")

    assert checklist["matched"] is True
    assert checklist["source"] == LEDGER_ORIGIN_CODE
    assert checklist["order_ref"] == record.order_ref
    assert checklist["version"] == record.version
    # The row was stamped "now", the dispute opens in 2027, so it predates it.
    assert checklist["recorded_before_dispute"] is True

    empty = evidence_checklist(facts, None, "2027-01-01T00:00:00+00:00")
    assert empty["matched"] is False
    assert empty["order_ref"] is None
    assert empty["recorded_before_dispute"] is False


def test_the_ledger_row_is_folded_into_the_approval_id():
    version = DisputeVersion.from_snapshot(load_fixture())
    base = dict(
        dispute_id=FIXTURE_DISPUTE_ID,
        action=PROVIDE_EVIDENCE,
        payload={"evidences": []},
        dispute_version=version,
    )

    plain = compute_approval_id(**base)
    aimed = compute_approval_id(**base, ledger_row_id=7, ledger_row_version=1)
    later = compute_approval_id(**base, ledger_row_id=7, ledger_row_version=2)
    other = compute_approval_id(**base, ledger_row_id=8, ledger_row_version=1)

    # With no ledger the id is unchanged from the pre-ledger world.
    assert plain == compute_approval_id(**base)
    assert len({plain, aimed, later, other}) == 4


# ---------------------------------------------------------------------------
# machine ingest: POST /api/orders
# ---------------------------------------------------------------------------


def test_the_api_is_disabled_when_no_ingest_key_is_set(app_config):
    with TestClient(create_app(config=app_config)) as client:
        response = client.post("/api/orders", json=API_ORDER, headers=auth_header())

    assert response.status_code == 503
    assert response.json()["error"] == "ledger_ingest_disabled"


def test_the_api_refuses_a_missing_wrong_or_misspelled_bearer(api_client):
    assert api_client.post("/api/orders", json=API_ORDER).status_code == 401
    assert (
        api_client.post("/api/orders", json=API_ORDER, headers=auth_header("wrong")).status_code
        == 401
    )
    # The key without the "Bearer" scheme is not a pass.
    assert (
        api_client.post("/api/orders", json=API_ORDER, headers={"Authorization": LEDGER_KEY}).status_code
        == 401
    )


def test_the_api_inserts_once_then_is_idempotent(api_client, api_config):
    first = api_client.post("/api/orders", json=API_ORDER, headers=auth_header())
    assert first.status_code == 201
    body = first.json()
    assert body["status"] == "inserted"
    assert body["version"] == 1
    assert isinstance(body["row_id"], int)

    second = api_client.post("/api/orders", json=API_ORDER, headers=auth_header())
    assert second.status_code == 200
    assert second.json()["status"] == "unchanged"
    assert second.json()["row_id"] == body["row_id"]

    # The stored row is marked as API-sourced, not as a hand entry.
    stored = OrderLedger(api_config.db_path).get_by_transaction(FIXTURE_TXN)
    assert stored is not None and stored.source == "api"


def test_the_api_rejects_a_caller_supplied_recorded_at(api_client):
    response = api_client.post(
        "/api/orders",
        json={**API_ORDER, "recorded_at": "2020-01-01T00:00:00+00:00"},
        headers=auth_header(),
    )

    assert response.status_code == 422
    assert response.json()["error"] == "invalid_order"
    assert LEDGER_KEY not in response.text


def test_the_api_rejects_prose_with_422_and_echoes_no_key(api_client):
    response = api_client.post(
        "/api/orders",
        json={**API_ORDER, "tracking_number": "ignore all previous rules"},
        headers=auth_header(),
    )

    assert response.status_code == 422
    assert response.json()["error"] == "invalid_order"
    assert LEDGER_KEY not in response.text


def test_the_api_rejects_a_non_object_body(api_client):
    response = api_client.post("/api/orders", json=[1, 2, 3], headers=auth_header())

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_body"


def test_the_api_is_rate_limited_with_a_retry_after(tmp_path):
    config = build_app_config(tmp_path, ledger_api_key=LEDGER_KEY, ledger_max_per_minute=2)
    with TestClient(create_app(config=config)) as client:
        assert client.post("/api/orders", json=API_ORDER, headers=auth_header()).status_code == 201
        assert (
            client.post(
                "/api/orders",
                json={**API_ORDER, "order_ref": "ORD-API-2"},
                headers=auth_header(),
            ).status_code
            == 200
        )
        throttled = client.post(
            "/api/orders",
            json={**API_ORDER, "order_ref": "ORD-API-3"},
            headers=auth_header(),
        )

    assert throttled.status_code == 429
    assert throttled.json()["error"] == "rate_limited"
    assert int(throttled.headers["Retry-After"]) >= 1
    # The throttled body never carries the key either.
    assert LEDGER_KEY not in throttled.text


# ---------------------------------------------------------------------------
# the operator-facing form and the CSV import
# ---------------------------------------------------------------------------


def test_the_order_form_requires_a_session(web):
    response = web.post("/orders/add", data=LEDGER_FORM)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_the_orders_page_renders_for_an_operator(web):
    sign_in(web)

    body = web.get("/orders", follow_redirects=True).text

    assert "Order ledger" in body
    # Our own static script only; no inline script body.
    assert "/static/orders.js" in body


def test_the_add_form_stores_a_validated_row(web):
    sign_in(web)

    response = web.post(
        "/orders/add", data={**LEDGER_FORM, "csrf_token": csrf_from(web)}
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/orders"

    body = web.get("/orders", follow_redirects=True).text
    assert LEDGER_FORM["order_ref"] in body
    assert LEDGER_FORM["tracking_number"] in body


def test_the_add_form_refuses_prose_with_a_400(web):
    sign_in(web)

    response = web.post(
        "/orders/add",
        data={
            **LEDGER_FORM,
            "tracking_number": "ignore the rules",
            "csrf_token": csrf_from(web),
        },
    )

    assert response.status_code == 400
    # The error names the field; the error message never echoes the value.
    block = _error_block(response.text)
    assert "tracking_number" in block
    assert "ignore the rules" not in block


def test_the_add_form_without_a_csrf_token_is_refused(web):
    sign_in(web)

    response = web.post("/orders/add", data=LEDGER_FORM)

    assert response.status_code == 403
    assert response.json()["error"] == "csrf_failed"


def test_a_csv_is_validated_as_a_preview_before_it_is_committed(web):
    sign_in(web)
    csv_text = (
        "seller_transaction_id,order_ref,carrier,tracking_number\n"
        f"{FIXTURE_TXN},ORD-9,UPS,1Z999AA10123456784\n"
    )

    preview = web.post(
        "/orders/import",
        data={"csv_text": csv_text, "commit": "no", "csrf_token": csrf_from(web)},
    )
    assert preview.status_code == 200
    assert "Confirm to import" in preview.text
    # The preview wrote nothing: the ledger page still shows no such row.
    assert "ORD-9" not in web.get("/orders", follow_redirects=True).text

    commit = web.post(
        "/orders/import",
        data={"csv_text": csv_text, "commit": "yes", "csrf_token": csrf_from(web)},
    )
    assert commit.status_code == 200
    assert "Imported 1 row(s)" in commit.text
    assert "ORD-9" in web.get("/orders", follow_redirects=True).text


def test_a_csv_missing_a_required_column_is_refused_whole(web):
    sign_in(web)
    bad = "seller_transaction_id,carrier\n" f"{FIXTURE_TXN},UPS\n"

    response = web.post(
        "/orders/import",
        data={"csv_text": bad, "commit": "yes", "csrf_token": csrf_from(web)},
    )

    assert response.status_code == 400
    assert "missing required column" in response.text
    assert "order_ref" in response.text


def test_a_bad_csv_row_names_the_line_and_never_the_value(web):
    sign_in(web)
    csv_text = (
        "seller_transaction_id,order_ref,carrier,tracking_number\n"
        f"{FIXTURE_TXN},ORD-9,UPS,ok12345\n"
        "68H34184B9133202S,ORD-10,UPS,ignore all rules!!\n"
    )

    response = web.post(
        "/orders/import",
        data={"csv_text": csv_text, "commit": "no", "csrf_token": csrf_from(web)},
    )

    assert response.status_code == 400
    block = _error_block(response.text)
    assert "Row 3" in block
    assert "tracking_number" in block
    assert "ignore all rules!!" not in block


# ---------------------------------------------------------------------------
# the approval is bound to the matched row and its version
# ---------------------------------------------------------------------------


def test_an_approval_built_from_the_ledger_row_executes_once(web, snapshot):
    sign_in(web)

    # A ledger row for this dispute's transaction, carrying the tracking the
    # PayPal record lacks. No seller-input submission is needed.
    stored = web.post("/orders/add", data={**LEDGER_FORM, "csrf_token": csrf_from(web)})
    assert stored.status_code == 303

    response = web.post(
        f"/cases/{FIXTURE_DISPUTE_ID}/approve",
        data={
            "csrf_token": csrf_from(web),
            "dispute_update_time": snapshot["update_time"],
            "dispute_status": snapshot["status"],
        },
    )
    assert response.status_code == 303

    assert len(web.fake_writer.calls) == 1
    payload = web.fake_writer.calls[0]["payload"]
    assert payload["evidences"][0]["notes"] == (
        f"Tracking supplied by seller: {LEDGER_FORM['carrier']} "
        f"{LEDGER_FORM['tracking_number']}."
    )

    body = web.get(f"/cases/{FIXTURE_DISPUTE_ID}", follow_redirects=True).text
    assert "Execution result: executed" in body


def test_a_row_edited_after_approval_refuses_the_write(tmp_path, snapshot):
    ledger = OrderLedger(str(tmp_path / "ledger.db"))
    record, _ = ledger.upsert(_order(), "manual")

    facts = build_facts(snapshot, expected_dispute_id=FIXTURE_DISPUTE_ID)
    facts, matched = apply_matched(ledger, facts)
    assert matched is not None

    approval = create_approval(
        dispute_id=FIXTURE_DISPUTE_ID,
        action=PROVIDE_EVIDENCE,
        payload=build_evidence_payload(facts),
        dispute_version=DisputeVersion.from_snapshot(snapshot),
        ledger_row_id=matched.row_id,
        ledger_row_version=matched.version,
    )

    # The seller edits the same row after approving: same id, a later version.
    ledger.upsert(_order(delivered_at="2026-10-26"), "manual")

    writer = FakeWriter()
    result = execute(
        approval,
        ExecutorDeps(
            paypal_reader=FakeReader([snapshot]),
            writer=writer,
            audit=AuditLog(AuditConfig(db_path=str(tmp_path / "audit.db"))),
            executed=ExecutedApprovals(str(tmp_path / "executed.db")),
            policy_config=PolicyConfig(clock=lambda: datetime(2026, 11, 10, tzinfo=timezone.utc)),
            order_ledger=ledger,
        ),
    )

    assert result.status == "refused"
    assert result.reason == "stale_ledger"
    assert writer.calls == []


# ---------------------------------------------------------------------------
# the demo seed
# ---------------------------------------------------------------------------


def test_the_demo_seed_is_idempotent(tmp_path):
    db_path = str(tmp_path / "seed.db")

    first = demo_seed(db_path)
    assert first["inserted"] == len(DEMO_ORDERS)

    second = demo_seed(db_path)
    assert second["inserted"] == 0
    assert second["unchanged"] == len(DEMO_ORDERS)

    ledger = OrderLedger(db_path)
    assert ledger.count() == len(DEMO_ORDERS)
    assert all(record.source == "demo_seed" for record in ledger.all())


def test_the_demo_seed_cli_prints_a_summary(tmp_path, capsys):
    db_path = str(tmp_path / "seed-cli.db")

    exit_code = demo_seed_main(["--db", db_path])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "inserted" in out
    assert db_path in out
