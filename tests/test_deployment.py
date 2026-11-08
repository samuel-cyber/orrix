"""Production posture: config refusal, cookies, throttle, headers, blueprint.

Nothing here reaches a network or a model.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from orrix.config import (
    ENV_PRODUCTION,
    MIN_PRODUCTION_PASSWORD_LENGTH,
    AppConfig,
    ConfigError,
)
from orrix.main import create_app
from orrix.web.app import PUBLIC_PATHS
from orrix.web.security import SESSION_COOKIE, LoginThrottle

from .conftest import ADMIN_PASSWORD, build_app_config

REPO_ROOT = Path(__file__).parent.parent
RENDER_YAML = REPO_ROOT / "render.yaml"

STRONG_PASSWORD = "a-long-enough-production-password"

REQUIRED_SECRETS = {
    "PAYPAL_CLIENT_ID",
    "PAYPAL_CLIENT_SECRET",
    "PAYPAL_WEBHOOK_ID",
    "ADMIN_PASSWORD",
    "READER_API_KEY",
    "READER_BASE_URL",
    "READER_MODEL",
    "AUDIT_HMAC_KEY",
    "AG_GRID_LICENSE_KEY",
}


@pytest.fixture
def client(app_config):
    """A non-redirect-following client, so status codes are assertable.

    conftest's shared client follows redirects, which turns a 303 to /login
    into a 200 and hides exactly what these tests check.
    """
    with TestClient(create_app(config=app_config), follow_redirects=False) as test_client:
        yield test_client


def prod_config(tmp_path, **overrides):
    settings = {
        "environment": ENV_PRODUCTION,
        "admin_password": STRONG_PASSWORD,
        # The same file conftest points ORRIX_DB_PATH at. A deployment has
        # one database: naming a different one here used to build a config
        # the startup check now rejects, which is correct of it.
        "db_path": str(tmp_path / "test.db"),
        "poller_enabled": False,
        "reader_api_key": None,
        "session_secret": "test-session-secret",
    }
    settings.update(overrides)
    return AppConfig(**settings)


# -- ADMIN_PASSWORD is required in production --------------------------


def test_production_refuses_to_start_without_an_admin_password(tmp_path):
    with pytest.raises(ConfigError, match="ADMIN_PASSWORD is not set"):
        prod_config(tmp_path, admin_password=None).validate()


def test_production_refuses_a_short_admin_password(tmp_path):
    for weak in ("short", "a" * (MIN_PRODUCTION_PASSWORD_LENGTH - 1), ""):
        with pytest.raises(ConfigError):
            prod_config(tmp_path, admin_password=weak).validate()


def test_production_accepts_a_password_at_the_limit(tmp_path):
    prod_config(tmp_path, admin_password="a" * MIN_PRODUCTION_PASSWORD_LENGTH).validate()


def test_the_refusal_never_quotes_the_password(tmp_path):
    secret = "tiny"
    with pytest.raises(ConfigError) as caught:
        prod_config(tmp_path, admin_password=secret).validate()

    assert secret not in str(caught.value)
    assert str(MIN_PRODUCTION_PASSWORD_LENGTH) in str(caught.value)


def test_development_does_not_require_a_password(tmp_path):
    """Local work must stay frictionless; the gate is production only."""
    AppConfig(db_path=str(tmp_path / "d.db"), admin_password=None).validate()


def test_the_app_refuses_to_build_with_an_unsafe_production_config(tmp_path):
    with pytest.raises(ConfigError):
        create_app(config=prod_config(tmp_path, admin_password="weak"))


def test_the_app_builds_with_a_safe_production_config(tmp_path):
    app = create_app(config=prod_config(tmp_path))

    assert app.state.config.is_production is True


# -- secure cookies ----------------------------------------------------


def test_cookies_are_secure_in_production(tmp_path):
    app = create_app(config=prod_config(tmp_path, admin_password=ADMIN_PASSWORD + "-long"))

    with TestClient(app, follow_redirects=False) as client:
        response = client.post(
            "/login", data={"password": ADMIN_PASSWORD + "-long"}
        )

    cookie = response.headers.get("set-cookie", "")
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie.replace("Lax", "lax")


def test_cookies_are_not_secure_in_development(client):
    response = client.post("/login", data={"password": ADMIN_PASSWORD})

    assert "Secure" not in response.headers.get("set-cookie", "")


def test_an_explicit_setting_overrides_the_environment(tmp_path):
    assert prod_config(tmp_path, secure_cookies=False).use_secure_cookies is False
    assert AppConfig(secure_cookies=True).use_secure_cookies is True
    # Unset follows the environment.
    assert AppConfig(environment=ENV_PRODUCTION, admin_password="x" * 12).use_secure_cookies


# -- login throttle ----------------------------------------------------


def test_five_failures_then_a_429(client):
    for attempt in range(5):
        response = client.post("/login", data={"password": "wrong"})
        assert response.status_code == 401, attempt

    blocked = client.post("/login", data={"password": "wrong"})

    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers
    assert int(blocked.headers["Retry-After"]) > 0
    assert "Too many failed attempts" in blocked.text


def test_the_throttle_blocks_even_the_correct_password(client):
    """Once locked, the lock holds. Otherwise it is not a throttle."""
    for _ in range(5):
        client.post("/login", data={"password": "wrong"})

    response = client.post("/login", data={"password": ADMIN_PASSWORD})

    assert response.status_code == 429
    assert not client.cookies.get(SESSION_COOKIE)


def test_a_success_clears_the_tally(client):
    for _ in range(4):
        assert client.post("/login", data={"password": "wrong"}).status_code == 401

    assert client.post("/login", data={"password": ADMIN_PASSWORD}).status_code == 303

    # The counter reset, so four more failures still do not lock.
    for _ in range(4):
        assert client.post("/login", data={"password": "wrong"}).status_code == 401


def test_the_throttle_is_per_client_address(client):
    for _ in range(5):
        client.post(
            "/login", data={"password": "wrong"}, headers={"X-Forwarded-For": "10.0.0.1"}
        )

    locked = client.post(
        "/login", data={"password": "wrong"}, headers={"X-Forwarded-For": "10.0.0.1"}
    )
    other = client.post(
        "/login", data={"password": "wrong"}, headers={"X-Forwarded-For": "10.0.0.2"}
    )

    assert locked.status_code == 429
    assert other.status_code == 401, "a different address is not punished"


def test_the_window_expires():
    throttle = LoginThrottle(max_failures=5, window_seconds=600)
    for _ in range(5):
        throttle.record_failure("1.2.3.4", now=1000.0)

    assert throttle.is_locked("1.2.3.4", now=1000.0)
    assert throttle.is_locked("1.2.3.4", now=1000.0 + 599)
    assert not throttle.is_locked("1.2.3.4", now=1000.0 + 601)


def test_the_throttle_limits_come_from_config(tmp_path):
    app = create_app(
        config=prod_config(tmp_path, login_max_failures=2, login_lockout_seconds=30)
    )
    throttle = app.state.services.login_throttle

    assert throttle.max_failures == 2
    assert throttle.window_seconds == 30


def test_a_throttled_attempt_logs_no_password(client, caplog):
    with caplog.at_level(logging.DEBUG):
        for _ in range(6):
            client.post("/login", data={"password": "my-secret-guess"})

    assert "my-secret-guess" not in caplog.text
    assert "login throttled" in caplog.text


# -- security headers --------------------------------------------------


def test_every_response_carries_the_security_headers(client):
    for path in ("/login", "/health", "/cases"):
        response = client.get(path)
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_frame_ancestors_is_none(client):
    csp = client.get("/login").headers["Content-Security-Policy"]

    directives = {
        part.strip().split(" ")[0]: part.strip().split(" ")[1:]
        for part in csp.split(";")
        if part.strip()
    }
    assert directives["frame-ancestors"] == ["'none'"]


def test_headers_are_present_on_a_redirect_and_an_error(client):
    redirected = client.get("/cases")
    assert redirected.status_code == 303
    assert redirected.headers["X-Content-Type-Options"] == "nosniff"

    unauthorised = client.get("/api/cases")
    assert unauthorised.status_code == 401
    assert "Content-Security-Policy" in unauthorised.headers


# -- the public surface ------------------------------------------------


def test_only_the_root_health_login_webhook_static_and_order_ingest_are_public():
    """The unauthenticated surface, pinned.

    /static is public because the login page needs its stylesheet. It serves
    only CSS and JS files, which carry no data: tests/test_boundaries.py
    enforces that no asset is built from data and no template inlines any.
    The bare "/" is public because it is the landing page, which reads only
    the on-disk evaluation summary, never dispute data. is_public("/x") is
    False: the allowlist entry is the exact root only, so no deeper route
    is exposed by it. /api/orders is machine ingest: it carries no session,
    authenticates with a bearer token, is rate-limited, and refuses every
    request when LEDGER_API_KEY is unset.
    """
    assert set(PUBLIC_PATHS) == {
        "/",
        "/health",
        "/login",
        "/webhooks/paypal",
        "/static",
        "/api/orders",
    }


def test_static_serves_only_assets_with_no_data(client):
    """Nothing under /static may carry dispute data or a secret."""
    for name in ("app.css", "cases.js", "audit.js", "grid-common.js", "evaluation.js"):
        response = client.get(f"/static/{name}")
        assert response.status_code == 200, name
        body = response.text
        assert "PP-R-" not in body
        assert "sk-" not in body
        assert "Bearer" not in body


@pytest.mark.parametrize(
    "path",
    [
        "/cases",
        "/orders",
        "/audit",
        "/evaluation",
        "/api/cases",
        "/api/audit",
        "/api/evaluation",
    ],
)
def test_every_other_route_needs_a_session(client, path):
    response = client.get(path)

    assert response.status_code in (303, 401)
    if response.status_code == 303:
        assert response.headers["location"] == "/login"


def test_health_answers_without_a_session_and_leaks_nothing(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_the_docs_routes_are_disabled(tmp_path):
    """FastAPI's schema endpoints would describe the whole surface."""
    app = create_app(config=prod_config(tmp_path))

    with TestClient(app, follow_redirects=False) as client:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path).status_code in (303, 404)


# -- the startup log never prints a secret -----------------------------


def test_the_startup_summary_reports_presence_not_values(tmp_path):
    config = prod_config(
        tmp_path,
        admin_password="production-password-123",
        paypal_client_id="client-id-secret",
        paypal_client_secret="client-secret-secret",
        paypal_webhook_id="WH-SECRET",
        audit_hmac_key="hmac-secret",
        ag_grid_license_key="AG-SECRET",
        reader_api_key="sk-reader-secret",
    )

    summary = "\n".join(config.startup_summary())

    for secret in (
        "production-password-123",
        "client-id-secret",
        "client-secret-secret",
        "WH-SECRET",
        "hmac-secret",
        "AG-SECRET",
        "sk-reader-secret",
    ):
        assert secret not in summary
    # It does say whether each one is set.
    assert "admin_password_set=True" in summary
    assert "paypal_credentials_set=True" in summary
    assert "audit_hmac_key_set=True" in summary
    assert "reader_configured=True" in summary


def test_startup_logging_prints_no_secret(tmp_path, caplog):
    config = prod_config(
        tmp_path,
        admin_password="production-password-123",
        paypal_client_secret="client-secret-secret",
        audit_hmac_key="hmac-secret",
    )

    with caplog.at_level(logging.DEBUG):
        with TestClient(create_app(config=config), follow_redirects=False) as client:
            client.get("/health")

    for secret in ("production-password-123", "client-secret-secret", "hmac-secret"):
        assert secret not in caplog.text
    assert "config environment=production" in caplog.text


def test_the_config_repr_hides_every_secret(tmp_path):
    config = prod_config(
        tmp_path,
        admin_password="production-password-123",
        paypal_client_secret="client-secret-secret",
        audit_hmac_key="hmac-secret",
        ag_grid_license_key="AG-SECRET",
    )

    text = repr(config)

    for secret in (
        "production-password-123",
        "client-secret-secret",
        "hmac-secret",
        "AG-SECRET",
    ):
        assert secret not in text


# -- the blueprint -----------------------------------------------------


@pytest.fixture
def blueprint():
    assert RENDER_YAML.is_file(), "render.yaml is missing"
    return yaml.safe_load(RENDER_YAML.read_text(encoding="utf-8"))


@pytest.fixture
def service(blueprint):
    services = blueprint["services"]
    assert len(services) == 1, "one web service"
    return services[0]


def test_the_blueprint_declares_one_python_web_service(service):
    assert service["type"] == "web"
    assert service["runtime"] == "python"


def test_the_start_command_binds_the_platform_port(service):
    assert service["startCommand"] == (
        "uvicorn orrix.main:app --host 0.0.0.0 --port $PORT"
    )


def test_the_build_command_installs_the_project(service):
    assert "pip install -e ." in service["buildCommand"]


def test_the_health_check_path_is_health(service):
    assert service["healthCheckPath"] == "/health"


def test_a_persistent_disk_is_mounted_and_the_database_points_at_it(service):
    assert service["disk"]["mountPath"] == "/var/data"
    assert service["disk"]["sizeGB"] >= 1

    env = {entry["key"]: entry.get("value") for entry in service["envVars"]}
    assert env["ORRIX_DB"].startswith("/var/data/")


def test_every_secret_is_declared_sync_false(service):
    declared = {
        entry["key"] for entry in service["envVars"] if entry.get("sync") is False
    }

    missing = REQUIRED_SECRETS - declared
    assert not missing, f"secrets not declared sync: false: {sorted(missing)}"


def test_no_secret_carries_a_value_in_the_file(service):
    for entry in service["envVars"]:
        if entry.get("sync") is False:
            assert "value" not in entry, f"{entry['key']} has an inline value"


def test_the_non_secret_defaults_are_set_inline(service):
    env = {entry["key"]: entry.get("value") for entry in service["envVars"]}

    assert env["POLLER_ENABLED"] == "true"
    assert env["POLL_INTERVAL_SECONDS"] == "60"
    assert env["ORRIX_ENV"] == "production"


def test_the_blueprint_warns_about_paid_instances_and_sleeping():
    text = RENDER_YAML.read_text(encoding="utf-8")

    assert "PAID INSTANCE" in text
    assert "SLEEP" in text.upper()
    assert "SANDBOX ONLY" in text


def test_the_blueprint_names_no_live_paypal_host():
    text = RENDER_YAML.read_text(encoding="utf-8")

    assert "api-m.paypal.com" not in text
    assert "api-m.sandbox.paypal.com" in text


def test_the_blueprint_contains_no_credential_value():
    """A blueprint is committed, so it must hold no secret at all."""
    text = RENDER_YAML.read_text(encoding="utf-8")

    for marker in ("sk-", "Bearer ", "AG-DEV", "EK-"):
        assert marker not in text


def test_orrix_db_env_var_is_honoured(monkeypatch, tmp_path):
    """render.yaml sets ORRIX_DB; the loader must read it."""
    from orrix.config import load_config

    target = str(tmp_path / "from-disk.db")
    monkeypatch.setenv("ORRIX_DB", target)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("ORRIX_ENV", "development")

    assert load_config().db_path == target
