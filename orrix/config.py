"""Application configuration, built once at startup.

This is the only module that reads the environment. Everything else takes a
config object or an explicit value from its caller, so nothing deep in the
system can reach for a credential on its own.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal

from dotenv import load_dotenv

from .audit import AuditConfig
from .policy import PolicyConfig
from .reader import ReaderConfig

# Sandbox host, as a plain string. Config deliberately does not import
# orrix.paypal_write: write capability lives only in orrix.executor.
SANDBOX_BASE_URL = "https://api-m.sandbox.paypal.com"

DEFAULT_DB_PATH = "orrix.db"
DEFAULT_PORT = 8010

ENV_PRODUCTION = "production"
ENV_DEVELOPMENT = "development"

#: Shortest admin password a production deployment will accept. The console
#: sits on a public URL and holds the approval button, so a weak password is
#: the whole trust boundary undone.
MIN_PRODUCTION_PASSWORD_LENGTH = 12


class ConfigError(RuntimeError):
    """The configuration is unsafe to serve. Refuse to start."""


def resolve_db_path() -> str:
    """The one place the database path is decided.

    ORRIX_DB is what render.yaml sets, pointing at the mounted disk.
    ORRIX_DB_PATH stays supported for existing local setups.

    Every component must resolve the path through here. orrix/store.py once
    read ORRIX_DB_PATH only, so on Render -- which sets ORRIX_DB alone --
    the poller wrote ./orrix.db while the console read /var/data/orrix.db.
    The poll reported five disputes synced and the queue stayed empty.
    """
    return os.environ.get("ORRIX_DB") or os.environ.get("ORRIX_DB_PATH", DEFAULT_DB_PATH)


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off", ""}


def _number(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class AppConfig:
    """Everything the app needs, resolved once.

    `secrets` are held here and handed to the services that need them; they
    are marked repr=False so a traceback or a log line cannot print them.
    """

    db_path: str = DEFAULT_DB_PATH
    paypal_client_id: str | None = field(default=None, repr=False)
    paypal_client_secret: str | None = field(default=None, repr=False)
    paypal_webhook_id: str | None = field(default=None, repr=False)
    audit_hmac_key: str | None = field(default=None, repr=False)

    admin_password: str | None = field(default=None, repr=False)
    session_secret: str = field(default_factory=lambda: secrets.token_hex(32), repr=False)
    session_ttl_seconds: int = 8 * 3600
    #: None means "decide from the environment": on in production, off
    #: otherwise, so local HTTP development still works.
    secure_cookies: bool | None = None
    environment: str = ENV_DEVELOPMENT
    #: Failed logins allowed per client address before a 429, and the window
    #: they are counted over.
    login_max_failures: int = 5
    login_lockout_seconds: int = 600

    # Optional AG Grid Enterprise licence. Injected into the page at render
    # time so the grid runs without a watermark. Never logged, never
    # committed; without it the grid still works.
    ag_grid_license_key: str | None = field(default=None, repr=False)

    # Where the evaluation harness writes its output, and where the caveats
    # that must be read alongside it live.
    results_path: str = "results/summary.json"
    results_notes_path: str = "docs/RESULTS.md"

    # The project's public repository, linked from the landing page footer.
    # A placeholder is shown when it is unset. Not a secret.
    site_repo_url: str = "https://github.com/example/orrix"

    reader_api_key: str | None = field(default=None, repr=False)
    reader_base_url: str = "https://api.openai.com/v1"
    reader_model: str = "gpt-4o-mini"
    reader_timeout: float = 30.0
    reader_max_retries: int = 2

    poller_enabled: bool = True
    poll_interval_seconds: float = 60.0

    refund_cap_usd: Decimal = Decimal("0")
    min_hours_before_deadline: float = 0.0

    port: int = DEFAULT_PORT

    # -- deployment posture ----------------------------------------------

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() == ENV_PRODUCTION

    @property
    def use_secure_cookies(self) -> bool:
        """Secure cookies in production; explicit setting wins either way."""
        if self.secure_cookies is not None:
            return self.secure_cookies
        return self.is_production

    def validate(self) -> None:
        """Refuse to serve a configuration that is unsafe on a public URL.

        Called before the app starts. Messages name the variable and the
        rule, never the value.
        """
        if not self.is_production:
            return

        if not self.admin_password:
            raise ConfigError(
                "ADMIN_PASSWORD is not set. A production deployment serves the "
                "approval button on a public URL and will not start without one."
            )
        if len(self.admin_password) < MIN_PRODUCTION_PASSWORD_LENGTH:
            raise ConfigError(
                f"ADMIN_PASSWORD is shorter than "
                f"{MIN_PRODUCTION_PASSWORD_LENGTH} characters. Set a longer one; "
                f"the length is the check, the value is never logged."
            )

    def startup_summary(self) -> list[str]:
        """Lines safe to log at startup: presence, never values."""
        return [
            f"environment={self.environment}",
            f"db_path={self.db_path}",
            f"secure_cookies={self.use_secure_cookies}",
            f"poller_enabled={self.poller_enabled}",
            f"poll_interval_seconds={self.poll_interval_seconds}",
            f"admin_password_set={bool(self.admin_password)}",
            f"paypal_credentials_set={bool(self.paypal_client_id and self.paypal_client_secret)}",
            f"paypal_webhook_id_set={bool(self.paypal_webhook_id)}",
            f"reader_configured={self.reader_is_configured}",
            f"reader_model={self.reader_model}",
            f"audit_hmac_key_set={bool(self.audit_hmac_key)}",
            f"ag_grid_license_set={self.ag_grid_license_is_set}",
            f"login_max_failures={self.login_max_failures}",
        ]

    # -- derived service configs -----------------------------------------

    @property
    def ag_grid_license_is_set(self) -> bool:
        return bool(self.ag_grid_license_key)

    @property
    def reader_is_configured(self) -> bool:
        return bool(self.reader_api_key)

    def audit_config(self) -> AuditConfig:
        return AuditConfig(db_path=self.db_path, hmac_key=self.audit_hmac_key)

    def policy_config(self) -> PolicyConfig:
        return PolicyConfig(
            refund_cap_usd=self.refund_cap_usd,
            min_hours_before_deadline=self.min_hours_before_deadline,
            clock=lambda: datetime.now(timezone.utc),
        )

    #: Values the writer needs. Handed to orrix.executor.build_writer, which
    #: is the only place a writer is constructed.
    write_base_url: str = SANDBOX_BASE_URL
    write_timeout: float = 60.0

    def reader_config(self) -> ReaderConfig | None:
        """None when no key is configured; the pipeline then skips the model."""
        if not self.reader_api_key:
            return None
        return ReaderConfig(
            base_url=self.reader_base_url,
            api_key=self.reader_api_key,
            model=self.reader_model,
            timeout=self.reader_timeout,
            max_retries=self.reader_max_retries,
        )


def load_config() -> AppConfig:
    """Read the environment once. Called at startup and nowhere else."""
    load_dotenv()

    session_secret = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)

    return AppConfig(
        db_path=resolve_db_path(),
        paypal_client_id=os.environ.get("PAYPAL_CLIENT_ID"),
        paypal_client_secret=os.environ.get("PAYPAL_CLIENT_SECRET"),
        paypal_webhook_id=os.environ.get("PAYPAL_WEBHOOK_ID"),
        audit_hmac_key=os.environ.get("AUDIT_HMAC_KEY"),
        admin_password=os.environ.get("ADMIN_PASSWORD"),
        session_secret=session_secret,
        session_ttl_seconds=int(_number("SESSION_TTL_SECONDS", 8 * 3600)),
        # Unset means "follow ORRIX_ENV"; an explicit value always wins.
        secure_cookies=(
            _flag("SECURE_COOKIES", False) if os.environ.get("SECURE_COOKIES") else None
        ),
        environment=os.environ.get("ORRIX_ENV", ENV_DEVELOPMENT),
        login_max_failures=int(_number("LOGIN_MAX_FAILURES", 5)),
        login_lockout_seconds=int(_number("LOGIN_LOCKOUT_SECONDS", 600)),
        ag_grid_license_key=os.environ.get("AG_GRID_LICENSE_KEY"),
        results_path=os.environ.get("ORRIX_RESULTS_PATH", "results/summary.json"),
        results_notes_path=os.environ.get("ORRIX_RESULTS_NOTES_PATH", "docs/RESULTS.md"),
        site_repo_url=os.environ.get("SITE_REPO_URL", "https://github.com/example/orrix"),
        reader_api_key=os.environ.get("READER_API_KEY"),
        reader_base_url=os.environ.get("READER_BASE_URL", "https://api.openai.com/v1"),
        reader_model=os.environ.get("READER_MODEL", "gpt-4o-mini"),
        reader_timeout=_number("READER_TIMEOUT", 30.0),
        reader_max_retries=int(_number("READER_MAX_RETRIES", 2)),
        poller_enabled=_flag("POLLER_ENABLED", True),
        poll_interval_seconds=_number("POLL_INTERVAL_SECONDS", 60.0),
        refund_cap_usd=Decimal(str(os.environ.get("REFUND_CAP_USD", "0"))),
        min_hours_before_deadline=_number("MIN_HOURS_BEFORE_DEADLINE", 0.0),
        port=int(_number("PORT", DEFAULT_PORT)),
    )
