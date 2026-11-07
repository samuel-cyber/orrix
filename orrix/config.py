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
    secure_cookies: bool = False

    # Optional AG Grid Enterprise licence. Injected into the page at render
    # time so the grid runs without a watermark. Never logged, never
    # committed; without it the grid still works.
    ag_grid_license_key: str | None = field(default=None, repr=False)

    # Where the evaluation harness writes its output, and where the caveats
    # that must be read alongside it live.
    results_path: str = "results/summary.json"
    results_notes_path: str = "docs/RESULTS.md"

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
        db_path=os.environ.get("ORRIX_DB_PATH", DEFAULT_DB_PATH),
        paypal_client_id=os.environ.get("PAYPAL_CLIENT_ID"),
        paypal_client_secret=os.environ.get("PAYPAL_CLIENT_SECRET"),
        paypal_webhook_id=os.environ.get("PAYPAL_WEBHOOK_ID"),
        audit_hmac_key=os.environ.get("AUDIT_HMAC_KEY"),
        admin_password=os.environ.get("ADMIN_PASSWORD"),
        session_secret=session_secret,
        session_ttl_seconds=int(_number("SESSION_TTL_SECONDS", 8 * 3600)),
        secure_cookies=_flag("SECURE_COOKIES", False),
        ag_grid_license_key=os.environ.get("AG_GRID_LICENSE_KEY"),
        results_path=os.environ.get("ORRIX_RESULTS_PATH", "results/summary.json"),
        results_notes_path=os.environ.get("ORRIX_RESULTS_NOTES_PATH", "docs/RESULTS.md"),
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
