"""Service container, built once from an AppConfig at startup.

Everything the UI and the pipeline need is assembled here and handed out.
Nothing below this layer reads the environment.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from ..audit import AuditLog
from ..config import AppConfig
from ..executor import ExecutedApprovals, ExecutorDeps, build_writer
from ..paypal import SandboxPayPalClient
from ..pipeline import CaseViewStore, PipelineDeps
from ..seller_input import SellerEvidenceInput, parse_seller_input
from .security import LoginThrottle, SessionStore, hash_password, verify_password

logger = logging.getLogger("orrix.web.services")


class Services:
    """Assembled services. One instance per application."""

    def __init__(
        self,
        config: AppConfig,
        paypal_reader: Any | None = None,
        writer: Any | None = None,
        reader_client: Any | None = None,
        case_store: Any | None = None,
    ):
        self.config = config
        self.secure_cookies = config.use_secure_cookies

        self.audit = AuditLog(config.audit_config())
        self.case_views = CaseViewStore(config.db_path)
        self.executed = ExecutedApprovals(config.db_path)
        self.sessions = SessionStore(
            secret=config.session_secret, ttl_seconds=config.session_ttl_seconds
        )
        self.login_throttle = LoginThrottle(
            max_failures=config.login_max_failures,
            window_seconds=config.login_lockout_seconds,
        )

        # Hashed once at startup; the plain password is not kept.
        self.admin_password_hash = (
            hash_password(config.admin_password) if config.admin_password else None
        )

        self._paypal_reader = paypal_reader
        self._writer = writer
        self._reader_client = reader_client
        self._case_store = case_store

        # Seller submissions and the last execution result per dispute. These
        # are operator working state, not authority: an approval re-derives
        # its payload from Facts at execution time.
        self._seller_inputs: dict[str, SellerEvidenceInput] = {}
        self._results: dict[str, dict[str, Any]] = {}

        self.pipeline_deps = PipelineDeps(
            audit=self.audit,
            case_views=self.case_views,
            policy_config=config.policy_config(),
            reader_config=config.reader_config(),
            reader_client=reader_client,
        )

    # -- password ---------------------------------------------------------

    def check_password(self, password: str) -> bool:
        if not self.admin_password_hash:
            return False
        return verify_password(password, self.admin_password_hash)

    # -- PayPal -----------------------------------------------------------

    @property
    def paypal_reader(self) -> Any:
        if self._paypal_reader is None:
            self._paypal_reader = SandboxPayPalClient(
                client_id=self.config.paypal_client_id,
                client_secret=self.config.paypal_client_secret,
                webhook_id=self.config.paypal_webhook_id,
            )
        return self._paypal_reader

    @property
    def writer(self) -> Any:
        if self._writer is None:
            # Built through the executor's factory: the web layer never
            # imports orrix.paypal_write.
            self._writer = build_writer(
                token_provider=self.paypal_reader.token,
                base_url=self.config.write_base_url,
                timeout=self.config.write_timeout,
            )
        return self._writer

    def executor_deps(self, seller_input: SellerEvidenceInput | None = None) -> ExecutorDeps:
        return ExecutorDeps(
            paypal_reader=self.paypal_reader,
            writer=self.writer,
            audit=self.audit,
            executed=self.executed,
            policy_config=self.config.policy_config(),
            seller_input=seller_input,
        )

    # -- stored cases -----------------------------------------------------

    def _store(self):
        if self._case_store is None:
            from .. import store as case_store

            self._case_store = case_store
        return self._case_store

    def list_dispute_ids(self) -> list[str]:
        import sqlite3

        connection = sqlite3.connect(self.config.db_path, timeout=30)
        try:
            rows = connection.execute("SELECT dispute_id FROM cases ORDER BY dispute_id").fetchall()
        except sqlite3.OperationalError:
            return []
        finally:
            connection.close()
        return [row[0] for row in rows]

    def case_snapshot(self, dispute_id: str) -> dict[str, Any] | None:
        """The stored snapshot for a dispute, as last fetched from PayPal."""
        import sqlite3

        connection = sqlite3.connect(self.config.db_path, timeout=30)
        try:
            row = connection.execute(
                "SELECT snapshot_json FROM cases WHERE dispute_id = ?", (dispute_id,)
            ).fetchone()
        except sqlite3.OperationalError:
            return None
        finally:
            connection.close()
        if not row:
            return None
        return json.loads(row[0])

    # -- operator working state -------------------------------------------

    def set_seller_input(self, dispute_id: str, parsed: SellerEvidenceInput) -> None:
        self._seller_inputs[dispute_id] = parsed

    def get_seller_input(self, dispute_id: str) -> SellerEvidenceInput | None:
        return self._seller_inputs.get(dispute_id)

    def set_result(self, dispute_id: str, result: dict[str, Any]) -> None:
        self._results[dispute_id] = result

    def get_result(self, dispute_id: str) -> dict[str, Any] | None:
        return self._results.get(dispute_id)
