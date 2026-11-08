"""Service container, built once from an AppConfig at startup.

Everything the UI and the pipeline need is assembled here and handed out.
Nothing below this layer reads the environment.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable

from ..audit import AuditLog
from ..config import AppConfig
from ..executor import ExecutedApprovals, ExecutorDeps, build_writer
from ..paypal import SandboxPayPalClient
from ..pipeline import CaseViewStore, PipelineDeps
from ..seller_input import SellerEvidenceInput, parse_seller_input
from .lab import LabRateLimiter, LabRunStore, utc_day_start
from .security import LoginThrottle, SessionStore, hash_password, verify_password

logger = logging.getLogger("orrix.web.services")

#: Minimum seconds between two actual Reader runs for the same case, so a
#: "Re-run reader" button cannot be used to spend the model budget by
#: repeated clicks.
RERUN_COOLDOWN_SECONDS = 30


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
        # Last "Re-run reader" attempt per dispute (monotonic-ish, via
        # time.time so a test can freeze/advance it) and the operator-facing
        # notice from that attempt.
        self._rerun_attempts: dict[str, float] = {}
        self._rerun_notices: dict[str, dict[str, Any]] = {}

        # The Attack Lab keeps its runs in its own table, never the
        # hash-chained audit log, and enforces a per-session and a
        # deployment-wide ceiling so a shared model key cannot be run up.
        self.lab_store = LabRunStore(config.db_path)
        try:
            self.lab_store.init()
        except Exception as error:  # noqa: BLE001 - a missing table is "no runs yet"
            logger.warning("lab store unavailable: %s", type(error).__name__)
        self.lab_limiter = LabRateLimiter(per_minute=config.lab_per_minute)
        self._lab_presets: tuple[dict[str, str], ...] | None = None

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

    def poll_status(self) -> dict[str, Any]:
        """When the poller last synced a dispute, as seconds ago.

        Reads the newest stored POLL event timestamp; it never makes a
        network call. Absence (no poll yet) is reported as None, not zero,
        so the indicator can say "not yet" rather than "0s ago".
        """
        from ..poller import POLL_EVENT_TYPE, poller_enabled

        try:
            latest = self._store().latest_event_at(POLL_EVENT_TYPE)
        except Exception:  # noqa: BLE001 - a missing table is "not polled"
            latest = None

        if latest is None:
            return {
                "enabled": poller_enabled(),
                "seconds_ago": None,
                "last_at": None,
                "label": "not yet",
            }

        try:
            stamp = datetime.fromisoformat(latest.replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            seconds = max(int((datetime.now(timezone.utc) - stamp).total_seconds()), 0)
        except ValueError:
            return {
                "enabled": poller_enabled(),
                "seconds_ago": None,
                "last_at": latest,
                "label": "not yet",
            }

        return {
            "enabled": poller_enabled(),
            "seconds_ago": seconds,
            "last_at": latest,
            "label": f"polled {seconds}s ago",
        }

    def list_dispute_ids(self) -> list[str]:
        """Dispute ids with a stored snapshot.

        A failure here used to return [] in silence, which is how a
        split-brain database looked like an empty queue. It now says what
        went wrong and where it was looking.
        """
        import sqlite3

        connection = sqlite3.connect(self.config.db_path, timeout=30)
        try:
            rows = connection.execute("SELECT dispute_id FROM cases ORDER BY dispute_id").fetchall()
        except sqlite3.OperationalError as error:
            logger.warning(
                "could not read the cases table: %s: %s db_path=%s",
                type(error).__name__,
                error,
                self.config.db_path,
            )
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
        except sqlite3.OperationalError as error:
            logger.warning(
                "could not read dispute_id=%s: %s: %s db_path=%s",
                dispute_id,
                type(error).__name__,
                error,
                self.config.db_path,
            )
            return None
        finally:
            connection.close()
        if not row:
            return None
        return json.loads(row[0])

    def sync_deps(self):
        """Deps for indexing a dispute. Never carries a reader_config.

        Listing the queue must cost nothing, so the sync path is given no
        model to call rather than merely being asked not to call one.
        """
        from ..pipeline import PipelineDeps

        return PipelineDeps(
            audit=self.audit,
            case_views=self.case_views,
            policy_config=self.config.policy_config(),
            reader_config=None,
        )

    def case_view(self, dispute_id: str):
        """The persisted view for the queue, with no Reader call.

        A dispute stored by an older build has no view row, so one is built
        here from the stored snapshot. Still Reader-free: the model runs only
        when the case itself is opened.
        """
        from ..pipeline import CaseView, sync_case

        stored = self.case_views.get(dispute_id)
        if stored is not None:
            view = self.case_views.hydrate(stored)
            if view is not None:
                return view
            logger.warning(
                "stored case view for dispute_id=%s could not be read; rebuilding",
                dispute_id,
            )

        snapshot = self.case_snapshot(dispute_id)
        if snapshot is None:
            logger.warning(
                "no stored snapshot for dispute_id=%s; it cannot be listed", dispute_id
            )
            return None

        return sync_case(
            snapshot, self.sync_deps(), seller_input=self.get_seller_input(dispute_id)
        )

    def fetch_and_store(self, dispute_id: str) -> dict[str, Any] | None:
        """Fetch one dispute from PayPal, store it, and index it.

        Read-only against PayPal, and no Reader. Used when the console is
        asked for a case it has no snapshot for, so a dispute the poller has
        not reached yet still opens instead of reporting "No such case".
        Returns None when PayPal does not have it.
        """
        from ..pipeline import sync_case

        try:
            snapshot = self.paypal_reader.get_dispute(dispute_id)
        except Exception as error:
            logger.warning(
                "on-demand fetch failed dispute_id=%s step=get_dispute exception=%s "
                "http_status=%s",
                dispute_id,
                type(error).__name__,
                getattr(error, "status_code", None),
            )
            return None

        if not isinstance(snapshot, dict) or snapshot.get("dispute_id") != dispute_id:
            logger.warning(
                "on-demand fetch returned a different dispute dispute_id=%s step=verify",
                dispute_id,
            )
            return None

        self._store().save_case_snapshot(dispute_id, snapshot)
        try:
            sync_case(
                snapshot, self.sync_deps(), seller_input=self.get_seller_input(dispute_id)
            )
        except Exception as error:
            logger.warning(
                "on-demand index failed dispute_id=%s step=sync_case exception=%s "
                "message=%s",
                dispute_id,
                type(error).__name__,
                error,
            )
        logger.info("fetched dispute_id=%s on demand", dispute_id)
        return snapshot

    def reindex(self, dispute_id: str):
        """Rebuild the stored view after operator input, with no model call.

        Needed because the queue is served from the stored view: without
        this, saving seller tracking would leave the list showing the state
        from before it was entered.

        If the Reader has already run on this dispute version its result is
        reused, so re-indexing never spends a credit either way.
        """
        from ..pipeline import process_case, sync_case

        snapshot = self.case_snapshot(dispute_id)
        if snapshot is None:
            logger.warning("cannot reindex dispute_id=%s: no stored snapshot", dispute_id)
            return None

        seller_input = self.get_seller_input(dispute_id)
        stored = self.case_views.get(dispute_id)
        reader_already_ran = bool(stored) and not stored.get("reader_pending")

        if reader_already_ran:
            # reuse_reader keeps the cached result for this update_time.
            return process_case(
                snapshot, self.pipeline_deps, seller_input=seller_input
            )
        return sync_case(snapshot, self.sync_deps(), seller_input=seller_input)

    # -- operator working state -------------------------------------------

    def set_seller_input(self, dispute_id: str, parsed: SellerEvidenceInput) -> None:
        self._seller_inputs[dispute_id] = parsed

    def get_seller_input(self, dispute_id: str) -> SellerEvidenceInput | None:
        return self._seller_inputs.get(dispute_id)

    def set_result(self, dispute_id: str, result: dict[str, Any]) -> None:
        self._results[dispute_id] = result

    def get_result(self, dispute_id: str) -> dict[str, Any] | None:
        return self._results.get(dispute_id)

    # -- reader re-run rate limiting ---------------------------------------

    def rerun_ready(self, dispute_id: str) -> tuple[bool, int]:
        """Whether a Reader re-run may proceed now, and seconds to wait if not."""
        last = self._rerun_attempts.get(dispute_id)
        if last is None:
            return True, 0
        elapsed = time.time() - last
        if elapsed >= RERUN_COOLDOWN_SECONDS:
            return True, 0
        return False, max(int(RERUN_COOLDOWN_SECONDS - elapsed), 1)

    def record_rerun(self, dispute_id: str) -> None:
        self._rerun_attempts[dispute_id] = time.time()

    def set_rerun_notice(self, dispute_id: str, notice: dict[str, Any]) -> None:
        self._rerun_notices[dispute_id] = notice

    def get_rerun_notice(self, dispute_id: str) -> dict[str, Any] | None:
        return self._rerun_notices.get(dispute_id)

    # -- attack lab --------------------------------------------------------

    def lab_presets(self) -> tuple[dict[str, str], ...]:
        """Author-written corpus messages, loaded once and cached."""
        if self._lab_presets is None:
            from .lab import load_presets

            self._lab_presets = load_presets()
        return self._lab_presets

    def find_preset(self, preset_id: str | None) -> dict[str, str] | None:
        if not preset_id:
            return None
        for preset in self.lab_presets():
            if preset["id"] == preset_id:
                return preset
        return None

    def lab_runs_today(self) -> int:
        """Runs started since 00:00 UTC, against the deployment-wide cap."""
        from .lab import utc_day_start

        try:
            return self.lab_store.count_since(utc_day_start())
        except Exception:  # noqa: BLE001 - a count we cannot read is zero pressure
            return 0

    def lab_daily_remaining(self) -> int:
        return max(self.config.lab_daily_cap - self.lab_runs_today(), 0)

    def run_lab(
        self,
        message: str,
        *,
        source: str = "custom",
        preset_id: str | None = None,
        session_key: str | None = None,
        session: Any = None,
    ) -> dict[str, Any]:
        """Run one comparison and record it in the lab's own table.

        The caller has already checked the per-session and daily ceilings;
        this method runs the two lanes and stores metadata only. The buyer
        text is never persisted.
        """
        from .lab import run_comparison

        reader_config = self.config.reader_config()
        comparison = run_comparison(
            message,
            reader_config=reader_config,
            client=session if session is not None else self._reader_client,
            policy_config=self.config.policy_config(),
        )
        result = comparison.as_result()

        created_at = datetime.now(timezone.utc).isoformat()
        try:
            self.lab_store.append(
                result=result,
                message=message,
                source=source,
                preset_id=preset_id,
                created_at=created_at,
            )
        except Exception as error:  # noqa: BLE001 - a store failure must not lose the result
            logger.warning("lab run not recorded: %s", type(error).__name__)

        return result
