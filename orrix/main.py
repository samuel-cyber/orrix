"""FastAPI application wiring for Orrix."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import store
from .config import AppConfig, load_config
from .poller import run_poller
from .web.app import STATIC_DIR, is_public
from .web.app import router as web_router
from .web.security import SECURITY_HEADERS, SESSION_COOKIE
from .web.services import Services
from .webhooks import router as webhook_router

logger = logging.getLogger("orrix.main")


def create_app(
    config: AppConfig | None = None,
    paypal_reader=None,
    writer=None,
    reader_client=None,
) -> FastAPI:
    """Build the application from one config object.

    Fakes can be injected for tests; in production the services construct
    the real sandbox clients themselves from the same config.
    """
    config = config or load_config()
    services = Services(
        config,
        paypal_reader=paypal_reader,
        writer=writer,
        reader_client=reader_client,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        store.init_db()

        if not config.admin_password:
            logger.warning(
                "ADMIN_PASSWORD is not set; the UI will refuse every login until it is"
            )
        if not config.reader_is_configured:
            logger.info("READER_API_KEY is not set; the reader will be skipped")
        if not config.audit_hmac_key:
            logger.warning(
                "AUDIT_HMAC_KEY is not set; the audit chain is tamper-evident only "
                "against a tamperer who cannot recompute it (see docs/THREAT_MODEL.md)"
            )

        task: asyncio.Task | None = None
        if config.poller_enabled:
            task = asyncio.create_task(run_poller(config.poll_interval_seconds))
        else:
            logger.info("poller disabled by POLLER_ENABLED")

        try:
            yield
        finally:
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(
        title="Orrix",
        description="Sandbox-only PayPal dispute console.",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.services = services
    app.state.config = config

    @app.middleware("http")
    async def require_login_and_set_headers(request: Request, call_next):
        """Gate everything but /health, /webhooks/paypal, /login and /static."""
        path = request.url.path

        if not is_public(path):
            session = services.sessions.get(request.cookies.get(SESSION_COOKIE))
            if session is None:
                if path.startswith("/api/"):
                    response = JSONResponse({"error": "login_required"}, status_code=401)
                else:
                    response = RedirectResponse("/login", status_code=303)
                for header, value in SECURITY_HEADERS.items():
                    response.headers[header] = value
                return response

        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        return response

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(webhook_router)
    app.include_router(web_router)
    return app


_app: FastAPI | None = None


def __getattr__(name: str):
    """Build the production app only when something asks for `app`.

    `uvicorn orrix.main:app` triggers this. Importing create_app for a test
    does not, so no test can accidentally construct services from the real
    environment.
    """
    if name == "app":
        global _app
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
