"""FastAPI application wiring for Orrix."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import store
from .poller import poll_interval_seconds, poller_enabled, run_poller
from .webhooks import router

logger = logging.getLogger("orrix.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    store.init_db()

    task: asyncio.Task | None = None
    if poller_enabled():
        task = asyncio.create_task(run_poller(poll_interval_seconds()))
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
    description="Sandbox-only PayPal dispute intake.",
    lifespan=lifespan,
)

app.include_router(router)
