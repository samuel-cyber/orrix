"""FastAPI application wiring for Orrix."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import store
from .webhooks import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    store.init_db()
    yield


app = FastAPI(
    title="Orrix",
    description="Sandbox-only PayPal dispute intake.",
    lifespan=lifespan,
)

app.include_router(router)
