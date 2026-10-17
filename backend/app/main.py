"""PhishLens API entry point."""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.cache import get_cache
from app.core.config import get_settings
from app.core.http import make_client
from app.storage.db import ReportStore

log = logging.getLogger("phishlens")


async def _retention_loop(store: ReportStore, days: int) -> None:
    while True:
        try:
            removed = store.purge_older_than(days)
            if removed:
                log.info("retention: purged %d report(s) older than %d days", removed, days)
        except Exception:  # noqa: BLE001
            log.exception("retention purge failed")
        await asyncio.sleep(3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.client = make_client(settings.http_timeout)
    app.state.cache = get_cache(settings.redis_url)
    app.state.store = ReportStore(settings.database_url)
    task = asyncio.create_task(_retention_loop(app.state.store, settings.retention_days))
    yield
    task.cancel()
    await app.state.client.aclose()


app = FastAPI(
    title="PhishLens",
    version="0.4.0",
    description="Self-hosted email triage: one input, every source, one explainable verdict.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origin_list,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)
app.include_router(router)
