from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import achievements, auth, awdp, challenges, content, invites, instances, scoreboard, users
from app.core.config import Settings, get_settings
from app.core.database import Database
from app.core.seed import seed_database
from app.services.docker import DockerService
from app.services.reaper import run_reaper

VERSION = "Alpha0.0.9"
logger = logging.getLogger("syclover")


def configure_logging() -> None:
    """Make platform logs visible even when the host app configures no logging.

    Uvicorn installs handlers for its own loggers only; without this the module-level
    loggers fall back to a handler-less root logger and every line is dropped.
    """
    if logging.getLogger().handlers:
        return
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or get_settings()
    configure_logging()

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        database = Database(resolved_settings.database_path)
        database.initialize()
        seed_database(database, resolved_settings)
        resolved_settings.storage_path.mkdir(parents=True, exist_ok=True)
        application.state.settings = resolved_settings
        application.state.database = database
        application.state.docker = DockerService(resolved_settings.docker_mode)
        reaper_task: asyncio.Task | None = None
        if resolved_settings.instance_reaper_enabled:
            reaper_task = asyncio.create_task(
                run_reaper(database, application.state.docker, resolved_settings),
                name="instance-reaper",
            )
            logger.info(
                "Instance reaper started: TTL %s minute(s), sweep every %s second(s)",
                resolved_settings.instance_ttl_minutes,
                resolved_settings.instance_reaper_interval_seconds,
            )
        else:
            logger.info("Instance reaper is disabled by configuration")
        try:
            yield
        finally:
            if reaper_task is not None:
                reaper_task.cancel()
                try:
                    await reaper_task
                except asyncio.CancelledError:
                    pass

    application = FastAPI(
        title=resolved_settings.app_name,
        version=VERSION,
        description="CTF and AWDP training platform API",
        lifespan=lifespan,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(resolved_settings.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api_prefix = "/api/v1"
    application.include_router(auth.router, prefix=api_prefix)
    application.include_router(users.router, prefix=api_prefix)
    application.include_router(achievements.router, prefix=api_prefix)
    application.include_router(content.announcements, prefix=api_prefix)
    application.include_router(content.collections, prefix=api_prefix)
    application.include_router(invites.router, prefix=api_prefix)
    application.include_router(challenges.router, prefix=api_prefix)
    application.include_router(instances.router, prefix=api_prefix)
    application.include_router(awdp.router, prefix=api_prefix)
    application.include_router(scoreboard.router, prefix=api_prefix)

    @application.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return application


app = create_app()
