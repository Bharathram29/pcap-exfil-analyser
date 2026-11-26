"""FastAPI application entrypoint, security headers, and lifecycle management."""

from __future__ import annotations

import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app.api.analysis import router as analysis_router
from app.api.health import router as health_router
from app.api.pcap import router as pcap_router
from app.core.config import Settings, get_settings
from app.core.database import DatabaseManager
from app.core.logging import configure_logging, get_logger


def create_app(custom_settings: Settings | None = None) -> FastAPI:
    """Construct and configure the FastAPI application instance."""
    settings = custom_settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(level=settings.log_level, json_logs=settings.json_logs)
        logger = get_logger("app.lifecycle")
        settings.ensure_directories()

        db = DatabaseManager(settings.database_path)
        db.init_schema()

        app.state.settings = settings
        app.state.db = db
        app.state.analysis_jobs = {}
        app.state.jobs_lock = threading.Lock()
        logger.info("Initialized %s v%s", settings.app_name, settings.app_version)
        yield
        logger.info("Shutting down %s", settings.app_name)

    app = FastAPI(
        title=settings.app_name,
        description=settings.app_tagline,
        version=settings.app_version,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        if request.url.path.startswith("/api/analysis/") and request.url.path.endswith("/report"):
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:;",
            )
        return response

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-API-Key"],
    )

    app.include_router(health_router)
    app.include_router(pcap_router)
    app.include_router(analysis_router)
    return app


app = create_app()
