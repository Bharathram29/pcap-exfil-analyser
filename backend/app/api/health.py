"""Health check endpoint for readiness and liveness probes."""

from datetime import UTC, datetime

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

from app.core.config import Settings
from app.core.database import DatabaseManager
from app.schemas.health import DirectoryStatus, HealthResponse

router = APIRouter(tags=["health"])


@router.get("/api/health", response_model=HealthResponse)
def health_check(request: Request) -> JSONResponse:
    """Return service, storage directory, and SQLite health status."""
    settings: Settings = request.app.state.settings
    db: DatabaseManager = request.app.state.db

    db_ok = db.check_health()
    dirs = DirectoryStatus(
        upload_dir_exists=settings.upload_dir.is_dir(),
        reports_dir_exists=settings.reports_dir.is_dir(),
        rules_dir_exists=settings.rules_dir.is_dir(),
    )
    overall_ok = (
        db_ok
        and dirs.upload_dir_exists
        and dirs.reports_dir_exists
        and dirs.rules_dir_exists
    )

    payload = HealthResponse(
        status="healthy" if overall_ok else "degraded",
        app_name=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
        database_ok=db_ok,
        timestamp_utc=datetime.now(UTC).isoformat(),
        directories=dirs,
    )
    http_status = status.HTTP_200_OK if overall_ok else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(status_code=http_status, content=payload.model_dump())
