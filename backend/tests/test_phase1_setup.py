"""Phase 1 tests: configuration, logging, SQLite schema, and health API."""

import io
import json
import logging

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.database import DatabaseManager
from app.core.logging import AnalysisContextFilter, JsonFormatter, analysis_id_ctx


def test_settings_ensure_directories(temp_settings: Settings) -> None:
    temp_settings.ensure_directories()
    assert temp_settings.upload_dir.is_dir()
    assert temp_settings.reports_dir.is_dir()
    assert temp_settings.rules_dir.is_dir()
    assert temp_settings.database_path.parent.is_dir()


def test_database_schema_and_health(temp_settings: Settings) -> None:
    db = DatabaseManager(temp_settings.database_path)
    db.init_schema()
    assert db.check_health() is True

    with db.connection() as conn:
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table';"
            ).fetchall()
        }
    assert {"investigations", "alerts"}.issubset(tables)


def test_structured_json_logging_includes_analysis_id() -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(AnalysisContextFilter())
    handler.setFormatter(JsonFormatter())

    logger = logging.getLogger("test.phase1.logger")
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False

    token = analysis_id_ctx.set("inv-1234")
    try:
        logger.info("Pipeline test message")
    finally:
        analysis_id_ctx.reset(token)

    parsed = json.loads(stream.getvalue().strip())
    assert parsed["analysis_id"] == "inv-1234"
    assert parsed["level"] == "INFO"
    assert parsed["message"] == "Pipeline test message"


def test_health_endpoint_returns_healthy(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database_ok"] is True
    assert data["directories"]["upload_dir_exists"] is True
    assert data["directories"]["reports_dir_exists"] is True
    assert data["directories"]["rules_dir_exists"] is True
