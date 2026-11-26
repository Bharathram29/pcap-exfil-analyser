"""Shared pytest fixtures for backend unit and integration tests."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


@pytest.fixture()
def temp_settings(tmp_path: Path) -> Settings:
    """Provide isolated Settings backed by a temporary directory."""
    return Settings(
        environment="test",
        upload_dir=tmp_path / "uploads",
        analyses_dir=tmp_path / "analyses",
        reports_dir=tmp_path / "reports",
        rules_dir=tmp_path / "rules",
        database_path=tmp_path / "data" / "test_forensics.db",
    )


@pytest.fixture()
def client(temp_settings: Settings) -> TestClient:
    """Provide a FastAPI TestClient using isolated test settings."""
    app = create_app(custom_settings=temp_settings)
    with TestClient(app) as test_client:
        yield test_client
