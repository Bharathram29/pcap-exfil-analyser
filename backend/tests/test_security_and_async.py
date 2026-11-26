"""Tests for Phase 10 & 11: API security hardening, async status, cancellation, and reports."""

from __future__ import annotations

import shutil
from pathlib import Path

from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.core.config import BACKEND_DIR, PROJECT_ROOT, Settings
from app.main import create_app


def test_api_key_authentication_security_headers_and_id_validation(tmp_path: Path) -> None:
    settings = Settings(
        environment="test",
        upload_dir=tmp_path / "uploads",
        analyses_dir=tmp_path / "analyses",
        reports_dir=tmp_path / "reports",
        rules_dir=tmp_path / "rules",
        database_path=tmp_path / "data" / "sec_test.db",
        api_key=SecretStr("secret-token-123"),
    )
    app = create_app(custom_settings=settings)
    with TestClient(app) as client:
        # Health check remains accessible for container readiness probes
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.headers["X-Content-Type-Options"] == "nosniff"
        assert health.headers["X-Frame-Options"] == "DENY"

        # Unauthenticated investigation query rejected with 401
        unauth = client.get("/api/investigations")
        assert unauth.status_code == 401

        # Wrong key rejected
        wrong = client.get("/api/investigations", headers={"X-API-Key": "bad"})
        assert wrong.status_code == 401

        # Valid X-API-Key accepted
        ok = client.get("/api/investigations", headers={"X-API-Key": "secret-token-123"})
        assert ok.status_code == 200

        # Valid Bearer token accepted, invalid analysis_id format rejected with 400
        bad_id = client.get(
            "/api/analysis/bad$id!",
            headers={"Authorization": "Bearer secret-token-123"},
        )
        assert bad_id.status_code == 400


def test_async_status_cancellation_and_upgraded_reports(tmp_path: Path) -> None:
    sample_pcap = PROJECT_ROOT / "sample_data" / "test_exfil.pcap"
    rules_dir = tmp_path / "rules"
    shutil.copytree(BACKEND_DIR / "rules", rules_dir)
    settings = Settings(
        environment="test",
        upload_dir=tmp_path / "uploads",
        analyses_dir=tmp_path / "analyses",
        reports_dir=tmp_path / "reports",
        rules_dir=rules_dir,
        database_path=tmp_path / "data" / "async_test.db",
    )
    app = create_app(custom_settings=settings)
    with TestClient(app) as client:
        with sample_pcap.open("rb") as fh:
            up = client.post(
                "/api/pcap/upload",
                files={"file": ("test_exfil.pcap", fh, "application/octet-stream")},
            )
        analysis_id = up.json()["analysis_id"]

        # Run async background analysis (TestClient executes BackgroundTasks before returning)
        start = client.post(
            "/api/analysis/start",
            json={"analysis_id": analysis_id, "run_async": True},
        )
        assert start.status_code == 200
        assert start.json()["status"] == "PROCESSING"

        st = client.get(f"/api/analysis/{analysis_id}/status").json()
        assert st["status"] == "COMPLETED"
        assert st["progress_pct"] == 100

        # Upgraded HTML report contains correlated incidents & specialized findings sections
        html_rep = client.get(f"/api/analysis/{analysis_id}/report?format=html")
        assert html_rep.status_code == 200
        assert "Content-Security-Policy" in html_rep.headers
        assert "Correlated Security Incidents" in html_rep.text
        assert "Specialized Findings" in html_rep.text
        assert "Packet Refs" in html_rep.text

        # Cancel endpoint returns deterministic response
        cancel_resp = client.post(f"/api/analysis/{analysis_id}/cancel")
        assert cancel_resp.status_code == 200
        assert cancel_resp.json()["cancel_requested"] is True
