"""Tests for Phase 7 & 8: MITRE indicators, threat intel guardrails, audit & integrity."""

from __future__ import annotations

import shutil
from pathlib import Path

from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.core.config import BACKEND_DIR, PROJECT_ROOT, Settings
from app.main import create_app
from app.models.detection import DetectionFinding
from app.services.mitre_mapper import MitreMapper
from app.services.threat_intel import (
    ThreatIntelIndicatorResult,
    ThreatIntelProvider,
    ThreatIntelService,
)


class _StubProvider(ThreatIntelProvider):
    provider_name = "stub_intel"

    def __init__(self) -> None:
        self.calls = 0

    def lookup_ip(self, ip: str) -> ThreatIntelIndicatorResult | None:
        self.calls += 1
        return ThreatIntelIndicatorResult(
            indicator=ip,
            indicator_type="ip",
            provider=self.provider_name,
            reputation="suspicious",
            confidence=0.75,
            summary="Stub reputation hit",
        )

    def lookup_domain(self, domain: str) -> ThreatIntelIndicatorResult | None:
        self.calls += 1
        return ThreatIntelIndicatorResult(
            indicator=domain,
            indicator_type="domain",
            provider=self.provider_name,
            reputation="clean",
            confidence=0.90,
            summary="Stub clean domain",
        )


def test_mitre_does_not_map_generic_http_without_c2_indicators() -> None:
    mapper = MitreMapper()
    benign_like_http = DetectionFinding(
        detection_id="det-http-generic",
        detection_name="Standard Port HTTP POST",
        detector_type="http_upload",
        severity="MEDIUM",
        confidence=0.70,
        timestamp="2026-01-01T00:00:00+00:00",
        timestamp_epoch=1700000000.0,
        source_ip="10.0.0.5",
        destination_ip="93.184.216.34",
        source_port=51000,
        destination_port=80,
        protocol="HTTP",
        evidence={"sample_attributes": {"raw_ip_host": False}, "requests_per_minute": 2.0},
        explanation="HTTP request on standard port 80.",
        recommended_investigation_steps=[],
        candidate_mitre_ids=["T1071.001"],
        packet_indices=[1, 2],
    )
    assert mapper.map_finding(benign_like_http) == []


def test_threat_intel_skips_private_ips_caches_and_separates_external_intel(
    temp_settings: Settings,
) -> None:
    stub = _StubProvider()
    svc = ThreatIntelService(
        Settings(
            **{
                **temp_settings.model_dump(),
                "threat_intel_enabled": True,
                "virustotal_api_key": SecretStr("super-secret-vt-key"),
            }
        ),
        providers=[stub],
    )
    res = svc.enrich_indicators(["10.0.0.5", "192.168.1.1", "203.0.113.75"], ["exfil.example.net"])
    assert "10.0.0.5" in res["skipped_private_ips"]
    assert "192.168.1.1" in res["skipped_private_ips"]
    assert res["source_label"] == "EXTERNAL_THREAT_INTEL"
    priv = [r for r in res["results"] if r["indicator"] == "10.0.0.5"]
    assert priv[0]["reputation"] == "private_reserved"
    assert stub.calls == 2  # only 203.0.113.75 and exfil.example.net

    # Second call hits cache without extra provider calls
    res2 = svc.enrich_indicators(["203.0.113.75"], ["exfil.example.net"])
    assert stub.calls == 2
    assert all(r["cached"] is True for r in res2["results"])


def test_forensic_integrity_audit_trail_and_report_regeneration(tmp_path: Path) -> None:
    sample_pcap = PROJECT_ROOT / "sample_data" / "test_exfil.pcap"
    rules_dir = tmp_path / "rules"
    shutil.copytree(BACKEND_DIR / "rules", rules_dir)
    settings = Settings(
        environment="test",
        upload_dir=tmp_path / "uploads",
        analyses_dir=tmp_path / "analyses",
        reports_dir=tmp_path / "reports",
        rules_dir=rules_dir,
        database_path=tmp_path / "data" / "audit_test.db",
    )
    app = create_app(custom_settings=settings)
    with TestClient(app) as client:
        with sample_pcap.open("rb") as fh:
            up = client.post(
                "/api/pcap/upload",
                files={"file": ("test_exfil.pcap", fh, "application/octet-stream")},
            )
        analysis_id = up.json()["analysis_id"]
        client.post("/api/analysis/start", json={"analysis_id": analysis_id, "run_async": False})

        # Verify integrity endpoint
        integ = client.get(f"/api/analysis/{analysis_id}/integrity").json()
        assert integ["capture_integrity_verified"] is True
        assert integ["html_report_verified"] is True
        assert integ["pdf_report_verified"] is True

        # Delete HTML report from disk and confirm auto-regeneration works
        html_path = settings.reports_dir / f"report_{analysis_id}.html"
        html_path.unlink()
        rep_resp = client.get(f"/api/analysis/{analysis_id}/report?format=html")
        assert rep_resp.status_code == 200
        assert html_path.is_file()

        # Verify audit log captures ingestion, start, completion, regen, download
        audit_resp = client.get(f"/api/analysis/{analysis_id}/audit").json()
        actions = {e["action"] for e in audit_resp["audit_logs"]}
        assert {
            "PCAP_INGESTED",
            "ANALYSIS_STARTED",
            "ANALYSIS_COMPLETED",
            "REPORT_REGENERATED",
            "REPORT_DOWNLOADED",
        }.issubset(actions)
        assert len(audit_resp["analysis_history"]) == 1
        assert audit_resp["analysis_history"][0]["status"] == "COMPLETED"
