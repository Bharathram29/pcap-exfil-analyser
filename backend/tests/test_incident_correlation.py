"""Tests for Phase 2: intelligent alert correlation and incident management."""

from __future__ import annotations

import shutil
from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import BACKEND_DIR, PROJECT_ROOT, Settings
from app.core.database import DatabaseManager
from app.main import create_app
from app.models.detection import DetectionFinding
from app.models.incident import CorrelationConfig
from app.services.alert_manager import AlertManager


def _finding(
    det_id: str,
    name: str,
    detector_type: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int | None,
    protocol: str,
    ts: float,
    severity: str = "HIGH",
    confidence: float = 0.80,
    flow_id: str | None = None,
    rule_id: str | None = None,
) -> DetectionFinding:
    return DetectionFinding(
        detection_id=det_id,
        detection_name=name,
        detector_type=detector_type,
        severity=severity,
        confidence=confidence,
        timestamp="2026-01-01T00:00:00+00:00",
        timestamp_epoch=ts,
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=50000,
        destination_port=dst_port,
        protocol=protocol,
        evidence={"outbound_bytes": 250_000, "packet_indices": [1, 2, 3]},
        explanation=f"{name} observed.",
        recommended_investigation_steps=[f"Inspect {dst_ip}"],
        flow_id=flow_id,
        rule_id=rule_id,
        packet_indices=[1, 2, 3],
    )


def test_correlator_groups_related_alerts_and_separates_unrelated() -> None:
    mgr = AlertManager()
    # Two different behavioral families on same src->dst within 30s -> 1 correlated incident
    f1 = _finding(
        "d1", "Suspicious HTTP Upload", "http_upload",
        "10.0.0.5", "203.0.113.10", 8081, "HTTP", 1000.0, flow_id="flow-a",
    )
    f2 = _finding(
        "d2", "Anomalous Outbound Data Transfer Volume", "outbound_exfiltration",
        "10.0.0.5", "203.0.113.10", 8081, "TCP", 1020.0, flow_id="flow-a",
    )
    # Same src->dst but 950s later (outside 300s window) -> separate incident
    f3 = _finding(
        "d3", "Periodic Outbound Beaconing Pattern", "network_beaconing",
        "10.0.0.5", "203.0.113.10", 8443, "TLS", 1950.0,
    )
    # Different destination host -> separate incident
    f4 = _finding(
        "d4", "Potential DNS Tunnelling Activity", "dns_tunnelling",
        "10.0.0.5", "8.8.8.8", 53, "DNS", 1010.0,
    )

    res = mgr.process_findings(
        [f1, f2, f3, f4],
        correlation_config=CorrelationConfig(time_window_seconds=300.0),
    )

    assert len(res.alerts) == 4
    assert len(res.incidents) == 3

    multi = next(inc for inc in res.incidents if inc.alert_count == 2)
    assert set(multi.detection_categories) == {"http_upload", "outbound_exfiltration"}
    assert multi.flow_ids == ["flow-a"]
    assert multi.packet_indices == [1, 2, 3]
    assert multi.first_seen_epoch == 1000.0
    assert multi.last_seen_epoch == 1020.0
    for aid in multi.alert_ids:
        alert = next(a for a in res.alerts if a.alert_id == aid)
        assert alert.incident_id == multi.incident_id


def test_correlator_prevents_duplicates_on_reprocessing(temp_settings: Settings) -> None:
    temp_settings.ensure_directories()
    db = DatabaseManager(temp_settings.database_path)
    db.init_schema()
    with db.connection() as conn:
        conn.execute(
            """
            INSERT INTO investigations (
                analysis_id, filename, stored_path, file_size_bytes,
                sha256, status, created_at, updated_at
            ) VALUES ('inv-dup', 'x.pcap', 'x.pcap', 100, 'abc', 'COMPLETED', 't', 't')
            """
        )

    mgr = AlertManager()
    findings = [
        _finding(
            "d1", "Suspicious HTTP Upload", "http_upload",
            "10.0.0.5", "203.0.113.10", 8081, "HTTP", 1000.0,
        ),
        _finding(
            "d2", "Anomalous Outbound Data Transfer Volume", "outbound_exfiltration",
            "10.0.0.5", "203.0.113.10", 8081, "TCP", 1015.0,
        ),
    ]
    res1 = mgr.process_findings(findings)
    res2 = mgr.process_findings(findings)
    assert res1.incidents[0].incident_id == res2.incidents[0].incident_id

    mgr.save_incidents(db, "inv-dup", res1.incidents)
    mgr.save_incidents(db, "inv-dup", res2.incidents)

    with db.connection() as conn:
        rows = conn.execute(
            "SELECT COUNT(*) AS c FROM incidents WHERE analysis_id = 'inv-dup'"
        ).fetchone()
        assert rows["c"] == len(res1.incidents)

    assert (
        mgr.update_incident_status(db, "inv-dup", res1.incidents[0].incident_id, "Investigating")
        is True
    )


def test_incidents_api_endpoints_e2e(tmp_path: Path) -> None:
    sample_pcap = PROJECT_ROOT / "sample_data" / "test_exfil.pcap"
    rules_dir = tmp_path / "rules"
    shutil.copytree(BACKEND_DIR / "rules", rules_dir)
    settings = Settings(
        environment="test",
        upload_dir=tmp_path / "uploads",
        analyses_dir=tmp_path / "analyses",
        reports_dir=tmp_path / "reports",
        rules_dir=rules_dir,
        database_path=tmp_path / "data" / "inc_api.db",
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

        inc_resp = client.get(f"/api/analysis/{analysis_id}/incidents")
        assert inc_resp.status_code == 200
        inc_data = inc_resp.json()
        assert inc_data["total"] >= 4
        exfil_inc = next(
            i for i in inc_data["incidents"] if "203.0.113.75" in i["destination_hosts"]
        )
        assert exfil_inc["alert_count"] >= 2

        detail_resp = client.get(
            f"/api/analysis/{analysis_id}/incidents/{exfil_inc['incident_id']}"
        )
        assert detail_resp.status_code == 200
        assert len(detail_resp.json()["alerts"]) == exfil_inc["alert_count"]

        patch_resp = client.patch(
            f"/api/analysis/{analysis_id}/incidents/{exfil_inc['incident_id']}",
            json={"status": "Confirmed Suspicious"},
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["status"] == "Confirmed Suspicious"
