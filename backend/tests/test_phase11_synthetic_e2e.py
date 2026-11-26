"""Phase 11 tests: reproducible synthetic PCAP & end-to-end forensic verification."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import BACKEND_DIR, PROJECT_ROOT, Settings
from app.main import create_app


def test_synthetic_pcap_generator_is_reproducible(tmp_path: Path) -> None:
    scripts_dir = PROJECT_ROOT / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    from generate_test_pcap import generate_synthetic_pcap

    out1 = tmp_path / "run1.pcap"
    out2 = tmp_path / "run2.pcap"
    sha1 = generate_synthetic_pcap(out1, seed=20250101)
    sha2 = generate_synthetic_pcap(out2, seed=20250101)

    assert sha1 == sha2
    sample_pcap = PROJECT_ROOT / "sample_data" / "test_exfil.pcap"
    assert sample_pcap.is_file()
    import hashlib

    sample_sha = hashlib.sha256(sample_pcap.read_bytes()).hexdigest()
    assert sha1 == sample_sha


def test_end_to_end_synthetic_exfil_pcap_pipeline(tmp_path: Path) -> None:
    sample_pcap = PROJECT_ROOT / "sample_data" / "test_exfil.pcap"
    assert sample_pcap.is_file()

    rules_dir = tmp_path / "rules"
    shutil.copytree(BACKEND_DIR / "rules", rules_dir)

    settings = Settings(
        environment="test",
        upload_dir=tmp_path / "uploads",
        analyses_dir=tmp_path / "analyses",
        reports_dir=tmp_path / "reports",
        rules_dir=rules_dir,
        database_path=tmp_path / "data" / "e2e_forensics.db",
    )
    app = create_app(custom_settings=settings)

    with TestClient(app) as client:
        with sample_pcap.open("rb") as fh:
            up_resp = client.post(
                "/api/pcap/upload",
                files={"file": ("test_exfil.pcap", fh, "application/vnd.tcpdump.pcap")},
            )
        assert up_resp.status_code == 201
        analysis_id = up_resp.json()["analysis_id"]

        start_resp = client.post(
            "/api/analysis/start",
            json={"analysis_id": analysis_id, "run_async": False},
        )
        assert start_resp.status_code == 200
        assert start_resp.json()["status"] == "COMPLETED"

        summary = client.get(f"/api/analysis/{analysis_id}/summary").json()
        assert summary["summary"]["total_packets"] > 450
        assert summary["summary"]["dns_queries"] == 13
        assert summary["summary"]["http_requests"] == 2
        assert summary["summary"]["tls_handshakes"] >= 7
        assert summary["summary"]["suspicious_events"] >= 5

        alerts_payload = client.get(f"/api/analysis/{analysis_id}/alerts").json()
        active_alerts = [a for a in alerts_payload["alerts"] if not a["suppressed"]]
        alert_titles = {a["title"] for a in active_alerts}
        alert_dsts = {a["destination_ip"] for a in active_alerts}

        # All four simulated threat behaviors must be detected
        assert "Potential DNS Tunnelling Activity" in alert_titles
        assert any("HTTP" in t for t in alert_titles)
        assert "Anomalous Outbound Data Transfer Volume" in alert_titles
        assert "Periodic Outbound Beaconing Pattern" in alert_titles
        assert any("4444" in t for t in alert_titles)

        assert {"203.0.113.75", "198.51.100.88", "198.51.100.99"}.issubset(alert_dsts)

        # Normal benign destinations must NOT generate false positive alerts
        assert "93.184.216.34" not in alert_dsts
        assert "93.184.216.35" not in alert_dsts

        # Verify MITRE ATT&CK mappings
        mitre_payload = client.get(f"/api/analysis/{analysis_id}/mitre").json()
        mitre_ids = {m["technique_id"] for m in mitre_payload["mitre_mappings"]}
        assert {"T1071.004", "T1048.003", "T1567", "T1041"}.issubset(mitre_ids)

        # Verify Network Graph & Timeline
        assert len(summary["network_graph"]["nodes"]) >= 6
        assert any(n["is_suspicious"] for n in summary["network_graph"]["nodes"])
        timeline = client.get(f"/api/analysis/{analysis_id}/timeline").json()
        assert timeline["total"] >= 5

        # Verify HTML & PDF reports
        html_rep = client.get(f"/api/analysis/{analysis_id}/report?format=html")
        assert html_rep.status_code == 200
        assert "test_exfil.pcap" in html_rep.text
        assert "T1071.004" in html_rep.text

        pdf_rep = client.get(f"/api/analysis/{analysis_id}/report?format=pdf")
        assert pdf_rep.status_code == 200
        assert pdf_rep.content.startswith(b"%PDF-")
