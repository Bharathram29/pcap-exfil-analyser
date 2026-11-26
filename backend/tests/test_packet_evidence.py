"""Tests for Phase 4 & 6: packet-level forensic evidence store and flow stats."""

from __future__ import annotations

import shutil
from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import BACKEND_DIR, PROJECT_ROOT, Settings
from app.main import create_app


def test_packet_evidence_api_search_filter_pagination_and_alert_navigation(
    tmp_path: Path,
) -> None:
    sample_pcap = PROJECT_ROOT / "sample_data" / "test_exfil.pcap"
    rules_dir = tmp_path / "rules"
    shutil.copytree(BACKEND_DIR / "rules", rules_dir)
    settings = Settings(
        environment="test",
        upload_dir=tmp_path / "uploads",
        analyses_dir=tmp_path / "analyses",
        reports_dir=tmp_path / "reports",
        rules_dir=rules_dir,
        database_path=tmp_path / "data" / "pkt_evidence.db",
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

        # 1. Paginated packet listing
        page1 = client.get(f"/api/analysis/{analysis_id}/packets?limit=10&offset=0").json()
        assert page1["total"] > 450
        assert len(page1["packets"]) == 10
        assert page1["packets"][0]["packet_number"] == 1
        assert page1["packets"][0]["flow_id"] is not None

        # 2. Filter by protocol & port
        dns_pkts = client.get(
            f"/api/analysis/{analysis_id}/packets?protocol=DNS&port=53&limit=50"
        ).json()
        assert dns_pkts["total"] == 26  # 13 queries + 13 responses
        assert all(p["protocol"] == "DNS" for p in dns_pkts["packets"])

        # 3. Alert -> supporting packets navigation
        alerts = client.get(f"/api/analysis/{analysis_id}/alerts").json()["alerts"]
        dns_alert = next(a for a in alerts if a["protocol"] == "DNS" and not a["suppressed"])
        assert len(dns_alert["packet_indices"]) >= 10

        alert_pkts = client.get(
            f"/api/analysis/{analysis_id}/packets?alert_id={dns_alert['alert_id']}"
        ).json()
        assert alert_pkts["total"] >= 10

        # 4. Single packet detail inspection
        first_idx = dns_alert["packet_indices"][0]
        detail = client.get(f"/api/analysis/{analysis_id}/packets/{first_idx}").json()
        assert detail["packet"]["packet_index"] == first_idx
        assert "dns" in detail["packet"]["decoded_fields"]
        assert detail["flow"] is not None
        assert any(a["alert_id"] == dns_alert["alert_id"] for a in detail["alerts"])

        # 5. Flow statistical enhancements (Phase 6)
        flows = client.get(f"/api/analysis/{analysis_id}/flows?limit=50").json()["flows"]
        large_flow = max(flows, key=lambda f: f["total_bytes"])
        assert large_flow["min_packet_size"] > 0
        assert large_flow["max_packet_size"] >= large_flow["min_packet_size"]
        assert large_flow["mean_iat_seconds"] is not None
        assert large_flow["state_basis"] != ""
