"""Phase 9 tests: FastAPI REST API upload, orchestration, queries, status updates, and reports."""

from __future__ import annotations

import shutil
from pathlib import Path

from fastapi.testclient import TestClient
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from app.core.config import BACKEND_DIR, Settings
from app.main import create_app


def _build_api_test_pcap(pcap_path: Path) -> None:
    t0 = 1700030000.0
    packets = []

    # 1. Normal DNS + HTTP GET
    q_norm = (
        Ether()
        / IP(src="10.0.0.10", dst="8.8.8.8")
        / UDP(sport=51000, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="api.example.com", qtype="A"))
    )
    q_norm.time = t0
    packets.append(q_norm)

    # 2. DNS tunnelling burst (8 long high-entropy TXT queries)
    for i in range(8):
        sub = f"4a7f9c2e8b1d0f3a9e7c5b{i:02x}d4a9e1f8c3b9e2a7d6c5"
        q_tun = (
            Ether()
            / IP(src="10.0.0.10", dst="8.8.8.8")
            / UDP(sport=51100 + i, dport=53)
            / DNS(id=100 + i, qr=0, qd=DNSQR(qname=f"{sub}.exfil-example.net", qtype="TXT"))
        )
        q_tun.time = t0 + 1.0 + i * 0.2
        packets.append(q_tun)

    # 3. Large HTTP POST upload (> 500 KB declared Content-Length)
    req_hdr = (
        "POST /exfil/drop HTTP/1.1\r\n"
        "Host: 203.0.113.50:8081\r\n"
        "User-Agent: ExfilClient/1.0\r\n"
        "Content-Length: 550000\r\n\r\n"
    ).encode("ascii") + b"X" * 500
    http_post = (
        Ether()
        / IP(src="10.0.0.10", dst="203.0.113.50")
        / TCP(sport=52000, dport=8081, flags="PA", seq=100, ack=1)
        / Raw(load=req_hdr)
    )
    http_post.time = t0 + 5.0
    packets.append(http_post)

    # 4. Periodic beaconing (4 short TCP flows every 10s)
    for i in range(4):
        syn = (
            Ether()
            / IP(src="10.0.0.10", dst="198.51.100.88")
            / TCP(sport=53000 + i, dport=4444, flags="S", seq=1)
        )
        syn.time = t0 + 10.0 + i * 10.0
        packets.append(syn)

    wrpcap(str(pcap_path), packets)


def test_api_rejects_invalid_uploads_and_unknown_ids(client: TestClient) -> None:
    bad_ext = client.post(
        "/api/pcap/upload",
        files={"file": ("notes.txt", b"hello", "text/plain")},
    )
    assert bad_ext.status_code == 400

    bad_sig = client.post(
        "/api/pcap/upload",
        files={"file": ("spoof.pcap", b"NOT_A_PCAP_HEADER_DATA", "application/octet-stream")},
    )
    assert bad_sig.status_code == 400

    missing_start = client.post("/api/analysis/start", json={"analysis_id": "missing-id"})
    assert missing_start.status_code == 404

    missing_get = client.get("/api/analysis/missing-id")
    assert missing_get.status_code == 404


def test_full_api_workflow_upload_analyze_query_patch_and_reports(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    shutil.copytree(BACKEND_DIR / "rules", rules_dir)
    settings = Settings(
        environment="test",
        upload_dir=tmp_path / "uploads",
        analyses_dir=tmp_path / "analyses",
        reports_dir=tmp_path / "reports",
        rules_dir=rules_dir,
        database_path=tmp_path / "data" / "api_test.db",
    )
    app = create_app(custom_settings=settings)
    pcap_path = tmp_path / "api_workflow.pcap"
    _build_api_test_pcap(pcap_path)

    with TestClient(app) as api_client:
        # 1. Upload
        with pcap_path.open("rb") as fh:
            up_resp = api_client.post(
                "/api/pcap/upload",
                files={"file": ("api_workflow.pcap", fh, "application/vnd.tcpdump.pcap")},
            )
        assert up_resp.status_code == 201
        up_data = up_resp.json()
        analysis_id = up_data["analysis_id"]
        assert up_data["status"] == "INGESTED"
        assert len(up_data["sha256"]) == 64

        # Pre-analysis query should report 409 on /summary
        pre_sum = api_client.get(f"/api/analysis/{analysis_id}/summary")
        assert pre_sum.status_code == 409

        # 2. Start Analysis
        start_resp = api_client.post(
            "/api/analysis/start",
            json={"analysis_id": analysis_id, "run_async": False},
        )
        assert start_resp.status_code == 200
        assert start_resp.json()["status"] == "COMPLETED"

        # 3. Investigations history
        hist_resp = api_client.get("/api/investigations")
        assert hist_resp.status_code == 200
        hist = hist_resp.json()
        assert len(hist) == 1
        assert hist[0]["analysis_id"] == analysis_id
        assert hist[0]["status"] == "COMPLETED"

        # 4. Analysis & Summary
        full_resp = api_client.get(f"/api/analysis/{analysis_id}")
        assert full_resp.status_code == 200
        assert full_resp.json()["status"] == "COMPLETED"

        sum_resp = api_client.get(f"/api/analysis/{analysis_id}/summary")
        assert sum_resp.status_code == 200
        sum_data = sum_resp.json()
        assert sum_data["summary"]["total_packets"] == 14
        assert sum_data["summary"]["suspicious_events"] >= 3
        assert len(sum_data["network_graph"]["nodes"]) >= 3
        assert len(sum_data["network_graph"]["edges"]) >= 2

        # 5. Alerts + filter + PATCH status
        alerts_resp = api_client.get(f"/api/analysis/{analysis_id}/alerts")
        assert alerts_resp.status_code == 200
        alerts_data = alerts_resp.json()
        assert alerts_data["total"] >= 3
        first_alert_id = alerts_data["alerts"][0]["alert_id"]

        dns_filtered = api_client.get(f"/api/analysis/{analysis_id}/alerts?protocol=DNS")
        assert dns_filtered.status_code == 200
        assert all(a["protocol"] == "DNS" for a in dns_filtered.json()["alerts"])

        patch_resp = api_client.patch(
            f"/api/analysis/{analysis_id}/alerts/{first_alert_id}",
            json={"status": "Confirmed Suspicious"},
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["status"] == "Confirmed Suspicious"

        refetched = api_client.get(f"/api/analysis/{analysis_id}/alerts").json()["alerts"]
        updated_item = next(a for a in refetched if a["alert_id"] == first_alert_id)
        assert updated_item["status"] == "Confirmed Suspicious"

        # 6. Flows, DNS, Timeline, MITRE
        flows_resp = api_client.get(f"/api/analysis/{analysis_id}/flows")
        assert flows_resp.status_code == 200
        assert flows_resp.json()["total"] >= 5

        dns_resp = api_client.get(f"/api/analysis/{analysis_id}/dns")
        assert dns_resp.status_code == 200
        assert dns_resp.json()["dns_analysis"]["total_queries"] == 9
        assert len(dns_resp.json()["dns_analysis"]["records"]) == 9

        tl_resp = api_client.get(f"/api/analysis/{analysis_id}/timeline")
        assert tl_resp.status_code == 200
        assert tl_resp.json()["total"] >= 3

        mitre_resp = api_client.get(f"/api/analysis/{analysis_id}/mitre")
        assert mitre_resp.status_code == 200
        mitre_ids = {m["technique_id"] for m in mitre_resp.json()["mitre_mappings"]}
        assert {"T1071.004", "T1041"}.issubset(mitre_ids)

        # 7. Download HTML & PDF reports
        html_rep = api_client.get(f"/api/analysis/{analysis_id}/report?format=html")
        assert html_rep.status_code == 200
        assert "text/html" in html_rep.headers["content-type"]
        assert analysis_id in html_rep.text

        pdf_rep = api_client.get(f"/api/analysis/{analysis_id}/report?format=pdf")
        assert pdf_rep.status_code == 200
        assert "application/pdf" in pdf_rep.headers["content-type"]
        assert pdf_rep.content.startswith(b"%PDF-")

        bad_rep = api_client.get(f"/api/analysis/{analysis_id}/report?format=docx")
        assert bad_rep.status_code == 400
