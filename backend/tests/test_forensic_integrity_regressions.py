"""Regression tests for forensic report parity, flow linking, MITRE, and timestamps."""

from __future__ import annotations

import base64
import re
import shutil
import zlib
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from app.core.config import BACKEND_DIR, PROJECT_ROOT, Settings
from app.detectors.http_upload import HttpUploadDetector
from app.main import create_app
from app.models.detection import DetectionContext, DetectionFinding
from app.models.flow import NetworkFlow
from app.models.packet import CaptureMetadata, HttpMetadata, NormalizedPacket
from app.reporting.reporter import ForensicReporter
from app.services.alert_manager import AlertManager
from app.services.allowlist import AllowlistManager
from app.services.mitre_mapper import MitreMapper


def _extract_pdf_text_streams(pdf_bytes: bytes) -> str:
    """Decode ASCII85 + FlateDecode ReportLab PDF streams in stdlib Python."""
    chunks: list[str] = []
    for match in re.finditer(rb"stream[\r\n]+(.*?)endstream", pdf_bytes, flags=re.S):
        raw = match.group(1).strip()
        for candidate in (raw, raw + b"~>"):
            try:
                decompressed = zlib.decompress(base64.a85decode(candidate, adobe=True))
                text = decompressed.decode("latin-1", errors="replace")
                tokens = re.findall(r"\(([^()\\]*(?:\\.[^()\\]*)*)\)", text)
                decoded = [
                    t.replace(r"\(", "(").replace(r"\)", ")").replace(r"\\", "\\")
                    for t in tokens
                ]
                chunks.append(" ".join(decoded))
                break
            except Exception:
                pass
    return "\n".join(chunks)


def test_real_pcap_packet_to_flow_association_html_pdf_parity_and_timestamps(
    tmp_path: Path,
) -> None:
    """Verify packet-to-flow links, full timestamps, and identical HTML/PDF counts & scores."""
    sample_pcap = PROJECT_ROOT / "sample_data" / "test_exfil.pcap"
    rules_dir = tmp_path / "rules"
    shutil.copytree(BACKEND_DIR / "rules", rules_dir)
    settings = Settings(
        environment="test",
        upload_dir=tmp_path / "uploads",
        analyses_dir=tmp_path / "analyses",
        reports_dir=tmp_path / "reports",
        rules_dir=rules_dir,
        database_path=tmp_path / "data" / "regressions.db",
    )
    app = create_app(custom_settings=settings)
    with TestClient(app) as client:
        with sample_pcap.open("rb") as fh:
            up = client.post(
                "/api/pcap/upload",
                files={"file": ("test_exfil.pcap", fh, "application/octet-stream")},
            )
        assert up.status_code == 201
        aid = up.json()["analysis_id"]
        st = client.post("/api/analysis/start", json={"analysis_id": aid, "run_async": False})
        assert st.status_code == 200

        bundle = client.get(f"/api/analysis/{aid}").json()
        html_text = client.get(f"/api/analysis/{aid}/report?format=html").text
        pdf_bytes = client.get(f"/api/analysis/{aid}/report?format=pdf").content
        pdf_text = _extract_pdf_text_streams(pdf_bytes)

        # 1. No missing 'flow=-' in HTML or PDF packet-level evidence for real IP traffic
        assert "flow=-" not in html_text
        assert "flow=-" not in pdf_text
        # HTTP alerts referencing packet #44 now resolve its exact flow_id
        for alert in bundle["alerts"]:
            if alert["protocol"] == "HTTP":
                assert alert["flow_id"] is not None
                assert alert["flow_id"].startswith("flow-")

        # 2. Full microsecond timestamps preserved in HTML, PDF, and packet evidence API
        assert "2025-01-01T00:00:15.050000+00:00" in html_text
        assert "2025-01-01T00:00:15.050000+00:00" in pdf_text
        assert "2025-01-01T00:00:08.000000+00:00" in html_text

        # 3. Identical counts and exact formatted risk scores across HTML & PDF
        s = bundle["summary"]
        expected_exec_phrase = (
            f"Total alerts: {s['total_alerts']} ({s['suspicious_events']} active, "
            f"{s['allowlisted_alerts']} allowlisted)"
        )
        assert expected_exec_phrase in pdf_text
        for inc in bundle["incidents"]:
            expected_score = ForensicReporter._fmt_score(inc["risk_score"])
            assert expected_score in html_text
            assert expected_score in pdf_text
            assert inc["incident_id"] in pdf_text
            assert inc["status"] in pdf_text

        for alert in bundle["alerts"]:
            risk_val = alert["priority_breakdown"].get("risk_score", alert["priority_score"])
            expected_score = ForensicReporter._fmt_score(risk_val)
            assert expected_score in html_text
            assert expected_score in pdf_text


def test_non_ip_arp_preserves_null_flow_without_fabrication(tmp_path: Path) -> None:
    """Ensure genuine non-IP detections (ARP) keep flow_id=None and render flow=null."""
    pcap_path = tmp_path / "arp_burst.pcap"
    t0 = 1_735_689_600.123456
    pkts = []
    for i in range(18):
        p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, psrc="10.0.0.5", pdst="10.0.0.1", hwsrc="00:11:22:33:44:55"
        )
        p.time = t0 + i * 0.1
        pkts.append(p)
    # Include one harmless TCP packet so flows exist, while ARP remains non-IP
    tcp_p = Ether() / IP(src="10.0.0.5", dst="198.51.100.10") / TCP(sport=50000, dport=443) / Raw(
        load=b"hi"
    )
    tcp_p.time = t0 + 2.0
    pkts.append(tcp_p)
    wrpcap(str(pcap_path), pkts)

    rules_dir = tmp_path / "rules"
    shutil.copytree(BACKEND_DIR / "rules", rules_dir)
    settings = Settings(
        environment="test",
        upload_dir=tmp_path / "uploads",
        analyses_dir=tmp_path / "analyses",
        reports_dir=tmp_path / "reports",
        rules_dir=rules_dir,
        database_path=tmp_path / "data" / "arp_null.db",
    )
    app = create_app(custom_settings=settings)
    with TestClient(app) as client:
        with pcap_path.open("rb") as fh:
            up = client.post(
                "/api/pcap/upload",
                files={"file": ("arp_burst.pcap", fh, "application/octet-stream")},
            )
        aid = up.json()["analysis_id"]
        client.post("/api/analysis/start", json={"analysis_id": aid, "run_async": False})
        bundle = client.get(f"/api/analysis/{aid}").json()
        arp_alerts = [a for a in bundle["alerts"] if a["protocol"] == "ARP"]
        assert len(arp_alerts) == 1
        assert arp_alerts[0]["flow_id"] is None

        html_text = client.get(f"/api/analysis/{aid}/report?format=html").text
        assert "flow=null" in html_text
        assert "2025-01-01T00:00:00.123456+00:00" in html_text


def test_http_explanation_distinguishes_counts_body_bytes_and_wire_bytes() -> None:
    """Verify HTTP explanations state request count, HTTP body size, and wire bytes."""
    ts = 1_700_005_000.654321
    ts_utc = datetime.fromtimestamp(ts, tz=UTC).isoformat(timespec="microseconds")
    pkt = NormalizedPacket(
        packet_index=10,
        timestamp=ts,
        timestamp_utc=ts_utc,
        src_ip="10.0.10.25",
        dst_ip="203.0.113.75",
        src_port=54000,
        dst_port=8081,
        protocol="HTTP",
        transport_protocol="TCP",
        length=1500,
        ttl=64,
        ip_version=4,
        http=HttpMetadata(
            is_request=True,
            method="POST",
            host="203.0.113.75:8081",
            uri="/exfil",
            user_agent="curl/8.0.1",
            content_length=400_000,
            payload_size=1_200,
            payload_incomplete=True,
            direction="outbound_request",
        ),
    )
    flow = NetworkFlow(
        flow_id="flow-http-1",
        transport_protocol="TCP",
        application_protocol="HTTP",
        initiator_ip="10.0.10.25",
        initiator_port=54000,
        responder_ip="203.0.113.75",
        responder_port=8081,
        direction="outbound",
        bytes_initiator_to_responder=425_000,
        bytes_responder_to_initiator=220,
        packet_indices=[10],
    )
    ctx = DetectionContext(
        metadata=CaptureMetadata(
            analysis_id="http-exp",
            original_filename="http.pcap",
            sanitized_filename="http.pcap",
            stored_path="http.pcap",
            file_size_bytes=2000,
            sha256="d" * 64,
            capture_format="pcap",
            ingested_at_utc=ts_utc,
        ),
        packets=[pkt],
        flows=[flow],
        packet_flow_map={10: "flow-http-1"},
    )
    findings = HttpUploadDetector().detect(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.flow_id == "flow-http-1"
    assert f.evidence["captured_upload_body_bytes"] == 1_200
    assert f.evidence["total_upload_bytes"] == 400_000
    assert f.evidence["flow_observed_outbound_bytes"] == 425_000
    assert "declared/max HTTP body=400,000 B" in f.explanation
    assert "captured segment body=1,200 B" in f.explanation
    assert "observed flow network outbound=425,000 B" in f.explanation
    assert {"T1567", "T1041", "T1071.001", "T1571"}.issubset(set(f.candidate_mitre_ids))


def test_mitre_mappings_strict_evidence_gating_and_no_duplicate_reasons() -> None:
    """Verify GET probes do not trigger T1567 and NXDOMAIN alone does not map T1048.003."""
    mapper = MitreMapper()
    ts_utc = "2026-01-01T00:00:00.000000+00:00"

    raw_ip_get = DetectionFinding(
        detection_id="det-http-get",
        detection_name="Raw IP HTTP GET Probe",
        detector_type="http_upload",
        severity="MEDIUM",
        confidence=0.70,
        timestamp=ts_utc,
        timestamp_epoch=1700000000.0,
        source_ip="10.0.0.5",
        destination_ip="203.0.113.55",
        source_port=51000,
        destination_port=8081,
        protocol="HTTP",
        evidence={
            "methods": ["GET"],
            "upload_request_count": 0,
            "max_payload_bytes": 0,
            "total_upload_bytes": 0,
            "sample_requests": [{"host": "203.0.113.55:8081"}],
        },
        explanation="GET probe over non-standard port.",
        recommended_investigation_steps=[],
        candidate_mitre_ids=["T1567", "T1071.001", "T1571"],
    )
    mapped_ids = {m.technique_id for m in mapper.map_finding(raw_ip_get)}
    assert "T1567" not in mapped_ids
    assert mapped_ids == {"T1071.001", "T1571"}

    # Duplicate reason guard across two findings sharing identical T1041 description
    f_a = DetectionFinding(
        detection_id="det-a",
        detection_name="Beacon A",
        detector_type="network_beaconing",
        severity="HIGH",
        confidence=0.75,
        timestamp=ts_utc,
        timestamp_epoch=1700000000.0,
        source_ip="10.0.0.5",
        destination_ip="203.0.113.55",
        source_port=50000,
        destination_port=8443,
        protocol="TLS",
        evidence={"interval_cv": 0.01},
        explanation="Beacon",
        recommended_investigation_steps=[],
        candidate_mitre_ids=["T1041"],
    )
    f_b = DetectionFinding(
        detection_id="det-b",
        detection_name="Port B",
        detector_type="suspicious_ports",
        severity="HIGH",
        confidence=0.88,
        timestamp=ts_utc,
        timestamp_epoch=1700000010.0,
        source_ip="10.0.0.5",
        destination_ip="203.0.113.55",
        source_port=50001,
        destination_port=4444,
        protocol="TCP",
        evidence={"external_destination": True, "outbound_bytes": 80_000},
        explanation="Port",
        recommended_investigation_steps=[],
        candidate_mitre_ids=["T1041"],
    )
    agg = mapper.aggregate_incident_mappings([f_a, f_b])
    assert len(agg) == 1
    assert "|" not in agg[0].reason


def test_allowlisted_incident_status_and_consistent_active_counting(tmp_path: Path) -> None:
    """Allowlisted incidents default to Resolved; resolving an active incident updates counts."""
    allow_mgr = AllowlistManager.from_yaml(Settings().rules_dir / "allowlist.yaml")
    mgr = AlertManager()
    allowlisted_finding = DetectionFinding(
        detection_id="det-allow-inc",
        detection_name="Potential DNS Tunnelling Activity",
        detector_type="dns_tunnelling",
        severity="MEDIUM",
        confidence=0.75,
        timestamp="2026-01-01T00:00:00.000000+00:00",
        timestamp_epoch=1700000000.0,
        source_ip="10.0.0.5",
        destination_ip="8.8.8.8",
        source_port=51000,
        destination_port=53,
        protocol="DNS",
        evidence={"parent_domain": "windowsupdate.com", "query_count": 8},
        explanation="Trusted domain match.",
        recommended_investigation_steps=[],
    )
    res = mgr.process_findings([allowlisted_finding], allowlist_manager=allow_mgr)
    assert len(res.incidents) == 1
    assert res.incidents[0].suppressed is True
    assert res.incidents[0].status == "Resolved"
    assert len(res.active_incidents) == 0
    assert len(res.suppressed_incidents) == 1

    # Also test end-to-end API PATCH status -> summary + report count parity
    sample_pcap = PROJECT_ROOT / "sample_data" / "test_exfil.pcap"
    rules_dir = tmp_path / "rules"
    shutil.copytree(BACKEND_DIR / "rules", rules_dir)
    settings = Settings(
        environment="test",
        upload_dir=tmp_path / "uploads",
        analyses_dir=tmp_path / "analyses",
        reports_dir=tmp_path / "reports",
        rules_dir=rules_dir,
        database_path=tmp_path / "data" / "status_sync.db",
    )
    app = create_app(custom_settings=settings)
    with TestClient(app) as client:
        with sample_pcap.open("rb") as fh:
            up = client.post(
                "/api/pcap/upload",
                files={"file": ("test_exfil.pcap", fh, "application/octet-stream")},
            )
        aid = up.json()["analysis_id"]
        client.post("/api/analysis/start", json={"analysis_id": aid, "run_async": False})
        bundle_before = client.get(f"/api/analysis/{aid}").json()
        initial_active = bundle_before["summary"]["active_incidents"]
        inc_id = bundle_before["incidents"][0]["incident_id"]

        patch = client.patch(
            f"/api/analysis/{aid}/incidents/{inc_id}",
            json={"status": "Resolved"},
        )
        assert patch.status_code == 200

        bundle_after = client.get(f"/api/analysis/{aid}").json()
        assert bundle_after["summary"]["active_incidents"] == initial_active - 1
        inc_api = client.get(f"/api/analysis/{aid}/incidents").json()
        assert inc_api["active_count"] == initial_active - 1
