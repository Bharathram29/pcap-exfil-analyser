"""Tests covering Phases 4-9 upgrades: detectors, calibrated scoring, 4-hop evidence, and audit."""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import BACKEND_DIR, PROJECT_ROOT, Settings
from app.core.database import DatabaseManager
from app.detectors.beaconing import BeaconingDetector
from app.detectors.dns_tunnelling import DnsTunnellingDetector
from app.detectors.flow_analyzer import FlowAnalyzer
from app.detectors.outbound_exfiltration import OutboundExfiltrationDetector
from app.main import create_app
from app.models.detection import DetectionContext, DetectionFinding
from app.models.flow import NetworkFlow
from app.models.packet import (
    CaptureMetadata,
    DnsMetadata,
    HttpMetadata,
    NormalizedPacket,
    TcpMetadata,
)
from app.services.alert_manager import AlertManager
from app.services.allowlist import AllowlistManager


def _capture_meta() -> CaptureMetadata:
    return CaptureMetadata(
        analysis_id="test-phase4-9",
        original_filename="upgrade_test.pcap",
        sanitized_filename="upgrade_test.pcap",
        stored_path="upgrade_test.pcap",
        file_size_bytes=4096,
        sha256="b" * 64,
        capture_format="pcap",
        ingested_at_utc="2026-01-01T00:00:00+00:00",
    )


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


def test_outbound_exfil_burst_periodic_baseline_and_http_volume_separation() -> None:
    """Verify 60s burst, periodic cadence, host baseline anomaly, and HTTP vs wire volume."""
    base_ts = 1_700_000_000.0
    flows: list[NetworkFlow] = []

    # Three normal small baseline outbound peers from 10.0.0.20
    for i, peer in enumerate(["198.51.100.10", "198.51.100.11", "198.51.100.12"]):
        ts = base_ts + i * 2.0
        flows.append(
            NetworkFlow(
                flow_id=f"flow-base-{i}",
                transport_protocol="TCP",
                application_protocol="TLS",
                initiator_ip="10.0.0.20",
                initiator_port=41000 + i,
                responder_ip=peer,
                responder_port=443,
                direction="outbound",
                packets_initiator_to_responder=4,
                packets_responder_to_initiator=6,
                bytes_initiator_to_responder=1_200,
                bytes_responder_to_initiator=3_200,
                first_seen=ts,
                last_seen=ts + 1.0,
                first_seen_utc=_utc(ts),
                last_seen_utc=_utc(ts + 1.0),
                duration_seconds=1.0,
                total_packets=10,
                total_bytes=4_400,
                outbound_to_inbound_ratio=0.38,
            )
        )

    # Periodic bursty outbound transfers to 203.0.113.88 every 10s
    packets: list[NormalizedPacket] = []
    for k in range(5):
        ts = base_ts + 20.0 + k * 10.0
        fid = f"flow-exfil-{k}"
        flows.append(
            NetworkFlow(
                flow_id=fid,
                transport_protocol="TCP",
                application_protocol="HTTP",
                initiator_ip="10.0.0.20",
                initiator_port=52000 + k,
                responder_ip="203.0.113.88",
                responder_port=8443,
                direction="outbound",
                packets_initiator_to_responder=40,
                packets_responder_to_initiator=5,
                bytes_initiator_to_responder=80_000,
                bytes_responder_to_initiator=1_000,
                first_seen=ts,
                last_seen=ts + 2.0,
                first_seen_utc=_utc(ts),
                last_seen_utc=_utc(ts + 2.0),
                duration_seconds=2.0,
                total_packets=45,
                total_bytes=81_000,
                outbound_to_inbound_ratio=80.0,
                packet_indices=[100 + k],
            )
        )
        packets.append(
            NormalizedPacket(
                packet_index=100 + k,
                timestamp=ts,
                timestamp_utc=_utc(ts),
                src_ip="10.0.0.20",
                dst_ip="203.0.113.88",
                src_port=52000 + k,
                dst_port=8443,
                protocol="HTTP",
                transport_protocol="TCP",
                length=1400,
                ttl=64,
                ip_version=4,
                http=HttpMetadata(
                    is_request=True,
                    method="POST",
                    host="203.0.113.88",
                    uri="/upload",
                    content_length=12_000,
                    payload_size=12_000,
                    direction="outbound",
                ),
            )
        )

    ctx = DetectionContext(metadata=_capture_meta(), packets=packets, flows=flows)
    findings = OutboundExfiltrationDetector().detect(ctx)
    target = [f for f in findings if f.destination_ip == "203.0.113.88"]
    assert len(target) == 1
    ev = target[0].evidence
    assert ev["outbound_bytes"] == 400_000
    assert ev["http_upload_count"] == 5
    assert ev["http_declared_body_bytes"] == 60_000
    assert ev["max_60s_window_bytes"] >= 320_000
    assert ev["periodic_transfer_detected"] is True
    assert ev["host_baseline_median_bytes"] == 1_200
    assert ev["baseline_anomaly"] is True


def test_dns_tunnelling_response_correlation_unusual_type_and_10s_burst() -> None:
    """Verify DNS detector tracks response sizes, unusual types, and 10s query bursts."""
    base_ts = 1_700_001_000.0
    packets: list[NormalizedPacket] = []
    subdomains = [
        "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8",
        "z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2",
        "m1n2b3v4c5x6z7a8s9d0f1g2h3j4k5l6p7o8",
        "q1w2e3r4t5y6u7i8o9p0a1s2d3f4g5h6j7k8",
        "l9k8j7h6g5f4d3s2a1p0o9i8u7y6t5r4e3w2",
        "c7v8b9n0m1x2z3l4k5j6h7g8f9d0s1a2p3o4",
        "r5t6y7u8i9o0p1a2s3d4f5g6h7j8k9l0z1x2",
    ]
    idx = 0
    for i, sub in enumerate(subdomains):
        qname = f"{sub}.tun-c2.example.org"
        ts = base_ts + i * 0.5
        packets.append(
            NormalizedPacket(
                packet_index=idx,
                timestamp=ts,
                timestamp_utc=_utc(ts),
                src_ip="10.0.0.30",
                dst_ip="8.8.4.4",
                src_port=53000 + i,
                dst_port=53,
                protocol="DNS",
                transport_protocol="UDP",
                length=140,
                ttl=64,
                ip_version=4,
                dns=DnsMetadata(
                    transaction_id=100 + i,
                    is_response=False,
                    query_name=qname,
                    query_type="NULL",
                    query_length=len(qname),
                    subdomain_labels=[sub],
                    subdomain_length=len(sub),
                    parent_domain="example.org",
                    label_count=3,
                ),
            )
        )
        idx += 1
        packets.append(
            NormalizedPacket(
                packet_index=idx,
                timestamp=ts + 0.05,
                timestamp_utc=_utc(ts + 0.05),
                src_ip="8.8.4.4",
                dst_ip="10.0.0.30",
                src_port=53,
                dst_port=53000 + i,
                protocol="DNS",
                transport_protocol="UDP",
                length=310,
                ttl=64,
                ip_version=4,
                dns=DnsMetadata(
                    transaction_id=100 + i,
                    is_response=True,
                    query_name=qname,
                    query_type="NULL",
                    query_length=len(qname),
                    parent_domain="example.org",
                    matched_query_timestamp=ts,
                    answer_count=2,
                    response_size_bytes=260,
                ),
            )
        )
        idx += 1

    ctx = DetectionContext(metadata=_capture_meta(), packets=packets, flows=[])
    findings = DnsTunnellingDetector().detect(ctx)
    assert len(findings) == 1
    ev = findings[0].evidence
    assert ev["response_count"] == 7
    assert ev["matched_response_count"] == 7
    assert ev["max_response_bytes"] == 260
    assert ev["max_10s_burst_queries"] == 7
    assert ev["txt_or_any_count"] == 7


def test_beaconing_distinguishes_periodicity_from_proven_c2() -> None:
    """Verify BeaconingDetector outputs periodicity_score and cautious non-C2 explanation."""
    base_ts = 1_700_002_000.0
    flows = [
        NetworkFlow(
            flow_id=f"beacon-{i}",
            transport_protocol="TCP",
            application_protocol="TLS",
            initiator_ip="10.0.0.40",
            initiator_port=51000 + i,
            responder_ip="198.51.100.77",
            responder_port=443,
            direction="outbound",
            packets_initiator_to_responder=3,
            packets_responder_to_initiator=2,
            bytes_initiator_to_responder=360,
            bytes_responder_to_initiator=280,
            first_seen=base_ts + i * 30.0,
            last_seen=base_ts + i * 30.0 + 0.5,
            first_seen_utc=_utc(base_ts + i * 30.0),
            last_seen_utc=_utc(base_ts + i * 30.0 + 0.5),
            duration_seconds=0.5,
            total_packets=5,
            total_bytes=640,
            std_packet_size=12.0,
        )
        for i in range(6)
    ]
    findings = BeaconingDetector().detect(
        DetectionContext(metadata=_capture_meta(), packets=[], flows=flows)
    )
    assert len(findings) == 1
    assert "periodicity_score" in findings[0].evidence
    assert "connections_per_hour" in findings[0].evidence
    assert "not proof of c2" in findings[0].explanation.lower()


def test_calibrated_risk_scoring_bands_and_duplicate_confidence_stability() -> None:
    """Verify risk score bands, explanations, and duplicate merge non-inflation."""
    allow = AllowlistManager()
    mgr = AlertManager()

    f1 = DetectionFinding(
        detection_id="det-dup-1",
        detection_name="Anomalous Outbound Data Transfer Volume",
        detector_type="outbound_exfiltration",
        severity="HIGH",
        confidence=0.80,
        timestamp="2026-01-01T00:00:00+00:00",
        timestamp_epoch=1_700_000_000.0,
        source_ip="10.0.0.50",
        destination_ip="203.0.113.77",
        source_port=50000,
        destination_port=443,
        protocol="TLS",
        evidence={"outbound_bytes": 1_200_000, "outbound_to_inbound_ratio": 18.0},
        explanation="Large outbound volume.",
        recommended_investigation_steps=["Check destination."],
        candidate_mitre_ids=["T1041"],
        packet_indices=[1, 2, 3],
    )
    f2 = DetectionFinding(
        detection_id="det-dup-2",
        detection_name="Large Outbound Data Transfer Volume",
        detector_type="yaml_rule",
        rule_id="RULE-002",
        severity="HIGH",
        confidence=0.72,
        timestamp="2026-01-01T00:00:01+00:00",
        timestamp_epoch=1_700_000_001.0,
        source_ip="10.0.0.50",
        destination_ip="203.0.113.77",
        source_port=50000,
        destination_port=443,
        protocol="TLS",
        evidence={"outbound_bytes": 1_200_000},
        explanation="YAML volume match.",
        recommended_investigation_steps=[],
        candidate_mitre_ids=["T1041"],
        packet_indices=[3, 4],
    )
    alerts = mgr.process_findings([f1, f2], allowlist_manager=allow).active_alerts
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.confidence == 0.80  # Must NOT inflate above max finding confidence
    bd = alert.priority_breakdown
    assert 0.0 <= bd.risk_score <= 100.0
    assert bd.severity_explanation != ""
    assert len(bd.score_change_reasons) >= 1
    assert len(bd.contributing_indicators) >= 1


def test_flow_metrics_duplicate_packets_and_incomplete_tcp_session() -> None:
    """Verify FlowAnalyzer handles duplicate packets, midstream TCP, and computes rate metrics."""
    base_ts = 1_700_003_000.0
    packets = [
        NormalizedPacket(
            packet_index=0,
            timestamp=base_ts,
            timestamp_utc=_utc(base_ts),
            src_ip="10.0.0.60",
            dst_ip="198.51.100.200",
            src_port=55555,
            dst_port=80,
            protocol="TCP",
            transport_protocol="TCP",
            length=600,
            ttl=64,
            ip_version=4,
            tcp=TcpMetadata(seq=100, ack=50, flags=0x18, flag_names="PSH+ACK", payload_size=546),
        ),
        # Exact duplicate packet
        NormalizedPacket(
            packet_index=1,
            timestamp=base_ts + 0.2,
            timestamp_utc=_utc(base_ts + 0.2),
            src_ip="10.0.0.60",
            dst_ip="198.51.100.200",
            src_port=55555,
            dst_port=80,
            protocol="TCP",
            transport_protocol="TCP",
            length=600,
            ttl=64,
            ip_version=4,
            tcp=TcpMetadata(
                seq=100,
                ack=50,
                flags=0x18,
                flag_names="PSH+ACK",
                payload_size=546,
                is_retransmission=True,
            ),
        ),
        NormalizedPacket(
            packet_index=2,
            timestamp=base_ts + 2.0,
            timestamp_utc=_utc(base_ts + 2.0),
            src_ip="198.51.100.200",
            dst_ip="10.0.0.60",
            src_port=80,
            dst_port=55555,
            protocol="TCP",
            transport_protocol="TCP",
            length=200,
            ttl=64,
            ip_version=4,
            tcp=TcpMetadata(seq=50, ack=646, flags=0x10, flag_names="ACK", payload_size=146),
        ),
    ]
    res = FlowAnalyzer().analyze(packets)
    assert res.total_flows == 1
    flow = res.flows[0]
    assert flow.is_midstream is True
    assert flow.handshake_completed is False
    assert flow.retransmission_reliability == "observed_tcp_seq_retransmissions"
    assert flow.bytes_per_second == 700.0
    assert flow.packets_per_second == 1.5
    assert flow.connection_frequency_per_min > 0.0


def test_api_4hop_incident_packet_filter_investigator_and_tamper_detection(
    tmp_path: Path,
) -> None:
    """Verify incident_id packet filter, X-Investigator tracking, and file tamper detection."""
    sample_pcap = PROJECT_ROOT / "sample_data" / "test_exfil.pcap"
    rules_dir = tmp_path / "rules"
    shutil.copytree(BACKEND_DIR / "rules", rules_dir)
    settings = Settings(
        environment="test",
        upload_dir=tmp_path / "uploads",
        analyses_dir=tmp_path / "analyses",
        reports_dir=tmp_path / "reports",
        rules_dir=rules_dir,
        database_path=tmp_path / "data" / "upgrade_e2e.db",
    )
    app = create_app(custom_settings=settings)
    with TestClient(app) as client:
        with sample_pcap.open("rb") as fh:
            up = client.post(
                "/api/pcap/upload",
                headers={"X-Investigator": "dfir_lead_alice"},
                files={"file": ("test_exfil.pcap", fh, "application/octet-stream")},
            )
        assert up.status_code == 201
        analysis_id = up.json()["analysis_id"]

        start = client.post(
            "/api/analysis/start", json={"analysis_id": analysis_id, "run_async": False}
        )
        assert start.status_code == 200

        bundle = client.get(f"/api/analysis/{analysis_id}").json()
        assert bundle["capture_metadata"]["packet_count"] > 0
        incidents = bundle["incidents"]
        assert len(incidents) >= 1
        inc = incidents[0]
        assert inc["status"] == "Open"

        # 4-hop lookup: Incident -> Packets directly via incident_id filter
        inc_pkts = client.get(
            f"/api/analysis/{analysis_id}/packets?incident_id={inc['incident_id']}&limit=10"
        ).json()
        assert inc_pkts["total"] >= 1
        assert all(inc["incident_id"] in p["incident_ids"] for p in inc_pkts["packets"])
        assert any(p["tcp_flags"] for p in inc_pkts["packets"] if p["transport_protocol"] == "TCP")

        # Update incident status with new dedicated status + custom investigator header
        patch = client.patch(
            f"/api/analysis/{analysis_id}/incidents/{inc['incident_id']}",
            headers={"X-Investigator": "tier2_bob"},
            json={"status": "Investigating", "notes": "Tracing outbound socket"},
        )
        assert patch.status_code == 200
        assert patch.json()["status"] == "Investigating"

        # Verify investigator recorded in DB
        db = DatabaseManager(settings.database_path)
        with db.connection() as conn:
            inv_row = conn.execute(
                "SELECT investigator_id, started_at FROM investigations WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
            assert inv_row["investigator_id"] == "dfir_lead_alice"
            assert inv_row["started_at"] is not None

        # Integrity before tamper
        integrity_ok = client.get(f"/api/analysis/{analysis_id}/integrity").json()
        assert integrity_ok["capture_integrity_verified"] is True
        assert integrity_ok["file_size_verified"] is True
        assert integrity_ok["evidence_modified"] is False

        # Tamper stored PCAP bytes and re-check integrity endpoint
        stored_pcap = Path(bundle["capture_metadata"]["stored_path"])
        with stored_pcap.open("ab") as fh:
            fh.write(b"\x00\xff")

        integrity_tampered = client.get(f"/api/analysis/{analysis_id}/integrity").json()
        assert integrity_tampered["capture_integrity_verified"] is False
        assert integrity_tampered["file_size_verified"] is False
        assert integrity_tampered["evidence_modified"] is True
