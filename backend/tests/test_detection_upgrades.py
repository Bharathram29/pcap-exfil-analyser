"""Tests for Phase 3: upgraded statistical, behavioral, and protocol detectors."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from app.detectors.base import DetectorConfig
from app.detectors.beaconing import BeaconingDetector
from app.detectors.dns_tunnelling import DnsTunnellingDetector
from app.detectors.http_upload import HttpUploadDetector
from app.detectors.outbound_exfiltration import OutboundExfiltrationDetector
from app.detectors.protocol_anomaly import ProtocolAnomalyDetector
from app.models.detection import DetectionContext
from app.models.flow import NetworkFlow
from app.models.packet import (
    CaptureMetadata,
    DnsMetadata,
    NormalizedPacket,
    TlsMetadata,
)
from app.parsers.protocol_extractors import extract_http_metadata


def _meta() -> CaptureMetadata:
    return CaptureMetadata(
        analysis_id="test-phase3-upg",
        original_filename="test.pcap",
        sanitized_filename="test.pcap",
        stored_path="test.pcap",
        file_size_bytes=2048,
        sha256="b" * 64,
        capture_format="pcap",
        ingested_at_utc="2026-01-01T00:00:00+00:00",
    )


def test_staged_small_outbound_exfiltration_detected() -> None:
    t0 = 1700010000.0
    flows = [
        NetworkFlow(
            flow_id=f"flow-staged-{i}",
            transport_protocol="TCP",
            application_protocol="TCP",
            initiator_ip="10.0.0.12",
            initiator_port=51000 + i,
            responder_ip="198.51.100.44",
            responder_port=8443,
            direction="outbound",
            packets_initiator_to_responder=12,
            packets_responder_to_initiator=3,
            bytes_initiator_to_responder=8_000,
            bytes_responder_to_initiator=400,
            first_seen=t0 + i * 3.0,
            last_seen=t0 + i * 3.0 + 1.0,
            first_seen_utc="2026-01-01T00:00:00+00:00",
            last_seen_utc="2026-01-01T00:00:01+00:00",
            duration_seconds=1.0,
            total_packets=15,
            total_bytes=8_400,
            outbound_to_inbound_ratio=20.0,
            packet_indices=[10 + i, 11 + i],
        )
        for i in range(6)
    ]
    ctx = DetectionContext(metadata=_meta(), packets=[], flows=flows)
    findings = OutboundExfiltrationDetector().detect(ctx)
    assert len(findings) == 1
    assert findings[0].evidence["staged_transfer_pattern"] is True
    assert findings[0].evidence["packet_count"] == 90
    assert len(findings[0].packet_indices) == 7


def test_beaconing_handles_missed_packets_with_lower_confidence() -> None:
    t0 = 1700020000.0
    # 15s beacon with a missed beat between index 2 (t=30) and index 3 (t=60)
    offsets = [0.0, 15.0, 30.0, 60.0, 75.0, 90.0]
    flows = [
        NetworkFlow(
            flow_id=f"flow-gap-{i}",
            transport_protocol="TCP",
            application_protocol="TLS",
            initiator_ip="10.0.0.33",
            initiator_port=52000 + i,
            responder_ip="203.0.113.88",
            responder_port=8443,
            direction="outbound",
            bytes_initiator_to_responder=300,
            bytes_responder_to_initiator=180,
            first_seen=t0 + off,
            last_seen=t0 + off + 0.5,
            first_seen_utc="2026-01-01T00:00:00+00:00",
            last_seen_utc="2026-01-01T00:00:01+00:00",
            duration_seconds=0.5,
            total_packets=4,
            total_bytes=480,
            packet_indices=[100 + i],
        )
        for i, off in enumerate(offsets)
    ]
    findings = BeaconingDetector().detect(
        DetectionContext(metadata=_meta(), packets=[], flows=flows)
    )
    assert len(findings) == 1
    ev = findings[0].evidence
    assert ev["missed_beacon_gaps"] == 1
    assert 14.5 <= ev["mean_interval_seconds"] <= 15.5
    assert findings[0].confidence < 0.90
    assert len(ev["supporting_timestamps"]) == 6


def test_http_extractor_and_detector_handle_incomplete_body_and_ua() -> None:
    raw = (
        b"POST /drop HTTP/1.1\r\n"
        b"Host: 203.0.113.90:9000\r\n"
        b"User-Agent: python-requests/2.32.0\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: 60000\r\n\r\n"
        b"PARTIAL_DATA"
    )
    meta = extract_http_metadata(raw, "10.0.0.10", "203.0.113.90")
    assert meta is not None
    assert meta.content_type == "application/octet-stream"
    assert meta.payload_incomplete is True

    pkt = NormalizedPacket(
        packet_index=7,
        timestamp=1700030000.0,
        timestamp_utc=datetime.fromtimestamp(1700030000.0, tz=UTC).isoformat(),
        src_ip="10.0.0.10",
        dst_ip="203.0.113.90",
        src_port=51111,
        dst_port=9000,
        protocol="HTTP",
        transport_protocol="TCP",
        length=200,
        ttl=64,
        ip_version=4,
        http=meta,
    )
    findings = HttpUploadDetector().detect(
        DetectionContext(metadata=_meta(), packets=[pkt], flows=[])
    )
    assert len(findings) == 1
    assert findings[0].evidence["payload_incomplete_count"] == 1
    assert "python-requests/2.32.0" in findings[0].evidence["user_agents"]
    assert "initial TCP segment" in findings[0].explanation


def test_dns_tunnelling_extended_metrics_and_protocol_tls_arp_anomalies() -> None:
    t0 = 1700040000.0
    dns_pkts = [
        NormalizedPacket(
            packet_index=i + 1,
            timestamp=t0 + i * 0.5,
            timestamp_utc=datetime.fromtimestamp(t0 + i * 0.5, tz=UTC).isoformat(),
            src_ip="10.0.0.19",
            dst_ip="8.8.8.8",
            src_port=50000 + i,
            dst_port=53,
            protocol="DNS",
            transport_protocol="UDP",
            length=130,
            ttl=64,
            ip_version=4,
            dns=DnsMetadata(
                transaction_id=i,
                is_response=False,
                query_name=f"a1b2c3d4e5f60718293a4b5c{i:02x}d6e7f8a9b0c1.tun-test.org",
                query_type="TXT",
                query_length=55,
                subdomain_labels=[f"a1b2c3d4e5f60718293a4b5c{i:02x}d6e7f8a9b0c1"],
                subdomain_length=42,
                parent_domain="tun-test.org",
                label_count=3,
            ),
        )
        for i in range(6)
    ]
    dns_findings = DnsTunnellingDetector().detect(
        DetectionContext(metadata=_meta(), packets=dns_pkts, flows=[])
    )
    assert len(dns_findings) == 1
    assert dns_findings[0].evidence["unique_subdomain_ratio"] == 1.0
    assert dns_findings[0].evidence["encoded_subdomain_count"] == 6
    assert dns_findings[0].evidence["avg_query_length"] == 55.0

    tls_pkt = NormalizedPacket(
        packet_index=50,
        timestamp=t0 + 5.0,
        timestamp_utc=datetime.fromtimestamp(t0 + 5.0, tz=UTC).isoformat(),
        src_ip="10.0.0.19",
        dst_ip="198.51.100.12",
        src_port=55555,
        dst_port=443,
        protocol="TLS",
        transport_protocol="TCP",
        length=140,
        ttl=64,
        ip_version=4,
        tls=TlsMetadata(
            record_version="TLSv1.0",
            handshake_version="TLSv1.0",
            handshake_type="ClientHello",
            sni="legacy.example.net",
        ),
    )
    arp_pkts = [
        NormalizedPacket(
            packet_index=100 + j,
            timestamp=t0 + 6.0 + j * 0.01,
            timestamp_utc=datetime.fromtimestamp(t0 + 6.0, tz=UTC).isoformat(),
            src_ip=None,
            dst_ip=None,
            src_port=None,
            dst_port=None,
            protocol="ARP",
            transport_protocol="ARP",
            length=42,
            ttl=None,
            ip_version=None,
        )
        for j in range(16)
    ]
    anom_findings = ProtocolAnomalyDetector().detect(
        DetectionContext(metadata=_meta(), packets=[tls_pkt, *arp_pkts], flows=[])
    )
    names = {f.detection_name for f in anom_findings}
    assert "Deprecated TLS/SSL Handshake Version" in names
    assert "Elevated Local ARP Activity Burst" in names


def test_detector_config_loads_from_yaml(tmp_path: Path) -> None:
    cfg_path = tmp_path / "detector_config.yaml"
    cfg_path.write_text("dns_min_query_count: 12\nexfil_min_ratio: 6.5\n", encoding="utf-8")
    cfg = DetectorConfig.from_yaml(cfg_path)
    assert cfg.dns_min_query_count == 12
    assert cfg.exfil_min_ratio == 6.5
