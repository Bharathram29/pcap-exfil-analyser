"""Phase 4 tests: statistical heuristics and behavioral detection modules."""

from __future__ import annotations

from datetime import UTC, datetime

from app.detectors.base import DetectorConfig
from app.detectors.beaconing import BeaconingDetector
from app.detectors.dns_tunnelling import DnsTunnellingDetector
from app.detectors.engine import DetectionEngine
from app.detectors.http_upload import HttpUploadDetector
from app.detectors.outbound_exfiltration import OutboundExfiltrationDetector
from app.detectors.protocol_anomaly import ProtocolAnomalyDetector
from app.detectors.suspicious_ports import SuspiciousPortDetector
from app.models.detection import DetectionContext
from app.models.flow import NetworkFlow
from app.models.packet import CaptureMetadata, DnsMetadata, HttpMetadata, NormalizedPacket
from app.utils.entropy import character_distribution_metrics, shannon_entropy


def _meta() -> CaptureMetadata:
    return CaptureMetadata(
        analysis_id="test-phase4",
        original_filename="test.pcap",
        sanitized_filename="test.pcap",
        stored_path="test.pcap",
        file_size_bytes=1024,
        sha256="a" * 64,
        capture_format="pcap",
        ingested_at_utc="2026-01-01T00:00:00+00:00",
    )


def _dns_pkt(idx: int, ts: float, qname: str, qtype: str = "TXT") -> NormalizedPacket:
    labels = qname.split(".")
    parent = ".".join(labels[-2:])
    subs = labels[:-2]
    sub_len = len(".".join(subs))
    return NormalizedPacket(
        packet_index=idx,
        timestamp=ts,
        timestamp_utc=datetime.fromtimestamp(ts, tz=UTC).isoformat(),
        src_ip="10.0.0.15",
        dst_ip="8.8.8.8",
        src_port=50000 + idx,
        dst_port=53,
        protocol="DNS",
        transport_protocol="UDP",
        length=120,
        ttl=64,
        ip_version=4,
        dns=DnsMetadata(
            transaction_id=idx,
            is_response=False,
            query_name=qname,
            query_type=qtype,
            query_length=len(qname),
            subdomain_labels=subs,
            subdomain_length=sub_len,
            parent_domain=parent,
            label_count=len(labels),
        ),
    )


def test_entropy_and_character_metrics() -> None:
    low = shannon_entropy("aaaaaaaaaa")
    high = shannon_entropy("4a7f9c2e8b1d0f3a9e7c5b6d8a2f1c4e")
    assert low == 0.0
    assert high > 3.5

    metrics = character_distribution_metrics("4a7f9c2e8b1d0f3a9e7c")
    assert metrics["hex_ratio"] == 1.0
    assert metrics["digit_ratio"] > 0.3


def test_dns_tunnelling_requires_multiple_indicators() -> None:
    t0 = 1700001000.0
    # Single high-entropy query should NOT trigger by itself
    single_ctx = DetectionContext(
        metadata=_meta(),
        packets=[_dns_pkt(1, t0, "4a7f9c2e8b1d.cdn-static.net", qtype="A")],
        flows=[],
    )
    assert DnsTunnellingDetector().detect(single_ctx) == []

    # Burst of 8 long, high-entropy unique TXT subdomains should trigger
    burst_pkts = [
        _dns_pkt(
            i,
            t0 + i * 0.5,
            f"4a7f9c2e8b1d0f3a9e7c5b{i:02x}d4a9e1f8c3b.exfil-example.net",
            qtype="TXT",
        )
        for i in range(1, 9)
    ]
    burst_ctx = DetectionContext(metadata=_meta(), packets=burst_pkts, flows=[])
    findings = DnsTunnellingDetector().detect(burst_ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity in {"HIGH", "CRITICAL"}
    assert f.confidence >= 0.70
    assert f.evidence["query_count"] == 8
    assert f.evidence["unique_subdomains"] == 8
    assert len(f.evidence["triggered_indicators"]) >= 4


def test_outbound_exfiltration_byte_ratio_and_benign_download() -> None:
    t0 = 1700002000.0
    exfil_flow = NetworkFlow(
        flow_id="flow-exfil-1",
        transport_protocol="TCP",
        application_protocol="TLS",
        initiator_ip="10.0.0.20",
        initiator_port=52001,
        responder_ip="198.51.100.77",
        responder_port=8443,
        direction="outbound",
        packets_initiator_to_responder=400,
        packets_responder_to_initiator=25,
        bytes_initiator_to_responder=550_000,
        bytes_responder_to_initiator=5_000,
        first_seen=t0,
        last_seen=t0 + 45.0,
        first_seen_utc="2023-11-14T22:46:40+00:00",
        last_seen_utc="2023-11-14T22:47:25+00:00",
        duration_seconds=45.0,
        total_packets=425,
        total_bytes=555_000,
        outbound_to_inbound_ratio=110.0,
    )
    normal_download = NetworkFlow(
        flow_id="flow-dl-1",
        transport_protocol="TCP",
        application_protocol="TLS",
        initiator_ip="10.0.0.20",
        initiator_port=52002,
        responder_ip="93.184.216.34",
        responder_port=443,
        direction="outbound",
        packets_initiator_to_responder=30,
        packets_responder_to_initiator=400,
        bytes_initiator_to_responder=4_000,
        bytes_responder_to_initiator=550_000,
        first_seen=t0,
        last_seen=t0 + 2.0,
        first_seen_utc="2023-11-14T22:46:40+00:00",
        last_seen_utc="2023-11-14T22:46:42+00:00",
        duration_seconds=2.0,
        total_packets=430,
        total_bytes=554_000,
        outbound_to_inbound_ratio=0.007,
    )

    ctx = DetectionContext(metadata=_meta(), packets=[], flows=[exfil_flow, normal_download])
    findings = OutboundExfiltrationDetector().detect(ctx)
    assert len(findings) == 1
    assert findings[0].destination_ip == "198.51.100.77"
    assert findings[0].evidence["outbound_to_inbound_ratio"] == 110.0
    assert "NAT" in findings[0].explanation


def test_http_upload_detector_flags_large_post_and_raw_ip_and_skips_normal_get() -> None:
    t0 = 1700003000.0
    normal_get = NormalizedPacket(
        packet_index=1,
        timestamp=t0,
        timestamp_utc="2023-11-14T23:03:20+00:00",
        src_ip="10.0.0.10",
        dst_ip="93.184.216.34",
        src_port=51111,
        dst_port=80,
        protocol="HTTP",
        transport_protocol="TCP",
        length=180,
        ttl=64,
        ip_version=4,
        http=HttpMetadata(
            is_request=True,
            method="GET",
            host="api.example.com",
            uri="/status",
            payload_size=0,
            direction="outbound_request",
        ),
    )
    large_post = NormalizedPacket(
        packet_index=2,
        timestamp=t0 + 1.0,
        timestamp_utc="2023-11-14T23:03:21+00:00",
        src_ip="10.0.0.10",
        dst_ip="203.0.113.99",
        src_port=51112,
        dst_port=8081,
        protocol="HTTP",
        transport_protocol="TCP",
        length=1500,
        ttl=64,
        ip_version=4,
        http=HttpMetadata(
            is_request=True,
            method="POST",
            host="203.0.113.99:8081",
            uri="/gate/upload",
            user_agent="python-requests/2.31",
            content_length=120_000,
            payload_size=120_000,
            direction="outbound_request",
        ),
    )

    ctx = DetectionContext(metadata=_meta(), packets=[normal_get, large_post], flows=[])
    findings = HttpUploadDetector().detect(ctx)
    assert len(findings) == 1
    assert findings[0].destination_ip == "203.0.113.99"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].evidence["max_payload_bytes"] == 120_000


def test_beaconing_detector_identifies_periodic_connections_and_ignores_jitter() -> None:
    t0 = 1700004000.0
    periodic_flows = [
        NetworkFlow(
            flow_id=f"flow-b-{i}",
            transport_protocol="TCP",
            application_protocol="TCP",
            initiator_ip="10.0.0.30",
            initiator_port=53000 + i,
            responder_ip="198.51.100.88",
            responder_port=8443,
            direction="outbound",
            bytes_initiator_to_responder=240,
            bytes_responder_to_initiator=120,
            first_seen=t0 + i * 10.0 + (0.1 if i % 2 else -0.1),
            last_seen=t0 + i * 10.0 + 0.5,
            first_seen_utc="2023-11-14T23:20:00+00:00",
            last_seen_utc="2023-11-14T23:20:01+00:00",
            total_packets=4,
            total_bytes=360,
        )
        for i in range(6)
    ]
    irregular_offsets = [0.0, 2.0, 35.0, 37.0, 120.0]
    irregular_flows = [
        NetworkFlow(
            flow_id=f"flow-irr-{i}",
            transport_protocol="TCP",
            application_protocol="TLS",
            initiator_ip="10.0.0.30",
            initiator_port=54000 + i,
            responder_ip="93.184.216.34",
            responder_port=443,
            direction="outbound",
            bytes_initiator_to_responder=500,
            bytes_responder_to_initiator=1500,
            first_seen=t0 + offset,
            last_seen=t0 + offset + 1.0,
            first_seen_utc="2023-11-14T23:20:00+00:00",
            last_seen_utc="2023-11-14T23:20:01+00:00",
            total_packets=6,
            total_bytes=2000,
        )
        for i, offset in enumerate(irregular_offsets)
    ]

    ctx = DetectionContext(metadata=_meta(), packets=[], flows=periodic_flows + irregular_flows)
    findings = BeaconingDetector().detect(ctx)
    assert len(findings) == 1
    assert findings[0].destination_ip == "198.51.100.88"
    assert findings[0].evidence["connection_count"] == 6
    assert 9.5 <= findings[0].evidence["mean_interval_seconds"] <= 10.5
    assert findings[0].evidence["interval_cv"] < 0.05


def test_suspicious_ports_and_protocol_anomalies_and_engine() -> None:
    t0 = 1700005000.0
    flows = [
        # Suspicious port 4444 + HTTP over 443 mismatch
        NetworkFlow(
            flow_id="flow-port-4444",
            transport_protocol="TCP",
            application_protocol="TCP",
            initiator_ip="10.0.0.40",
            initiator_port=50100,
            responder_ip="203.0.113.200",
            responder_port=4444,
            direction="outbound",
            bytes_initiator_to_responder=60_000,
            bytes_responder_to_initiator=500,
            first_seen=t0,
            last_seen=t0 + 2.0,
            first_seen_utc="2023-11-14T23:36:40+00:00",
            last_seen_utc="2023-11-14T23:36:42+00:00",
            total_packets=50,
            total_bytes=60_500,
        ),
        NetworkFlow(
            flow_id="flow-http-443",
            transport_protocol="TCP",
            application_protocol="HTTP",
            initiator_ip="10.0.0.40",
            initiator_port=50101,
            responder_ip="203.0.113.201",
            responder_port=443,
            direction="outbound",
            first_seen=t0 + 1.0,
            last_seen=t0 + 1.5,
            first_seen_utc="2023-11-14T23:36:41+00:00",
            last_seen_utc="2023-11-14T23:36:41+00:00",
            total_packets=4,
            total_bytes=400,
        ),
    ]
    icmp_pkt = NormalizedPacket(
        packet_index=1,
        timestamp=t0 + 2.0,
        timestamp_utc="2023-11-14T23:36:42+00:00",
        src_ip="10.0.0.40",
        dst_ip="203.0.113.202",
        src_port=None,
        dst_port=None,
        protocol="ICMP",
        transport_protocol="ICMP",
        length=400,
        ttl=64,
        ip_version=4,
    )
    nx_pkts = [
        NormalizedPacket(
            packet_index=10 + i,
            timestamp=t0 + 3.0 + i * 0.1,
            timestamp_utc="2023-11-14T23:36:43+00:00",
            src_ip="8.8.8.8",
            dst_ip="10.0.0.40",
            src_port=53,
            dst_port=55000 + i,
            protocol="DNS",
            transport_protocol="UDP",
            length=90,
            ttl=55,
            ip_version=4,
            dns=DnsMetadata(
                transaction_id=i,
                is_response=True,
                query_name=f"dga{i}.bad.net",
                query_type="A",
                response_code="NXDOMAIN",
            ),
        )
        for i in range(5)
    ]

    ctx = DetectionContext(metadata=_meta(), packets=[icmp_pkt, *nx_pkts], flows=flows)
    port_findings = SuspiciousPortDetector().detect(ctx)
    assert len(port_findings) == 1
    assert port_findings[0].destination_port == 4444
    assert "do not prove malicious activity" in port_findings[0].explanation

    anom_findings = ProtocolAnomalyDetector().detect(ctx)
    anom_names = {f.detection_name for f in anom_findings}
    assert "Unexpected Protocol/Port Combination" in anom_names
    assert "Unusual External ICMP Payload / Volume" in anom_names
    assert "High DNS NXDOMAIN Failure Ratio" in anom_names

    all_findings = DetectionEngine(DetectorConfig()).run(ctx)
    assert len(all_findings) >= 4
