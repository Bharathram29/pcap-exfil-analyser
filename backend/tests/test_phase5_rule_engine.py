"""Phase 5 tests: YAML rule engine loading, validation, AND/OR logic, and evaluation."""

from __future__ import annotations

from pathlib import Path

from app.core.config import Settings
from app.detectors.rule_engine import YamlRuleEngine
from app.models.detection import DetectionContext
from app.models.flow import NetworkFlow
from app.models.packet import CaptureMetadata, DnsMetadata, HttpMetadata, NormalizedPacket


def _meta() -> CaptureMetadata:
    return CaptureMetadata(
        analysis_id="test-phase5",
        original_filename="test.pcap",
        sanitized_filename="test.pcap",
        stored_path="test.pcap",
        file_size_bytes=512,
        sha256="b" * 64,
        capture_format="pcap",
        ingested_at_utc="2026-01-01T00:00:00+00:00",
    )


def test_default_detection_rules_yaml_loads_cleanly() -> None:
    rules_path = Settings().rules_dir / "detection_rules.yaml"
    engine = YamlRuleEngine()
    res = engine.load_rules(rules_path)

    assert res.errors == []
    assert res.version == "1.0"
    assert len(res.rules) >= 8
    assert res.disabled_count == 1
    assert any(r.id == "RULE-001" for r in res.rules)
    assert any(r.id == "RULE-002" for r in res.rules)


def test_yaml_rules_evaluate_http_dns_and_flow_thresholds() -> None:
    rules_path = Settings().rules_dir / "detection_rules.yaml"
    engine = YamlRuleEngine()
    t0 = 1700010000.0

    # Matches RULE-001 (POST >= 500,000) and RULE-005 (OR: port 8081 not in standard ports)
    big_post = NormalizedPacket(
        packet_index=1,
        timestamp=t0,
        timestamp_utc="2023-11-15T01:00:00+00:00",
        src_ip="10.0.0.50",
        dst_ip="198.51.100.12",
        src_port=52000,
        dst_port=8081,
        protocol="HTTP",
        transport_protocol="TCP",
        length=1500,
        ttl=64,
        ip_version=4,
        http=HttpMetadata(
            is_request=True,
            method="POST",
            host="drop.example.org:8081",
            uri="/exfil",
            content_length=600_000,
            payload_size=600_000,
            direction="outbound_request",
        ),
    )

    # Matches RULE-002 (len >= 65 and entropy >= 3.8)
    long_sub = "4a7f9c2e8b1d0f3a9e7c5b6d8a2f1c4e9b0d3e7a5c1f8b2d4e6a9c0f"
    qname = f"{long_sub}.exfil-example.net"
    tunnel_dns = NormalizedPacket(
        packet_index=2,
        timestamp=t0 + 1.0,
        timestamp_utc="2023-11-15T01:00:01+00:00",
        src_ip="10.0.0.50",
        dst_ip="8.8.8.8",
        src_port=53000,
        dst_port=53,
        protocol="DNS",
        transport_protocol="UDP",
        length=140,
        ttl=64,
        ip_version=4,
        dns=DnsMetadata(
            transaction_id=10,
            is_response=False,
            query_name=qname,
            query_type="TXT",
            query_length=len(qname),
            subdomain_labels=[long_sub],
            subdomain_length=len(long_sub),
            parent_domain="exfil-example.net",
            label_count=3,
        ),
    )

    # Matches RULE-003 (FLOW outbound >= 250KB and ratio >= 5)
    exfil_flow = NetworkFlow(
        flow_id="flow-yaml-1",
        transport_protocol="TCP",
        application_protocol="TLS",
        initiator_ip="10.0.0.50",
        initiator_port=52010,
        responder_ip="203.0.113.45",
        responder_port=443,
        direction="outbound",
        bytes_initiator_to_responder=300_000,
        bytes_responder_to_initiator=10_000,
        outbound_to_inbound_ratio=30.0,
        first_seen=t0 + 2.0,
        last_seen=t0 + 5.0,
        first_seen_utc="2023-11-15T01:00:02+00:00",
        last_seen_utc="2023-11-15T01:00:05+00:00",
        total_packets=220,
        total_bytes=310_000,
    )

    ctx = DetectionContext(metadata=_meta(), packets=[big_post, tunnel_dns], flows=[exfil_flow])
    findings = engine.evaluate(ctx, rules_path=rules_path)

    matched_ids = {f.rule_id for f in findings}
    assert {"RULE-001", "RULE-002", "RULE-003", "RULE-005"}.issubset(matched_ids)
    # Disabled RULE-008 must NOT fire even though TXT query matched
    assert "RULE-008" not in matched_ids


def test_invalid_yaml_and_partial_invalid_rules_handled_gracefully(tmp_path: Path) -> None:
    engine = YamlRuleEngine()

    # 1. Broken YAML syntax
    broken_file = tmp_path / "broken.yaml"
    broken_file.write_text("rules: [unclosed", encoding="utf-8")
    broken_res = engine.load_rules(broken_file)
    assert broken_res.rules == []
    assert len(broken_res.errors) == 1

    # 2. Mixed valid + invalid rule
    mixed_file = tmp_path / "mixed.yaml"
    mixed_file.write_text(
        """
version: "2.0"
rules:
  - id: BAD-RULE
    name: Invalid Severity
    protocol: INVALID_PROTO
    severity: SUPER_HIGH
    description: Should fail validation gracefully.
  - id: CUSTOM-001
    name: Custom DNS Domain Alert
    enabled: true
    protocol: DNS
    operator: OR
    condition:
      domain_contains: "custom-c2.org"
      min_query_length: 200
    severity: HIGH
    mitre_id: T1071.004
    description: Custom user rule triggered without Python code edits.
""",
        encoding="utf-8",
    )
    mixed_res = engine.load_rules(mixed_file)
    assert len(mixed_res.errors) == 1
    assert len(mixed_res.rules) == 1
    assert mixed_res.rules[0].id == "CUSTOM-001"

    pkt = NormalizedPacket(
        packet_index=1,
        timestamp=1700010500.0,
        timestamp_utc="2023-11-15T01:08:20+00:00",
        src_ip="10.0.0.99",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=53,
        protocol="DNS",
        transport_protocol="UDP",
        length=70,
        ttl=64,
        ip_version=4,
        dns=DnsMetadata(
            transaction_id=7,
            is_response=False,
            query_name="a.custom-c2.org",
            query_type="A",
            query_length=15,
            subdomain_labels=["a"],
            subdomain_length=1,
            parent_domain="custom-c2.org",
            label_count=3,
        ),
    )
    ctx = DetectionContext(metadata=_meta(), packets=[pkt], flows=[])
    findings = engine.evaluate(ctx, rules_path=mixed_file)
    assert len(findings) == 1
    assert findings[0].rule_id == "CUSTOM-001"
    assert findings[0].candidate_mitre_ids == ["T1071.004"]
