"""Phase 8 tests: standalone HTML & PDF report generation and XSS escaping."""

from __future__ import annotations

from datetime import UTC, datetime

from app.core.config import Settings
from app.detectors.flow_analyzer import FlowAnalyzer
from app.models.detection import DetectionFinding
from app.models.investigation import build_investigation_bundle
from app.models.packet import (
    CaptureMetadata,
    DnsMetadata,
    HttpMetadata,
    NormalizedPacket,
    TlsMetadata,
)
from app.reporting.reporter import ForensicReporter
from app.services.alert_manager import AlertManager


def test_generate_standalone_html_and_pdf_with_xss_escaping(temp_settings: Settings) -> None:
    temp_settings.ensure_directories()
    t0 = 1700020000.0
    xss_payload = "<script>alert('xss')</script>"

    meta = CaptureMetadata(
        analysis_id="inv-report-001",
        original_filename="capture_<evil>.pcap",
        sanitized_filename="capture_evil.pcap",
        stored_path="capture_evil.pcap",
        file_size_bytes=20480,
        sha256="c" * 64,
        capture_format="pcap",
        ingested_at_utc="2026-01-01T00:00:00+00:00",
        link_layer_type=1,
        link_layer_name="Ethernet (EN10MB)",
        packet_count=3,
    )

    packets = [
        NormalizedPacket(
            packet_index=1,
            timestamp=t0,
            timestamp_utc=datetime.fromtimestamp(t0, tz=UTC).isoformat(),
            src_ip="10.0.0.10",
            dst_ip="198.51.100.55",
            src_port=51000,
            dst_port=80,
            protocol="HTTP",
            transport_protocol="TCP",
            length=1500,
            ttl=64,
            ip_version=4,
            http=HttpMetadata(
                is_request=True,
                method="POST",
                host="drop.example.org",
                uri=f"/upload?q={xss_payload}",
                user_agent=f"BadBot {xss_payload}",
                content_length=500_000,
                payload_size=500_000,
                direction="outbound_request",
            ),
        ),
        NormalizedPacket(
            packet_index=2,
            timestamp=t0 + 1.0,
            timestamp_utc=datetime.fromtimestamp(t0 + 1.0, tz=UTC).isoformat(),
            src_ip="10.0.0.10",
            dst_ip="8.8.8.8",
            src_port=51001,
            dst_port=53,
            protocol="DNS",
            transport_protocol="UDP",
            length=120,
            ttl=64,
            ip_version=4,
            dns=DnsMetadata(
                transaction_id=9,
                is_response=False,
                query_name="4a7f9c2e8b1d.exfil-example.net",
                query_type="TXT",
                query_length=30,
                subdomain_labels=["4a7f9c2e8b1d"],
                subdomain_length=12,
                parent_domain="exfil-example.net",
                label_count=3,
            ),
        ),
        NormalizedPacket(
            packet_index=3,
            timestamp=t0 + 2.0,
            timestamp_utc=datetime.fromtimestamp(t0 + 2.0, tz=UTC).isoformat(),
            src_ip="10.0.0.10",
            dst_ip="93.184.216.34",
            src_port=51002,
            dst_port=443,
            protocol="TLS",
            transport_protocol="TCP",
            length=300,
            ttl=64,
            ip_version=4,
            tls=TlsMetadata(
                record_version="TLSv1.0",
                handshake_version="TLSv1.2",
                handshake_type="ClientHello",
                sni="cdn.example.com",
            ),
        ),
    ]

    flow_res = FlowAnalyzer().analyze(packets)
    finding = DetectionFinding(
        detection_id="det-rep-1",
        detection_name="Large HTTP POST Upload",
        detector_type="http_upload",
        severity="HIGH",
        confidence=0.84,
        timestamp=packets[0].timestamp_utc,
        timestamp_epoch=t0,
        source_ip="10.0.0.10",
        destination_ip="198.51.100.55",
        source_port=51000,
        destination_port=80,
        protocol="HTTP",
        evidence={"max_payload_bytes": 500_000, "uri": f"/upload?q={xss_payload}"},
        explanation=f"Large POST upload to URI /upload?q={xss_payload}",
        recommended_investigation_steps=["Inspect host logs on 10.0.0.10."],
        candidate_mitre_ids=["T1567", "T1041"],
    )
    alert_res = AlertManager().process_findings([finding])

    bundle = build_investigation_bundle(
        metadata=meta,
        packets=packets,
        flow_result=flow_res,
        alert_result=alert_res,
        processing_duration_ms=42.5,
    )

    reporter = ForensicReporter(temp_settings.reports_dir)
    artifacts = reporter.generate_reports(bundle)

    assert artifacts.html_path.is_file()
    assert artifacts.pdf_path.is_file()

    html = artifacts.html_path.read_text(encoding="utf-8")
    # Required report sections & metadata
    assert "inv-report-001" in html
    assert "c" * 64 in html
    assert "Executive Summary" in html
    assert "DNS, HTTP &amp; TLS Metadata Analysis" in html
    assert "MITRE ATT&amp;CK Mappings" in html
    assert "Chronological Incident Timeline" in html
    assert "Limitations &amp; Confidence Assessment" in html
    assert "https://attack.mitre.org/techniques/T1567/" in html
    # Standalone check: no external CDN script/link tags
    assert "<script src=" not in html
    # XSS escaping check: raw <script> must never appear unescaped
    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in html

    pdf_bytes = artifacts.pdf_path.read_bytes()
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 2000
