"""Phase 7 tests: alert deduplication, prioritisation, allowlisting, and SQLite state."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.database import DatabaseManager
from app.models.detection import DetectionFinding
from app.services.alert_manager import AlertManager
from app.services.allowlist import AllowlistManager


def test_default_allowlist_yaml_loads_and_matches_safely() -> None:
    allow_path = Settings().rules_dir / "allowlist.yaml"
    mgr = AllowlistManager.from_yaml(allow_path)
    assert mgr.load_errors == []

    # Trusted domain wildcard
    dom_finding = DetectionFinding(
        detection_id="det-dom-1",
        detection_name="Potential DNS Tunnelling Activity",
        detector_type="dns_tunnelling",
        severity="MEDIUM",
        confidence=0.60,
        timestamp="2026-01-01T00:00:00+00:00",
        timestamp_epoch=1700000000.0,
        source_ip="10.0.0.5",
        destination_ip="8.8.8.8",
        source_port=51000,
        destination_port=53,
        protocol="DNS",
        evidence={"parent_domain": "windowsupdate.com", "sample_queries": ["dl.windowsupdate.com"]},
        explanation="Test domain match.",
        recommended_investigation_steps=[],
    )
    match = mgr.check_finding(dom_finding)
    assert match is not None
    assert match.category == "trusted_domain"

    # Approved backup service (198.51.100.250:443 TLS)
    svc_finding = DetectionFinding(
        detection_id="det-svc-1",
        detection_name="Anomalous Outbound Data Transfer Volume",
        detector_type="outbound_exfiltration",
        severity="HIGH",
        confidence=0.75,
        timestamp="2026-01-01T00:01:00+00:00",
        timestamp_epoch=1700000060.0,
        source_ip="10.0.0.5",
        destination_ip="198.51.100.250",
        source_port=52000,
        destination_port=443,
        protocol="TLS",
        evidence={"outbound_bytes": 900_000},
        explanation="Backup transfer.",
        recommended_investigation_steps=[],
    )
    svc_match = mgr.check_finding(svc_finding)
    assert svc_match is not None
    assert svc_match.category == "approved_service"

    # Non-allowlisted external exfil domain MUST NOT match
    bad_finding = DetectionFinding(
        detection_id="det-bad-1",
        detection_name="Potential DNS Tunnelling Activity",
        detector_type="dns_tunnelling",
        severity="CRITICAL",
        confidence=0.90,
        timestamp="2026-01-01T00:02:00+00:00",
        timestamp_epoch=1700000120.0,
        source_ip="10.0.0.5",
        destination_ip="8.8.8.8",
        source_port=51001,
        destination_port=53,
        protocol="DNS",
        evidence={"parent_domain": "exfil-example.net"},
        explanation="Suspicious domain.",
        recommended_investigation_steps=[],
    )
    assert mgr.check_finding(bad_finding) is None


def test_alert_deduplication_prioritisation_and_suppressed_preservation() -> None:
    allow_mgr = AllowlistManager.from_yaml(Settings().rules_dir / "allowlist.yaml")
    alert_mgr = AlertManager()

    # Two overlapping findings (heuristic + YAML RULE-001) on same HTTP upload target
    f_heur = DetectionFinding(
        detection_id="det-http-heur",
        detection_name="Suspicious HTTP Upload / Request Behaviour",
        detector_type="http_upload",
        severity="HIGH",
        confidence=0.82,
        timestamp="2026-01-01T00:00:00+00:00",
        timestamp_epoch=1700000000.0,
        source_ip="10.0.0.25",
        destination_ip="203.0.113.99",
        source_port=54000,
        destination_port=80,
        protocol="HTTP",
        evidence={"methods": ["POST"], "max_payload_bytes": 600_000, "upload_request_count": 3},
        explanation="Heuristic detected large POST.",
        recommended_investigation_steps=["Check HTTP Host/URI."],
        candidate_mitre_ids=["T1567"],
    )
    f_yaml = DetectionFinding(
        detection_id="det-http-yaml",
        detection_name="Large HTTP POST Upload",
        detector_type="yaml_rule",
        rule_id="RULE-001",
        severity="HIGH",
        confidence=0.80,
        timestamp="2026-01-01T00:00:00+00:00",
        timestamp_epoch=1700000000.0,
        source_ip="10.0.0.25",
        destination_ip="203.0.113.99",
        source_port=54000,
        destination_port=80,
        protocol="HTTP",
        evidence={"sample_attributes": {"payload_bytes": 600_000}},
        explanation="[RULE-001] Large outbound HTTP POST upload detected.",
        recommended_investigation_steps=["Verify endpoint process."],
        candidate_mitre_ids=["T1041"],
    )
    # Allowlisted monitoring finding -> must be preserved with suppressed=True
    f_mon = DetectionFinding(
        detection_id="det-mon-1",
        detection_name="Connection to Uncommon/High-Risk Port (9001)",
        detector_type="suspicious_ports",
        severity="LOW",
        confidence=0.50,
        timestamp="2026-01-01T00:01:00+00:00",
        timestamp_epoch=1700000060.0,
        source_ip="10.250.10.5",
        destination_ip="10.0.0.25",
        source_port=40000,
        destination_port=9001,
        protocol="TCP",
        evidence={"external_destination": False},
        explanation="Monitoring system check.",
        recommended_investigation_steps=[],
    )

    res = alert_mgr.process_findings([f_heur, f_yaml, f_mon], allowlist_manager=allow_mgr)

    # 3 raw findings deduplicated into 2 alerts (never deleting the suppressed one)
    assert len(res.alerts) == 2
    assert len(res.active_alerts) == 1
    assert len(res.suppressed_alerts) == 1

    active = res.active_alerts[0]
    assert active.correlated_indicators_count == 2
    assert active.contributing_rule_ids == ["RULE-001"]
    assert {m.technique_id for m in active.mitre_mappings} == {"T1567", "T1041"}
    assert active.priority_breakdown.correlation_score > 0
    assert active.priority_score > res.suppressed_alerts[0].priority_score

    sup = res.suppressed_alerts[0]
    assert sup.suppressed is True
    assert sup.allowlist_match is not None
    assert sup.allowlist_match.category == "known_monitoring_system"

    # Chronological timeline preserves both events
    assert len(res.timeline) == 2
    assert res.timeline[0].timestamp_epoch <= res.timeline[1].timestamp_epoch


def test_alert_persistence_and_status_updates(temp_settings: Settings) -> None:
    temp_settings.ensure_directories()
    db = DatabaseManager(temp_settings.database_path)
    db.init_schema()

    with db.connection() as conn:
        conn.execute(
            """
            INSERT INTO investigations (
                analysis_id, filename, stored_path, file_size_bytes,
                sha256, status, created_at, updated_at
            ) VALUES ('inv-alert-1', 'x.pcap', 'x.pcap', 100, 'abc', 'COMPLETED', 't', 't')
            """
        )

    alert_mgr = AlertManager()
    finding = DetectionFinding(
        detection_id="det-1",
        detection_name="Potential DNS Tunnelling Activity",
        detector_type="dns_tunnelling",
        severity="CRITICAL",
        confidence=0.90,
        timestamp="2026-01-01T00:00:00+00:00",
        timestamp_epoch=1700000000.0,
        source_ip="10.0.0.5",
        destination_ip="8.8.8.8",
        source_port=50000,
        destination_port=53,
        protocol="DNS",
        evidence={"query_count": 10},
        explanation="DNS tunnelling.",
        recommended_investigation_steps=[],
        candidate_mitre_ids=["T1071.004"],
    )
    res = alert_mgr.process_findings([finding])
    alert_mgr.save_alerts(db, "inv-alert-1", res.alerts)

    alert_id = res.alerts[0].alert_id
    updated = alert_mgr.update_alert_status(
        db, "inv-alert-1", alert_id, "Confirmed Suspicious"
    )
    assert updated is True
    assert alert_mgr.update_alert_status(db, "inv-alert-1", "nonexistent", "Closed") is False

    with pytest.raises(ValueError):
        alert_mgr.update_alert_status(db, "inv-alert-1", alert_id, "BogusStatus")
