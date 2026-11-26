"""Tests for Phase 5: separate risk and confidence scoring and severity safeguards."""

from __future__ import annotations

from app.models.detection import DetectionFinding
from app.services.alert_manager import AlertManager, ScoringConfig


def test_low_confidence_findings_cannot_escalate_to_critical() -> None:
    mgr = AlertManager()
    # Even if a rule claims CRITICAL, low confidence (< 0.65) caps severity at HIGH
    low_conf_crit = DetectionFinding(
        detection_id="det-lowq-1",
        detection_name="Weak Heuristic Match",
        detector_type="protocol_anomaly",
        severity="CRITICAL",
        confidence=0.40,
        timestamp="2026-01-01T00:00:00+00:00",
        timestamp_epoch=1700000000.0,
        source_ip="10.0.0.5",
        destination_ip="203.0.113.10",
        source_port=50000,
        destination_port=8080,
        protocol="TCP",
        evidence={"triggered_indicators": ["Single weak signal"]},
        explanation="Low quality signal.",
        recommended_investigation_steps=[],
    )
    res = mgr.process_findings([low_conf_crit], scoring_config=ScoringConfig())
    alert = res.alerts[0]
    assert alert.severity != "CRITICAL"
    assert alert.severity == "MEDIUM"  # 0.40 < high_min_confidence(0.45) -> downgraded
    assert alert.risk_score == alert.priority_score
    assert alert.priority_breakdown.evidence_quality_score > 0
    assert "Confidence=" in alert.priority_breakdown.confidence_rationale


def test_multiple_low_quality_indicators_stay_bounded() -> None:
    mgr = AlertManager()
    findings = [
        DetectionFinding(
            detection_id=f"det-low-{i}",
            detection_name=f"Low Indicator {i}",
            detector_type=f"custom_{i}",
            severity="LOW",
            confidence=0.35,
            timestamp="2026-01-01T00:00:00+00:00",
            timestamp_epoch=1700000000.0 + i,
            source_ip="10.0.0.5",
            destination_ip="203.0.113.10",
            source_port=50000 + i,
            destination_port=8000 + i,
            protocol="TCP",
            evidence={},
            explanation="Weak indicator.",
            recommended_investigation_steps=[],
        )
        for i in range(4)
    ]
    res = mgr.process_findings(findings)
    assert all(a.severity == "LOW" for a in res.alerts)
    assert res.incidents[0].overall_severity == "LOW"
    assert res.incidents[0].overall_confidence == 0.35
