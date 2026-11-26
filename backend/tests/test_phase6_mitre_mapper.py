"""Phase 6 tests: MITRE ATT&CK catalog validation and evidence-gated mapping."""

from __future__ import annotations

from app.models.detection import DetectionFinding
from app.services.mitre_mapper import MITRE_TECHNIQUE_CATALOG, MitreMapper


def test_mitre_catalog_entries_have_valid_urls_and_tactics() -> None:
    required_ids = {"T1041", "T1048.002", "T1048.003", "T1071.004", "T1567"}
    assert required_ids.issubset(MITRE_TECHNIQUE_CATALOG.keys())
    for tid, tech in MITRE_TECHNIQUE_CATALOG.items():
        assert tech.technique_id == tid
        assert tech.technique_name
        assert tech.tactic in {"Exfiltration", "Command and Control"}
        assert tech.reference_url.startswith("https://attack.mitre.org/techniques/")


def test_unknown_and_low_confidence_findings_are_not_mapped() -> None:
    mapper = MitreMapper(min_confidence_threshold=0.45)
    assert mapper.get_technique("T9999.999") is None

    low_finding = DetectionFinding(
        detection_id="det-low-1",
        detection_name="Minor Port Check",
        detector_type="suspicious_ports",
        severity="LOW",
        confidence=0.30,
        timestamp="2026-01-01T00:00:00+00:00",
        timestamp_epoch=1700000000.0,
        source_ip="10.0.0.5",
        destination_ip="10.0.0.8",
        source_port=50000,
        destination_port=8888,
        protocol="TCP",
        evidence={"external_destination": False},
        explanation="Internal non-standard port.",
        recommended_investigation_steps=[],
        candidate_mitre_ids=["T1041"],
    )
    assert mapper.map_finding(low_finding) == []

    # Even with higher confidence, internal port without volume or beacon must NOT map to T1041
    unjustified_t1041 = DetectionFinding(
        detection_id="det-unjust-1",
        detection_name="Internal Port",
        detector_type="suspicious_ports",
        severity="LOW",
        confidence=0.60,
        timestamp="2026-01-01T00:00:00+00:00",
        timestamp_epoch=1700000000.0,
        source_ip="10.0.0.5",
        destination_ip="10.0.0.8",
        source_port=50000,
        destination_port=8888,
        protocol="TCP",
        evidence={"external_destination": False},
        explanation="Internal connection.",
        recommended_investigation_steps=[],
        candidate_mitre_ids=["T1041", "T9999"],
    )
    assert mapper.map_finding(unjustified_t1041) == []


def test_multi_technique_mapping_and_incident_aggregation() -> None:
    mapper = MitreMapper()

    dns_finding = DetectionFinding(
        detection_id="det-dns-1",
        detection_name="Potential DNS Tunnelling Activity",
        detector_type="dns_tunnelling",
        severity="CRITICAL",
        confidence=0.88,
        timestamp="2026-01-01T00:00:00+00:00",
        timestamp_epoch=1700000000.0,
        source_ip="10.0.0.15",
        destination_ip="8.8.8.8",
        source_port=51000,
        destination_port=53,
        protocol="DNS",
        evidence={"parent_domain": "exfil-example.net", "query_count": 12, "max_entropy": 4.1},
        explanation="DNS tunnelling indicators observed.",
        recommended_investigation_steps=[],
        candidate_mitre_ids=["T1071.004", "T1048.003"],
    )

    http_finding = DetectionFinding(
        detection_id="det-http-1",
        detection_name="Suspicious HTTP Upload",
        detector_type="http_upload",
        severity="HIGH",
        confidence=0.82,
        timestamp="2026-01-01T00:01:00+00:00",
        timestamp_epoch=1700000060.0,
        source_ip="10.0.0.15",
        destination_ip="198.51.100.20",
        source_port=52000,
        destination_port=80,
        protocol="HTTP",
        evidence={"methods": ["POST"], "max_payload_bytes": 600_000, "upload_request_count": 1},
        explanation="Large HTTP POST upload.",
        recommended_investigation_steps=[],
        candidate_mitre_ids=["T1567", "T1041"],
    )

    beacon_finding = DetectionFinding(
        detection_id="det-beacon-1",
        detection_name="Periodic Outbound Beaconing Pattern",
        detector_type="network_beaconing",
        severity="HIGH",
        confidence=0.85,
        timestamp="2026-01-01T00:02:00+00:00",
        timestamp_epoch=1700000120.0,
        source_ip="10.0.0.15",
        destination_ip="198.51.100.20",
        source_port=52001,
        destination_port=8443,
        protocol="TCP",
        evidence={"interval_cv": 0.02, "connection_count": 6},
        explanation="Periodic outbound check-ins.",
        recommended_investigation_steps=[],
        candidate_mitre_ids=["T1041"],
    )

    dns_maps = mapper.map_finding(dns_finding)
    assert {m.technique_id for m in dns_maps} == {"T1071.004", "T1048.003"}
    assert all(m.confidence_level == "HIGH" for m in dns_maps)
    assert all(m.reference_url.startswith("https://attack.mitre.org/") for m in dns_maps)

    incident_maps = mapper.aggregate_incident_mappings([dns_finding, http_finding, beacon_finding])
    by_id = {m.technique_id: m for m in incident_maps}
    assert {"T1071.004", "T1048.003", "T1567", "T1041"}.issubset(by_id.keys())
    # T1041 merged across http_finding and beacon_finding
    assert set(by_id["T1041"].source_detection_ids) == {"det-http-1", "det-beacon-1"}
