"""Validated MITRE ATT&CK Enterprise enrichment with evidence-gating."""

from __future__ import annotations

from typing import Any

from app.models.detection import DetectionFinding
from app.models.mitre import MitreMapping, MitreTechniqueDef

# Verified against the official MITRE ATT&CK Enterprise Knowledge Base.
MITRE_TECHNIQUE_CATALOG: dict[str, MitreTechniqueDef] = {
    "T1041": MitreTechniqueDef(
        technique_id="T1041",
        technique_name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
        description=(
            "Adversaries may steal data by exfiltrating it over an existing command and "
            "control channel."
        ),
        reference_url="https://attack.mitre.org/techniques/T1041/",
    ),
    "T1048": MitreTechniqueDef(
        technique_id="T1048",
        technique_name="Exfiltration Over Alternative Protocol",
        tactic="Exfiltration",
        description=(
            "Adversaries may steal data by exfiltrating it over a different protocol than "
            "that of the existing command and control channel."
        ),
        reference_url="https://attack.mitre.org/techniques/T1048/",
    ),
    "T1048.002": MitreTechniqueDef(
        technique_id="T1048.002",
        technique_name="Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
        tactic="Exfiltration",
        description=(
            "Adversaries may steal data by exfiltrating it over an asymmetrically encrypted "
            "network protocol other than that of the existing command and control channel."
        ),
        reference_url="https://attack.mitre.org/techniques/T1048/002/",
    ),
    "T1048.003": MitreTechniqueDef(
        technique_id="T1048.003",
        technique_name="Exfiltration Over Unencrypted Non-C2 Protocol",
        tactic="Exfiltration",
        description=(
            "Adversaries may steal data by exfiltrating it over an unencrypted network "
            "protocol other than that of the existing command and control channel."
        ),
        reference_url="https://attack.mitre.org/techniques/T1048/003/",
    ),
    "T1071.001": MitreTechniqueDef(
        technique_id="T1071.001",
        technique_name="Application Layer Protocol: Web Protocols",
        tactic="Command and Control",
        description=(
            "Adversaries may communicate using application layer protocols associated with "
            "web traffic to avoid detection/network filtering."
        ),
        reference_url="https://attack.mitre.org/techniques/T1071/001/",
    ),
    "T1071.004": MitreTechniqueDef(
        technique_id="T1071.004",
        technique_name="Application Layer Protocol: DNS",
        tactic="Command and Control",
        description=(
            "Adversaries may communicate using the Domain Name System (DNS) application layer "
            "protocol to avoid detection/network filtering."
        ),
        reference_url="https://attack.mitre.org/techniques/T1071/004/",
    ),
    "T1095": MitreTechniqueDef(
        technique_id="T1095",
        technique_name="Non-Application Layer Protocol",
        tactic="Command and Control",
        description=(
            "Adversaries may use an OSI non-application layer protocol (such as ICMP) for "
            "communication between host and C2 server or among infected hosts."
        ),
        reference_url="https://attack.mitre.org/techniques/T1095/",
    ),
    "T1567": MitreTechniqueDef(
        technique_id="T1567",
        technique_name="Exfiltration Over Web Service",
        tactic="Exfiltration",
        description=(
            "Adversaries may use an existing, legitimate external Web service to exfiltrate "
            "data rather than their primary command and control channel."
        ),
        reference_url="https://attack.mitre.org/techniques/T1567/",
    ),
    "T1571": MitreTechniqueDef(
        technique_id="T1571",
        technique_name="Non-Standard Port",
        tactic="Command and Control",
        description=(
            "Adversaries may communicate using a protocol and port pairing that are typically "
            "not associated."
        ),
        reference_url="https://attack.mitre.org/techniques/T1571/",
    ),
}


def _confidence_label(score: float) -> str:
    if score >= 0.75:
        return "HIGH"
    if score >= 0.50:
        return "MEDIUM"
    return "LOW"


class MitreMapper:
    """Map behavioral and rule findings to justified MITRE ATT&CK Enterprise techniques."""

    def __init__(self, min_confidence_threshold: float = 0.45) -> None:
        self.min_confidence_threshold = min_confidence_threshold

    def get_technique(self, technique_id: str) -> MitreTechniqueDef | None:
        """Return official MITRE metadata if the technique ID is in the validated catalog."""
        return MITRE_TECHNIQUE_CATALOG.get(technique_id.strip().upper())

    def map_finding(self, finding: DetectionFinding) -> list[MitreMapping]:
        """Produce evidence-backed MITRE mappings for a single detection finding."""
        if finding.confidence < self.min_confidence_threshold:
            return []

        # Do not assign exfiltration/C2 techniques solely for generic low-signal transport events
        if finding.severity == "INFORMATIONAL":
            return []

        candidates = list(finding.candidate_mitre_ids)
        # Enrich protocol/port mismatch findings with T1571 when justified
        if (
            finding.detector_type == "protocol_anomaly"
            and finding.detection_name == "Unexpected Protocol/Port Combination"
            and "T1571" not in candidates
        ):
            candidates.append("T1571")
        if (
            finding.detector_type == "protocol_anomaly"
            and finding.protocol == "ICMP"
            and "T1095" not in candidates
        ):
            candidates.append("T1095")

        mappings: list[MitreMapping] = []
        for tech_id in candidates:
            tech_def = self.get_technique(tech_id)
            if tech_def is None:
                continue
            justification = self._justify_mapping(tech_def, finding)
            if justification is None:
                continue
            reason, evidence_subset, adjusted_score = justification
            indicators = list(finding.evidence.get("triggered_indicators", []))
            if not indicators:
                indicators = [reason]
            ev_refs = {
                "flow_id": finding.flow_id,
                "packet_indices": list(finding.packet_indices[:50]),
                "source_detection_ids": [finding.detection_id],
            }
            mappings.append(
                MitreMapping(
                    technique_id=tech_def.technique_id,
                    technique_name=tech_def.technique_name,
                    tactic=tech_def.tactic,
                    reason=reason,
                    supporting_evidence=evidence_subset,
                    confidence_level=_confidence_label(adjusted_score),
                    confidence_score=round(adjusted_score, 2),
                    reference_url=tech_def.reference_url,
                    source_detection_ids=[finding.detection_id],
                    supporting_indicators=indicators,
                    evidence_references=ev_refs,
                )
            )
        return mappings

    def enrich_findings(
        self, findings: list[DetectionFinding]
    ) -> dict[str, list[MitreMapping]]:
        """Return a mapping of detection_id -> list[MitreMapping]."""
        return {
            finding.detection_id: self.map_finding(finding)
            for finding in findings
        }

    def aggregate_incident_mappings(
        self, findings: list[DetectionFinding]
    ) -> list[MitreMapping]:
        """Deduplicate and merge justified MITRE mappings across all incident detections."""
        merged: dict[str, MitreMapping] = {}
        for finding in findings:
            for m in self.map_finding(finding):
                existing = merged.get(m.technique_id)
                if existing is None:
                    merged[m.technique_id] = m
                    continue
                for det_id in m.source_detection_ids:
                    if det_id not in existing.source_detection_ids:
                        existing.source_detection_ids.append(det_id)
                for ind in m.supporting_indicators:
                    if ind not in existing.supporting_indicators:
                        existing.supporting_indicators.append(ind)
                prev_pkts = set(existing.evidence_references.get("packet_indices", []))
                prev_pkts.update(m.evidence_references.get("packet_indices", []))
                existing.evidence_references["packet_indices"] = sorted(prev_pkts)[:100]
                existing.evidence_references["source_detection_ids"] = list(
                    existing.source_detection_ids
                )
                if m.confidence_score > existing.confidence_score:
                    existing.confidence_score = m.confidence_score
                    existing.confidence_level = m.confidence_level
                    existing.reason = f"{existing.reason} | {m.reason}"
                existing.supporting_evidence = {
                    **existing.supporting_evidence,
                    **{f"{finding.detection_id}": m.supporting_evidence},
                }

        return sorted(
            merged.values(),
            key=lambda m: (-m.confidence_score, m.technique_id),
        )

    def _justify_mapping(
        self,
        tech: MitreTechniqueDef,
        finding: DetectionFinding,
    ) -> tuple[str, dict[str, Any], float] | None:
        """Verify that observable evidence actually supports the candidate technique."""
        ev = finding.evidence
        tid = tech.technique_id

        if tid == "T1071.004":
            if finding.protocol != "DNS":
                return None
            return (
                "DNS queries exhibited multi-indicator tunnelling or anomalous NXDOMAIN behaviour.",
                {
                    "protocol": "DNS",
                    "parent_domain": ev.get("parent_domain"),
                    "query_count": ev.get("query_count") or ev.get("matched_packet_count"),
                    "max_entropy": ev.get("max_entropy"),
                    "nxdomain_ratio": ev.get("nxdomain_ratio"),
                },
                finding.confidence,
            )

        if tid == "T1048.003":
            if finding.protocol not in {"DNS", "ICMP", "HTTP", "TCP", "UDP", "MULTI"}:
                return None
            if finding.protocol == "TLS":
                return None
            return (
                f"Unencrypted {finding.protocol} traffic exhibited potential alternative-protocol "
                "exfiltration indicators.",
                {
                    "protocol": finding.protocol,
                    "source_ip": finding.source_ip,
                    "destination_ip": finding.destination_ip,
                    "outbound_bytes": ev.get("outbound_bytes"),
                    "max_packet_length": ev.get("max_packet_length"),
                    "triggered_indicators": ev.get("triggered_indicators"),
                },
                min(0.90, finding.confidence * 0.95),
            )

        if tid == "T1048.002":
            protocols = ev.get("protocols") or [finding.protocol]
            if "TLS" not in protocols and finding.protocol != "TLS":
                return None
            if (ev.get("outbound_bytes") or 0) <= 0 and finding.detector_type != "protocol_anomaly":
                return None
            return (
                "Asymmetrically encrypted TLS flow(s) transferred disproportionate outbound bytes "
                "to an external destination.",
                {
                    "protocols": protocols,
                    "outbound_bytes": ev.get("outbound_bytes"),
                    "outbound_to_inbound_ratio": ev.get("outbound_to_inbound_ratio"),
                    "observed_tls_snis": ev.get("observed_tls_snis"),
                },
                finding.confidence,
            )

        if tid == "T1567":
            if finding.protocol != "HTTP":
                return None
            return (
                "HTTP upload request(s) (POST/PUT/PATCH) sent substantial payload data to an "
                "external endpoint.",
                {
                    "methods": ev.get("methods"),
                    "max_payload_bytes": ev.get("max_payload_bytes"),
                    "upload_request_count": ev.get("upload_request_count"),
                    "sample_requests": ev.get("sample_requests"),
                },
                finding.confidence,
            )

        if tid == "T1071.001":
            if finding.protocol != "HTTP":
                return None
            sample_attrs = ev.get("sample_attributes") or {}
            raw_ip = bool(sample_attrs.get("raw_ip_host"))
            dst_port = finding.destination_port
            non_std_port = dst_port is not None and dst_port not in {80, 8080, 8000, 8008}
            req_freq = float(ev.get("requests_per_minute") or 0.0)
            if not (raw_ip or non_std_port or req_freq >= 20.0):
                return None
            return (
                "Anomalous HTTP web-protocol communication observed "
                "(raw-IP Host, uncommon port, or automated polling cadence).",
                {
                    "destination_port": dst_port,
                    "sample_attributes": sample_attrs,
                    "triggered_indicators": ev.get("triggered_indicators"),
                },
                finding.confidence,
            )

        if tid == "T1041":
            # Require periodic beaconing, external C2 port, or large outbound upload
            is_beacon = finding.detector_type == "network_beaconing"
            is_ext_c2_port = (
                finding.detector_type == "suspicious_ports"
                and bool(ev.get("external_destination"))
            )
            has_volume = (
                (ev.get("outbound_bytes") or 0) >= 50_000
                or (ev.get("max_payload_bytes") or 0) >= 50_000
                or ((ev.get("sample_attributes") or {}).get("payload_bytes") or 0) >= 50_000
            )
            if not (is_beacon or is_ext_c2_port or has_volume):
                return None
            return (
                "Traffic exhibited C2 channel characteristics (periodic beaconing, C2 port, or "
                "large outbound channel upload).",
                {
                    "destination_ip": finding.destination_ip,
                    "destination_port": finding.destination_port,
                    "outbound_bytes": ev.get("outbound_bytes") or ev.get("max_payload_bytes"),
                    "interval_cv": ev.get("interval_cv"),
                },
                min(0.92, finding.confidence * 0.95),
            )

        if tid == "T1571":
            if finding.detector_type != "protocol_anomaly":
                return None
            return (
                "Application protocol observed over an unexpected destination port.",
                {
                    "application_protocol": ev.get("application_protocol"),
                    "destination_port": ev.get("destination_port"),
                    "mismatch_reason": ev.get("mismatch_reason"),
                },
                finding.confidence,
            )

        if tid == "T1095":
            if finding.protocol != "ICMP":
                return None
            return (
                "Unusual external ICMP packet length or volume observed "
                "(non-application protocol).",
                {
                    "icmp_packet_count": ev.get("icmp_packet_count"),
                    "max_packet_length": ev.get("max_packet_length"),
                },
                finding.confidence,
            )

        return (
            f"Finding {finding.detection_name} provides supporting indicators "
            f"for {tech.technique_id}.",
            dict(ev),
            finding.confidence,
        )
