"""Alert prioritisation, deduplication, correlation, and investigation state manager."""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime

from app.core.database import DatabaseManager
from app.models.alert import (
    INVESTIGATION_STATUSES,
    AllowlistMatch,
    PriorityBreakdown,
    SecurityAlert,
    TimelineEvent,
)
from app.models.detection import DetectionFinding
from app.models.incident import CorrelatedIncident, CorrelationConfig
from app.models.mitre import MitreMapping
from app.services.allowlist import AllowlistManager
from app.services.incident_correlator import IncidentCorrelator
from app.services.mitre_mapper import MitreMapper
from app.utils.network import is_external_ip

SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFORMATIONAL": 1,
}

SEVERITY_BASE_WEIGHTS: dict[str, float] = {
    "CRITICAL": 44.0,
    "HIGH": 32.0,
    "MEDIUM": 20.0,
    "LOW": 10.0,
    "INFORMATIONAL": 4.0,
}


@dataclass(slots=True)
class ScoringConfig:
    """Configurable weights for transparent risk and confidence scoring."""

    severity_weights: dict[str, float] | None = None
    max_confidence_points: float = 16.0
    max_volume_points: float = 12.0
    external_destination_points: float = 8.0
    max_frequency_points: float = 8.0
    max_correlation_points: float = 10.0
    max_evidence_quality_points: float = 8.0
    critical_min_confidence: float = 0.65
    high_min_confidence: float = 0.45


@dataclass(slots=True)
class AlertPipelineResult:
    """Output of alert correlation, prioritisation, and allowlist tagging."""

    alerts: list[SecurityAlert]
    active_alerts: list[SecurityAlert]
    suppressed_alerts: list[SecurityAlert]
    incidents: list[CorrelatedIncident]
    active_incidents: list[CorrelatedIncident]
    suppressed_incidents: list[CorrelatedIncident]
    timeline: list[TimelineEvent]
    mitre_summary: list[MitreMapping]


def _behavior_family(finding: DetectionFinding) -> str:
    """Normalize heuristic and YAML findings into shared correlation families."""
    name_l = finding.detection_name.lower()
    if finding.detector_type == "dns_tunnelling" or "dns tunnelling" in name_l:
        return "dns_tunnelling"
    if finding.detector_type == "http_upload" or (
        finding.protocol == "HTTP" and ("post" in name_l or "put" in name_l or "upload" in name_l)
    ):
        return "http_upload"
    if finding.detector_type == "outbound_exfiltration" or "outbound data transfer" in name_l:
        return "outbound_exfiltration"
    if finding.detector_type == "network_beaconing":
        return "network_beaconing"
    if finding.detector_type == "suspicious_ports" or "c2 port" in name_l:
        return "suspicious_port"
    if finding.protocol == "ICMP" and "icmp" in name_l:
        return "unusual_icmp"
    return f"{finding.detector_type}:{finding.rule_id or finding.detection_name}"


class AlertManager:
    """Deduplicate, correlate, prioritise, allowlist-tag, and persist alerts."""

    def process_findings(
        self,
        findings: list[DetectionFinding],
        mitre_mapper: MitreMapper | None = None,
        allowlist_manager: AllowlistManager | None = None,
        correlation_config: CorrelationConfig | None = None,
        scoring_config: ScoringConfig | None = None,
    ) -> AlertPipelineResult:
        """Transform raw findings into deduplicated, prioritised alerts and incidents."""
        mapper = mitre_mapper or MitreMapper()

        # Pre-check allowlist per finding so suppressed findings do not boost active correlations
        allowlist_by_idx: list[AllowlistMatch | None] = [
            allowlist_manager.check_finding(f) if allowlist_manager is not None else None
            for f in findings
        ]

        # Group overlapping detections on the same (src, dst, dst_port, protocol, family)
        CorrKey = tuple[str | None, str | None, int | None, str, str]
        groups: dict[CorrKey, list[DetectionFinding]] = defaultdict(list)
        for finding in findings:
            family = _behavior_family(finding)
            corr_key = (
                finding.source_ip,
                finding.destination_ip,
                finding.destination_port,
                finding.protocol,
                family,
            )
            groups[corr_key].append(finding)

        # Count distinct active behavior families per (source_ip, destination_ip)
        pair_families: dict[tuple[str | None, str | None], set[str]] = defaultdict(set)
        active_findings: list[DetectionFinding] = []
        for finding, amatch in zip(findings, allowlist_by_idx, strict=True):
            if amatch is None:
                active_findings.append(finding)
                pair_families[(finding.source_ip, finding.destination_ip)].add(
                    _behavior_family(finding)
                )

        alerts: list[SecurityAlert] = []
        for corr_key, group_findings in groups.items():
            src_ip, dst_ip, dst_port, protocol, family = corr_key
            correlated_count = max(
                len(group_findings),
                len(pair_families.get((src_ip, dst_ip), set())),
            )
            alert = self._build_consolidated_alert(
                corr_key=corr_key,
                group_findings=group_findings,
                correlated_count=correlated_count,
                mapper=mapper,
                allowlist_manager=allowlist_manager,
                scoring_config=scoring_config or ScoringConfig(),
            )
            alerts.append(alert)

        # Correlate alerts into higher-level incidents while preserving all raw alerts
        correlator = IncidentCorrelator(correlation_config)
        incidents = correlator.correlate(alerts)
        active_incidents = [inc for inc in incidents if not inc.suppressed]
        suppressed_incidents = [inc for inc in incidents if inc.suppressed]

        # Sort unsuppressed alerts first, then descending priority_score
        alerts.sort(
            key=lambda a: (
                1 if a.suppressed else 0,
                -a.priority_score,
                -SEVERITY_RANK.get(a.severity, 0),
                a.timestamp_epoch,
            )
        )

        active = [a for a in alerts if not a.suppressed]
        suppressed = [a for a in alerts if a.suppressed]
        timeline = self.build_timeline(alerts)
        mitre_summary = mapper.aggregate_incident_mappings(active_findings)

        return AlertPipelineResult(
            alerts=alerts,
            active_alerts=active,
            suppressed_alerts=suppressed,
            incidents=incidents,
            active_incidents=active_incidents,
            suppressed_incidents=suppressed_incidents,
            timeline=timeline,
            mitre_summary=mitre_summary,
        )

    def _build_consolidated_alert(
        self,
        corr_key: tuple[str | None, str | None, int | None, str, str],
        group_findings: list[DetectionFinding],
        correlated_count: int,
        mapper: MitreMapper,
        allowlist_manager: AllowlistManager | None,
        scoring_config: ScoringConfig | None = None,
    ) -> SecurityAlert:
        src_ip, dst_ip, dst_port, protocol, family = corr_key
        scfg = scoring_config or ScoringConfig()

        # Choose highest severity and highest confidence among merged detections
        primary = max(
            group_findings,
            key=lambda f: (SEVERITY_RANK.get(f.severity, 0), f.confidence),
        )
        earliest = min(group_findings, key=lambda f: f.timestamp_epoch)
        latest = max(group_findings, key=lambda f: f.timestamp_epoch)

        pkt_indices_set: set[int] = set()
        for f in group_findings:
            pkt_indices_set.update(f.packet_indices)
            for k in ("packet_indices", "sample_packet_indices"):
                raw_p = f.evidence.get(k)
                if isinstance(raw_p, list):
                    for pidx in raw_p:
                        if isinstance(pidx, int):
                            pkt_indices_set.add(pidx)
        pkt_indices = sorted(pkt_indices_set)[:500]

        # Compute evidence-grounded confidence separate from risk
        max_conf = max(f.confidence for f in group_findings)
        evidence_quality, quality_notes = self._evaluate_evidence_quality(
            group_findings, pkt_indices
        )
        # Do not artificially inflate confidence when evidence is sparse
        has_gaps = any(f.evidence.get("missed_beacon_gaps", 0) > 0 for f in group_findings)
        if not pkt_indices and has_gaps:
            adjusted_conf = round(max(0.30, max_conf - 0.05), 2)
        else:
            adjusted_conf = round(max_conf, 2)

        # Prevent CRITICAL severity when confidence/evidence quality is low
        max_sev = primary.severity
        if max_sev == "CRITICAL" and adjusted_conf < scfg.critical_min_confidence:
            max_sev = "HIGH"
        if max_sev == "HIGH" and adjusted_conf < scfg.high_min_confidence:
            max_sev = "MEDIUM"

        # Merge MITRE mappings across all findings in this correlation group
        group_mitre = mapper.aggregate_incident_mappings(group_findings)

        # Check allowlist against all contributing findings (preserve match if any matched)
        allowlist_match: AllowlistMatch | None = None
        if allowlist_manager is not None:
            for f in group_findings:
                match = allowlist_manager.check_finding(f)
                if match is not None:
                    allowlist_match = match
                    break

        priority_breakdown = self._compute_priority(
            severity=max_sev,
            confidence=adjusted_conf,
            evidence_quality=evidence_quality,
            quality_notes=quality_notes,
            group_findings=group_findings,
            destination_ip=dst_ip,
            correlated_count=correlated_count,
            scoring_config=scfg,
        )

        # Merge evidence cleanly without losing contributing rule details
        merged_evidence: dict[str, object] = dict(primary.evidence)
        if len(group_findings) > 1:
            merged_evidence["correlated_detections"] = [
                {
                    "detection_id": f.detection_id,
                    "name": f.detection_name,
                    "detector_type": f.detector_type,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "confidence": f.confidence,
                }
                for f in group_findings
            ]

        steps: list[str] = []
        for f in group_findings:
            for step in f.recommended_investigation_steps:
                if step not in steps:
                    steps.append(step)

        det_ids = [f.detection_id for f in group_findings]
        rule_ids = sorted({f.rule_id for f in group_findings if f.rule_id})
        det_types = sorted({f.detector_type for f in group_findings})

        digest = hashlib.sha256(
            f"alert:{src_ip}:{dst_ip}:{dst_port}:{protocol}:{family}".encode()
        ).hexdigest()[:12]

        return SecurityAlert(
            alert_id=f"alert-{digest}",
            title=primary.detection_name,
            severity=max_sev,
            confidence=adjusted_conf,
            priority_score=priority_breakdown.total_score,
            risk_score=priority_breakdown.risk_score,
            priority_breakdown=priority_breakdown,
            status="New",
            timestamp=earliest.timestamp,
            timestamp_epoch=earliest.timestamp_epoch,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=earliest.source_port,
            destination_port=dst_port,
            protocol=protocol,
            explanation=primary.explanation,
            evidence=merged_evidence,
            recommended_investigation_steps=steps,
            mitre_mappings=group_mitre,
            contributing_detection_ids=det_ids,
            contributing_rule_ids=rule_ids,
            detector_types=det_types,
            correlated_indicators_count=correlated_count,
            suppressed=allowlist_match is not None,
            allowlist_match=allowlist_match,
            observation_type=primary.observation_type,
            flow_id=primary.flow_id,
            packet_indices=pkt_indices,
            last_seen=latest.timestamp,
            last_seen_epoch=latest.timestamp_epoch,
        )

    def _evaluate_evidence_quality(
        self,
        group_findings: list[DetectionFinding],
        pkt_indices: list[int],
    ) -> tuple[float, list[str]]:
        """Score evidence completeness (0.0-1.0) separately from threat severity."""
        notes: list[str] = []
        quality = 0.35
        if pkt_indices:
            quality += 0.25
            notes.append(f"{len(pkt_indices)} packet ref(s)")
        if any(f.flow_id for f in group_findings):
            quality += 0.15
            notes.append("flow context")
        indicator_count = max(
            (len(f.evidence.get("triggered_indicators", [])) for f in group_findings),
            default=0,
        )
        if indicator_count >= 3:
            quality += 0.20
            notes.append(f"{indicator_count} indicators")
        elif indicator_count >= 1:
            quality += 0.10
            notes.append(f"{indicator_count} indicator(s)")
        if any(f.evidence.get("payload_incomplete_count", 0) > 0 for f in group_findings):
            quality -= 0.08
            notes.append("partial HTTP payload")
        if any(f.evidence.get("missed_beacon_gaps", 0) > 0 for f in group_findings):
            quality -= 0.10
            notes.append("capture gaps detected")
        return round(max(0.1, min(1.0, quality)), 2), notes

    def _compute_priority(
        self,
        severity: str,
        confidence: float,
        evidence_quality: float,
        quality_notes: list[str],
        group_findings: list[DetectionFinding],
        destination_ip: str | None,
        correlated_count: int,
        scoring_config: ScoringConfig | None = None,
    ) -> PriorityBreakdown:
        scfg = scoring_config or ScoringConfig()
        weights = scfg.severity_weights or SEVERITY_BASE_WEIGHTS
        sev_score = weights.get(severity, 10.0)
        conf_score = round(confidence * scfg.max_confidence_points, 2)
        quality_score = round(evidence_quality * scfg.max_evidence_quality_points, 2)

        # Volume score from max observed bytes across merged evidence (log-scaled)
        max_bytes = 0
        repeat_count = 1
        for f in group_findings:
            ev = f.evidence
            for b_key in (
                "outbound_bytes",
                "max_payload_bytes",
                "total_bytes",
                "total_upload_bytes",
            ):
                val = ev.get(b_key)
                if isinstance(val, (int, float)):
                    max_bytes = max(max_bytes, int(val))
            for c_key in (
                "query_count",
                "flow_count",
                "connection_count",
                "upload_request_count",
                "matched_packet_count",
            ):
                cval = ev.get(c_key)
                if isinstance(cval, int):
                    repeat_count = max(repeat_count, cval)

        volume_score = (
            round(
                min(scfg.max_volume_points, math.log10(max(max_bytes, 10)) * 2.0),
                2,
            )
            if max_bytes > 0
            else 0.0
        )
        ext_score = scfg.external_destination_points if is_external_ip(destination_ip) else 0.0
        repeat_score = round(
            min(scfg.max_frequency_points, max(0, repeat_count - 1) * 1.5),
            2,
        )
        corr_score = round(
            min(scfg.max_correlation_points, max(0, correlated_count - 1) * 4.0),
            2,
        )

        raw_total = (
            sev_score
            + conf_score
            + volume_score
            + ext_score
            + repeat_score
            + corr_score
            + quality_score
        )
        total = round(min(100.0, raw_total), 2)
        risk_score = total
        rationale = (
            f"Severity({severity})={sev_score} + Confidence({confidence:.2f})={conf_score} "
            f"+ EvidenceQuality({evidence_quality:.2f})={quality_score} "
            f"+ Volume={volume_score} + ExternalDst={ext_score} "
            f"+ Frequency={repeat_score} + Correlation({correlated_count})={corr_score}"
        )
        conf_rationale = (
            f"Confidence={confidence:.2f} (evidence_quality={evidence_quality:.2f}: "
            f"{', '.join(quality_notes) or 'basic metadata'})"
        )
        return PriorityBreakdown(
            severity_score=sev_score,
            confidence_score=conf_score,
            volume_score=volume_score,
            external_destination_score=ext_score,
            repeated_activity_score=repeat_score,
            correlation_score=corr_score,
            total_score=total,
            rationale=rationale,
            risk_score=risk_score,
            evidence_quality_score=quality_score,
            confidence_rationale=conf_rationale,
        )

    def build_timeline(self, alerts: list[SecurityAlert]) -> list[TimelineEvent]:
        """Create a chronological incident timeline across all alerts."""
        ordered = sorted(alerts, key=lambda a: (a.timestamp_epoch, -a.priority_score))
        events: list[TimelineEvent] = []
        for idx, alert in enumerate(ordered, start=1):
            rule_label = (
                ", ".join(alert.contributing_rule_ids)
                if alert.contributing_rule_ids
                else ", ".join(alert.detector_types)
            )
            mitre_ids = [m.technique_id for m in alert.mitre_mappings]
            events.append(
                TimelineEvent(
                    event_id=f"evt-{idx:04d}",
                    timestamp=alert.timestamp,
                    timestamp_epoch=alert.timestamp_epoch,
                    source_ip=alert.source_ip,
                    destination_ip=alert.destination_ip,
                    protocol=alert.protocol,
                    detection_rule=rule_label,
                    severity=alert.severity,
                    mitre_techniques=mitre_ids,
                    evidence_summary=alert.explanation,
                    suppressed=alert.suppressed,
                    alert_id=alert.alert_id,
                    incident_id=alert.incident_id,
                    packet_indices=list(alert.packet_indices),
                )
            )
        return events

    def save_alerts(
        self,
        db: DatabaseManager,
        analysis_id: str,
        alerts: list[SecurityAlert],
    ) -> None:
        """Persist alerts for an analysis into SQLite (replacing prior rows on re-run)."""
        now_utc = datetime.now(UTC).isoformat()
        with db.connection() as conn:
            conn.execute("DELETE FROM alerts WHERE analysis_id = ?", (analysis_id,))
            for alert in alerts:
                rule_ref = (
                    ",".join(alert.contributing_rule_ids)
                    if alert.contributing_rule_ids
                    else ",".join(alert.detector_types)
                )
                allow_reason = (
                    alert.allowlist_match.reason if alert.allowlist_match is not None else None
                )
                conn.execute(
                    """
                    INSERT INTO alerts (
                        alert_id, analysis_id, rule_id, title, severity, confidence,
                        priority_score, status, src_ip, dst_ip, protocol, timestamp,
                        suppressed, allowlist_reason, payload_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"{analysis_id}:{alert.alert_id}",
                        analysis_id,
                        rule_ref,
                        alert.title,
                        alert.severity,
                        alert.confidence,
                        alert.priority_score,
                        alert.status,
                        alert.source_ip,
                        alert.destination_ip,
                        alert.protocol,
                        alert.timestamp,
                        1 if alert.suppressed else 0,
                        allow_reason,
                        json.dumps(alert.to_dict()),
                        now_utc,
                        now_utc,
                    ),
                )

    def update_alert_status(
        self,
        db: DatabaseManager,
        analysis_id: str,
        alert_id: str,
        new_status: str,
    ) -> bool:
        """Update an alert's investigation workflow status in SQLite."""
        if new_status not in INVESTIGATION_STATUSES:
            raise ValueError(
                f"Invalid status {new_status!r}; expected one of {INVESTIGATION_STATUSES}"
            )

        prefix = f"{analysis_id}:"
        db_alert_id = alert_id if alert_id.startswith(prefix) else f"{prefix}{alert_id}"
        now_utc = datetime.now(UTC).isoformat()
        with db.connection() as conn:
            row = conn.execute(
                "SELECT payload_json FROM alerts WHERE alert_id = ? AND analysis_id = ?",
                (db_alert_id, analysis_id),
            ).fetchone()
            if row is None:
                return False

            payload = json.loads(row["payload_json"])
            payload["status"] = new_status
            conn.execute(
                """
                UPDATE alerts
                SET status = ?, payload_json = ?, updated_at = ?
                WHERE alert_id = ? AND analysis_id = ?
                """,
                (new_status, json.dumps(payload), now_utc, db_alert_id, analysis_id),
            )
            return True

    def save_incidents(
        self,
        db: DatabaseManager,
        analysis_id: str,
        incidents: list[CorrelatedIncident],
    ) -> None:
        """Persist correlated incidents into SQLite (replacing prior rows on re-run)."""
        now_utc = datetime.now(UTC).isoformat()
        with db.connection() as conn:
            conn.execute("DELETE FROM incidents WHERE analysis_id = ?", (analysis_id,))
            for inc in incidents:
                conn.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, analysis_id, title, severity, confidence, risk_score,
                        status, alert_count, first_seen, last_seen, suppressed,
                        payload_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"{analysis_id}:{inc.incident_id}",
                        analysis_id,
                        inc.incident_title,
                        inc.overall_severity,
                        inc.overall_confidence,
                        inc.risk_score,
                        inc.status,
                        inc.alert_count,
                        inc.first_seen,
                        inc.last_seen,
                        1 if inc.suppressed else 0,
                        json.dumps(inc.to_dict()),
                        now_utc,
                        now_utc,
                    ),
                )

    def update_incident_status(
        self,
        db: DatabaseManager,
        analysis_id: str,
        incident_id: str,
        new_status: str,
    ) -> bool:
        """Update a correlated incident's investigation status in SQLite."""
        if new_status not in INVESTIGATION_STATUSES:
            raise ValueError(
                f"Invalid status {new_status!r}; expected one of {INVESTIGATION_STATUSES}"
            )
        prefix = f"{analysis_id}:"
        db_inc_id = incident_id if incident_id.startswith(prefix) else f"{prefix}{incident_id}"
        now_utc = datetime.now(UTC).isoformat()
        with db.connection() as conn:
            row = conn.execute(
                "SELECT payload_json FROM incidents WHERE incident_id = ? AND analysis_id = ?",
                (db_inc_id, analysis_id),
            ).fetchone()
            if row is None:
                return False

            payload = json.loads(row["payload_json"])
            payload["status"] = new_status
            conn.execute(
                """
                UPDATE incidents
                SET status = ?, payload_json = ?, updated_at = ?
                WHERE incident_id = ? AND analysis_id = ?
                """,
                (new_status, json.dumps(payload), now_utc, db_inc_id, analysis_id),
            )
            return True
