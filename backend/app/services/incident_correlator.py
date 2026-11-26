"""Intelligent alert correlation engine grouping related alerts into incidents."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from app.models.alert import SecurityAlert
from app.models.incident import CorrelatedIncident, CorrelationConfig
from app.models.mitre import MitreMapping

SEV_RANK: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFORMATIONAL": 1,
}


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


class IncidentCorrelator:
    """Correlate individual alerts into contextual incidents without discarding raw evidence."""

    def __init__(self, config: CorrelationConfig | None = None) -> None:
        self.config = config or CorrelationConfig()

    def correlate(self, alerts: list[SecurityAlert]) -> list[CorrelatedIncident]:
        """Group related alerts into deterministic CorrelatedIncident objects."""
        if not alerts:
            return []

        ordered = sorted(alerts, key=lambda a: (a.timestamp_epoch, a.alert_id))
        n = len(ordered)
        uf = _UnionFind(n)

        # 1. Bucket by configurable correlation tuple, then cluster by time window
        buckets: dict[tuple[Any, ...], list[int]] = defaultdict(list)
        for idx, alert in enumerate(ordered):
            key = self._correlation_key(alert)
            buckets[key].append(idx)

        window = max(0.0, self.config.time_window_seconds)
        for indices in buckets.values():
            if len(indices) < 2:
                continue
            prev_idx = indices[0]
            for cur_idx in indices[1:]:
                delta = ordered[cur_idx].timestamp_epoch - ordered[prev_idx].timestamp_epoch
                if delta <= window:
                    uf.union(prev_idx, cur_idx)
                prev_idx = cur_idx

        # 2. Link alerts sharing explicit non-null flow_id within the time window
        if self.config.match_flow_id:
            flow_buckets: dict[tuple[bool, str], list[int]] = defaultdict(list)
            for idx, alert in enumerate(ordered):
                flow_ids = self._extract_flow_ids(alert)
                for fid in flow_ids:
                    sup_key = alert.suppressed if self.config.separate_suppressed else False
                    flow_buckets[(sup_key, fid)].append(idx)
            for indices in flow_buckets.values():
                if len(indices) < 2:
                    continue
                anchor = indices[0]
                for cur_idx in indices[1:]:
                    delta = ordered[cur_idx].timestamp_epoch - ordered[anchor].timestamp_epoch
                    if delta <= window:
                        uf.union(anchor, cur_idx)

        # 3. Collect connected components
        components: dict[int, list[SecurityAlert]] = defaultdict(list)
        for idx, alert in enumerate(ordered):
            components[uf.find(idx)].append(alert)

        incidents: list[CorrelatedIncident] = []
        for group in components.values():
            if len(group) < self.config.min_alerts_for_incident:
                continue
            incident = self._build_incident(group)
            incidents.append(incident)
            for alert in group:
                alert.incident_id = incident.incident_id

        incidents.sort(
            key=lambda inc: (
                1 if inc.suppressed else 0,
                -inc.risk_score,
                -SEV_RANK.get(inc.overall_severity, 0),
                inc.first_seen_epoch,
            )
        )
        return incidents

    def _correlation_key(self, alert: SecurityAlert) -> tuple[Any, ...]:
        cfg = self.config
        parts: list[Any] = [alert.suppressed if cfg.separate_suppressed else False]

        # Avoid merging unrelated alerts that both have missing endpoints
        if cfg.match_source_ip:
            parts.append(alert.source_ip or f"__no_src:{alert.alert_id}")
        if cfg.match_destination_ip:
            parts.append(alert.destination_ip or f"__no_dst:{alert.alert_id}")
        if cfg.match_source_port:
            parts.append(alert.source_port)
        if cfg.match_destination_port:
            parts.append(alert.destination_port)
        if cfg.match_protocol:
            parts.append(alert.protocol)
        if cfg.match_rule:
            rule_sig = ",".join(alert.contributing_rule_ids) or ",".join(alert.detector_types)
            parts.append(rule_sig)
        return tuple(parts)

    def _extract_flow_ids(self, alert: SecurityAlert) -> list[str]:
        fids: list[str] = []
        if alert.flow_id:
            fids.append(alert.flow_id)
        ev_fids = alert.evidence.get("flow_ids")
        if isinstance(ev_fids, list):
            for fid in ev_fids:
                if isinstance(fid, str) and fid not in fids:
                    fids.append(fid)
        return fids

    def _build_incident(self, group: list[SecurityAlert]) -> CorrelatedIncident:
        ordered = sorted(group, key=lambda a: (a.timestamp_epoch, a.alert_id))
        alert_ids = [a.alert_id for a in ordered]

        # Deterministic incident_id prevents duplicate creation on repeated processing
        seed = "|".join(alert_ids)
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
        incident_id = f"inc-{digest}"

        primary = max(
            ordered,
            key=lambda a: (SEV_RANK.get(a.severity, 0), a.priority_score, a.confidence),
        )

        src_hosts = sorted({a.source_ip for a in ordered if a.source_ip})
        dst_hosts = sorted({a.destination_ip for a in ordered if a.destination_ip})
        src_ports = sorted({a.source_port for a in ordered if a.source_port is not None})
        dst_ports = sorted({a.destination_port for a in ordered if a.destination_port is not None})
        protocols = sorted({a.protocol for a in ordered if a.protocol})

        categories = sorted(
            {dt for a in ordered for dt in a.detector_types}
            | {r for a in ordered for r in a.contributing_rule_ids}
        )
        rule_ids = sorted({r for a in ordered for r in a.contributing_rule_ids})

        flow_ids_set: set[str] = set()
        pkt_indices_set: set[int] = set()
        for a in ordered:
            for fid in self._extract_flow_ids(a):
                flow_ids_set.add(fid)
            for pidx in a.packet_indices:
                pkt_indices_set.add(pidx)
            sample_p = a.evidence.get("sample_packet_indices")
            if isinstance(sample_p, list):
                for pidx in sample_p:
                    if isinstance(pidx, int):
                        pkt_indices_set.add(pidx)
            ev_p = a.evidence.get("packet_indices")
            if isinstance(ev_p, list):
                for pidx in ev_p:
                    if isinstance(pidx, int):
                        pkt_indices_set.add(pidx)

        flow_ids = sorted(flow_ids_set)
        packet_indices = sorted(pkt_indices_set)[:500]

        first_epoch = min(a.timestamp_epoch for a in ordered)
        last_epoch = max(
            (a.last_seen_epoch if a.last_seen_epoch is not None else a.timestamp_epoch)
            for a in ordered
        )
        first_seen = min(ordered, key=lambda a: a.timestamp_epoch).timestamp
        last_seen = datetime.fromtimestamp(last_epoch, tz=UTC).isoformat()

        # Overall confidence reflects strongest evidence without artificial inflation
        overall_confidence = round(max(a.confidence for a in ordered), 2)

        # Risk score combines highest alert priority + modest multi-alert corroboration
        max_prio = max(a.priority_score for a in ordered)
        distinct_detectors = len(
            {dt for a in ordered for dt in a.detector_types if dt != "yaml_rule"}
        )
        corroboration_bonus = min(10.0, max(0, distinct_detectors - 1) * 4.0)
        risk_score = round(min(100.0, max_prio + corroboration_bonus), 2)

        # Preserve severity without inflating multiple LOW alerts to CRITICAL
        overall_severity = primary.severity

        # Merge MITRE mappings across alerts in incident
        mitre_map: dict[str, MitreMapping] = {}
        for a in ordered:
            for m in a.mitre_mappings:
                existing = mitre_map.get(m.technique_id)
                if existing is None:
                    mitre_map[m.technique_id] = MitreMapping(
                        technique_id=m.technique_id,
                        technique_name=m.technique_name,
                        tactic=m.tactic,
                        reason=m.reason,
                        supporting_evidence=dict(m.supporting_evidence),
                        confidence_level=m.confidence_level,
                        confidence_score=m.confidence_score,
                        reference_url=m.reference_url,
                        source_detection_ids=list(m.source_detection_ids),
                    )
                else:
                    for det_id in m.source_detection_ids:
                        if det_id not in existing.source_detection_ids:
                            existing.source_detection_ids.append(det_id)
                    if m.confidence_score > existing.confidence_score:
                        existing.confidence_score = m.confidence_score
                        existing.confidence_level = m.confidence_level
        mitre_mappings = sorted(
            mitre_map.values(), key=lambda m: (-m.confidence_score, m.technique_id)
        )

        steps: list[str] = []
        for a in ordered:
            for step in a.recommended_investigation_steps:
                if step not in steps:
                    steps.append(step)

        if len(ordered) == 1:
            title = primary.title
        else:
            src_lbl = src_hosts[0] if len(src_hosts) == 1 else f"{len(src_hosts)} sources"
            dst_lbl = dst_hosts[0] if len(dst_hosts) == 1 else f"{len(dst_hosts)} destinations"
            title = f"Correlated {primary.title} ({src_lbl} → {dst_lbl}, {len(ordered)} alerts)"

        reason_parts = []
        if len(src_hosts) == 1:
            reason_parts.append(f"source={src_hosts[0]}")
        if len(dst_hosts) == 1:
            reason_parts.append(f"destination={dst_hosts[0]}")
        if flow_ids:
            reason_parts.append(f"flows={len(flow_ids)}")
        reason_parts.append(f"window<={self.config.time_window_seconds:.0f}s")
        correlation_reason = (
            f"Grouped {len(ordered)} alert(s) sharing {', '.join(reason_parts)} "
            f"across categories [{', '.join(categories)}]."
        )

        all_suppressed = all(a.suppressed for a in ordered)

        return CorrelatedIncident(
            incident_id=incident_id,
            incident_title=title,
            overall_severity=overall_severity,
            overall_confidence=overall_confidence,
            risk_score=risk_score,
            status="Open",
            source_hosts=src_hosts,
            destination_hosts=dst_hosts,
            source_ports=src_ports,
            destination_ports=dst_ports,
            protocols=protocols,
            detection_categories=categories,
            alert_count=len(ordered),
            suppressed=all_suppressed,
            first_seen=first_seen,
            first_seen_epoch=first_epoch,
            last_seen=last_seen,
            last_seen_epoch=last_epoch,
            alert_ids=alert_ids,
            flow_ids=flow_ids,
            packet_indices=packet_indices,
            rule_ids=rule_ids,
            mitre_mappings=mitre_mappings,
            evidence_references={
                "alert_ids": alert_ids,
                "flow_ids": flow_ids,
                "packet_indices": packet_indices[:100],
                "rule_ids": rule_ids,
                "mitre_techniques": [m.technique_id for m in mitre_mappings],
            },
            correlation_reason=correlation_reason,
            recommended_investigation_steps=steps,
        )
