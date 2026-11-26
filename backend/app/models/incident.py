"""Domain models for correlated security incidents and correlation configuration."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from app.models.mitre import MitreMapping


@dataclass(slots=True)
class CorrelationConfig:
    """Configurable grouping criteria for correlating alerts into incidents."""

    time_window_seconds: float = 300.0
    match_source_ip: bool = True
    match_destination_ip: bool = True
    match_source_port: bool = False
    match_destination_port: bool = False
    match_protocol: bool = False
    match_rule: bool = False
    match_flow_id: bool = True
    separate_suppressed: bool = True
    min_alerts_for_incident: int = 1


@dataclass(slots=True)
class CorrelatedIncident:
    """High-level security incident grouping related alerts without discarding evidence."""

    incident_id: str
    incident_title: str
    overall_severity: str
    overall_confidence: float
    risk_score: float
    status: str
    source_hosts: list[str]
    destination_hosts: list[str]
    source_ports: list[int]
    destination_ports: list[int]
    protocols: list[str]
    detection_categories: list[str]
    alert_count: int
    suppressed: bool
    first_seen: str
    first_seen_epoch: float
    last_seen: str
    last_seen_epoch: float
    alert_ids: list[str] = field(default_factory=list)
    flow_ids: list[str] = field(default_factory=list)
    packet_indices: list[int] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    mitre_mappings: list[MitreMapping] = field(default_factory=list)
    evidence_references: dict[str, Any] = field(default_factory=dict)
    correlation_reason: str = ""
    recommended_investigation_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["mitre_mappings"] = [m.to_dict() for m in self.mitre_mappings]
        return data
