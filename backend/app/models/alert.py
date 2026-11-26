"""Domain models for prioritised security alerts, allowlist tags, and timelines."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from app.models.mitre import MitreMapping

INVESTIGATION_STATUSES = (
    "New",
    "Investigating",
    "Confirmed Suspicious",
    "False Positive",
    "Closed",
)


@dataclass(slots=True)
class PriorityBreakdown:
    """Explainable decomposition of risk score (0-100) and evidence confidence."""

    severity_score: float
    confidence_score: float
    volume_score: float
    external_destination_score: float
    repeated_activity_score: float
    correlation_score: float
    total_score: float
    rationale: str
    risk_score: float = 0.0
    evidence_quality_score: float = 0.0
    confidence_rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AllowlistMatch:
    """Audit record preserved when an alert matches an allowlist entry."""

    category: str
    matched_entry: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SecurityAlert:
    """Prioritised, deduplicated, MITRE-enriched alert surfaced to SOC analysts."""

    alert_id: str
    title: str
    severity: str
    confidence: float
    priority_score: float
    priority_breakdown: PriorityBreakdown
    status: str
    timestamp: str
    timestamp_epoch: float
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str
    explanation: str
    evidence: dict[str, Any]
    recommended_investigation_steps: list[str]
    mitre_mappings: list[MitreMapping] = field(default_factory=list)
    contributing_detection_ids: list[str] = field(default_factory=list)
    contributing_rule_ids: list[str] = field(default_factory=list)
    detector_types: list[str] = field(default_factory=list)
    correlated_indicators_count: int = 1
    suppressed: bool = False
    allowlist_match: AllowlistMatch | None = None
    observation_type: str = "SUSPICIOUS_INDICATOR"
    flow_id: str | None = None
    incident_id: str | None = None
    packet_indices: list[int] = field(default_factory=list)
    last_seen: str | None = None
    last_seen_epoch: float | None = None
    risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["mitre_mappings"] = [m.to_dict() for m in self.mitre_mappings]
        data["priority_breakdown"] = self.priority_breakdown.to_dict()
        data["allowlist_match"] = (
            self.allowlist_match.to_dict() if self.allowlist_match is not None else None
        )
        return data


@dataclass(slots=True)
class TimelineEvent:
    """Chronological security event entry for SOC incident timeline."""

    event_id: str
    timestamp: str
    timestamp_epoch: float
    source_ip: str | None
    destination_ip: str | None
    protocol: str
    detection_rule: str
    severity: str
    mitre_techniques: list[str]
    evidence_summary: str
    suppressed: bool = False
    alert_id: str | None = None
    incident_id: str | None = None
    packet_indices: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
