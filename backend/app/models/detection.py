"""Domain models for heuristic/rule detections and analysis context."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from app.models.flow import NetworkFlow
from app.models.packet import CaptureMetadata, NormalizedPacket

SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")


@dataclass(slots=True)
class DetectionFinding:
    """Structured, explainable detection produced by a heuristic or YAML rule."""

    detection_id: str
    detection_name: str
    detector_type: str
    severity: str
    confidence: float
    timestamp: str
    timestamp_epoch: float
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str
    evidence: dict[str, Any]
    explanation: str
    recommended_investigation_steps: list[str]
    candidate_mitre_ids: list[str] = field(default_factory=list)
    rule_id: str | None = None
    observation_type: str = "SUSPICIOUS_INDICATOR"
    flow_id: str | None = None
    packet_indices: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DetectionContext:
    """Immutable analysis bundle passed to independent detectors and rule evaluators."""

    metadata: CaptureMetadata
    packets: list[NormalizedPacket]
    flows: list[NetworkFlow]
