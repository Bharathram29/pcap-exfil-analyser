"""Domain models for validated MITRE ATT&CK Enterprise technique mappings."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class MitreTechniqueDef:
    """Official MITRE ATT&CK Enterprise technique metadata."""

    technique_id: str
    technique_name: str
    tactic: str
    description: str
    reference_url: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class MitreMapping:
    """Justified MITRE ATT&CK mapping linked to specific forensic evidence."""

    technique_id: str
    technique_name: str
    tactic: str
    reason: str
    supporting_evidence: dict[str, Any]
    confidence_level: str
    confidence_score: float
    reference_url: str
    source_detection_ids: list[str] = field(default_factory=list)
    supporting_indicators: list[str] = field(default_factory=list)
    evidence_references: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
