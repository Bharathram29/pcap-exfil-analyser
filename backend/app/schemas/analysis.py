"""Pydantic v2 schemas for PCAP upload, analysis orchestration, and investigation APIs."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class PcapUploadResponse(BaseModel):
    analysis_id: str
    filename: str
    file_size_bytes: int
    sha256: str
    capture_format: str
    link_layer_type: int | None
    link_layer_name: str | None
    supported_link_layer: bool
    warnings: list[str] = Field(default_factory=list)
    status: str
    ingested_at_utc: str


class AnalysisStartRequest(BaseModel):
    analysis_id: str = Field(min_length=1, max_length=128)
    run_async: bool = False


class AnalysisStartResponse(BaseModel):
    analysis_id: str
    status: str
    processing_duration_ms: float | None = None
    message: str


class AlertStatusUpdateRequest(BaseModel):
    status: Literal[
        "New",
        "Investigating",
        "Confirmed Suspicious",
        "False Positive",
        "Closed",
    ]


class AlertStatusUpdateResponse(BaseModel):
    analysis_id: str
    alert_id: str
    status: str
    updated: bool


class IncidentStatusUpdateRequest(BaseModel):
    status: Literal[
        "Open",
        "Investigating",
        "Resolved",
        "Closed",
    ]


class IncidentStatusUpdateResponse(BaseModel):
    analysis_id: str
    incident_id: str
    status: str
    updated: bool


class InvestigationListItem(BaseModel):
    analysis_id: str
    filename: str
    file_size_bytes: int
    sha256: str
    status: str
    created_at: str
    completed_at: str | None = None
    processing_duration_ms: float | None = None
    summary: dict[str, Any] | None = None
    error_message: str | None = None
