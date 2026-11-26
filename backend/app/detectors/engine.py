"""Coordinator executing independent heuristic detectors across an analysis context."""

from __future__ import annotations

from app.detectors.base import BaseDetector, DetectorConfig
from app.detectors.beaconing import BeaconingDetector
from app.detectors.dns_tunnelling import DnsTunnellingDetector
from app.detectors.http_upload import HttpUploadDetector
from app.detectors.outbound_exfiltration import OutboundExfiltrationDetector
from app.detectors.protocol_anomaly import ProtocolAnomalyDetector
from app.detectors.suspicious_ports import SuspiciousPortDetector
from app.models.detection import DetectionContext, DetectionFinding


class DetectionEngine:
    """Run all configured statistical and behavioral detectors independently."""

    def __init__(
        self,
        config: DetectorConfig | None = None,
        extra_detectors: list[BaseDetector] | None = None,
    ) -> None:
        self.config = config or DetectorConfig()
        self.detectors: list[BaseDetector] = [
            DnsTunnellingDetector(self.config),
            OutboundExfiltrationDetector(self.config),
            HttpUploadDetector(self.config),
            BeaconingDetector(self.config),
            SuspiciousPortDetector(self.config),
            ProtocolAnomalyDetector(self.config),
        ]
        if extra_detectors:
            self.detectors.extend(extra_detectors)

    def run(self, context: DetectionContext) -> list[DetectionFinding]:
        """Execute all registered detectors and return chronologically sorted findings."""
        findings: list[DetectionFinding] = []
        for detector in self.detectors:
            findings.extend(detector.detect(context))
        findings.sort(key=lambda f: (f.timestamp_epoch, f.detection_id))
        return findings
