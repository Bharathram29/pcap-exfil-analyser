"""Suspicious destination port detector avoiding blind non-standard-port alerts."""

from __future__ import annotations

import hashlib
from collections import defaultdict

from app.detectors.base import BaseDetector
from app.models.detection import DetectionContext, DetectionFinding
from app.models.flow import NetworkFlow
from app.utils.network import is_external_ip


class SuspiciousPortDetector(BaseDetector):
    """Identify connections to configurable high-risk or uncommon external ports."""

    detector_name = "suspicious_ports"

    def detect(self, context: DetectionContext) -> list[DetectionFinding]:
        grouped: dict[tuple[str, str, int], list[NetworkFlow]] = defaultdict(list)
        for flow in context.flows:
            if flow.responder_port is None:
                continue
            if flow.responder_port in self.config.suspicious_ports:
                grouped[(flow.initiator_ip, flow.responder_ip, flow.responder_port)].append(flow)

        findings: list[DetectionFinding] = []
        for (src_ip, dst_ip, dst_port), flows in sorted(grouped.items()):
            findings.append(self._build_finding(src_ip, dst_ip, dst_port, flows))
        return findings

    def _build_finding(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        flows: list[NetworkFlow],
    ) -> DetectionFinding:
        port_label = self.config.suspicious_ports.get(dst_port, "Uncommon Service Port")
        is_ext = is_external_ip(dst_ip)
        total_bytes = sum(f.total_bytes for f in flows)
        total_out = sum(f.bytes_initiator_to_responder for f in flows)

        score = 0.35
        indicators = [f"Traffic targeting configured port {dst_port} ({port_label})"]
        if is_ext:
            score += 0.25
            indicators.append(f"Destination {dst_ip} is external")
        if total_out >= 10_000:
            score += 0.15
            indicators.append(f"Notable outbound volume ({total_out:,} bytes)")
        if len(flows) >= 2:
            score += 0.10
            indicators.append(f"Multiple connections ({len(flows)} flows)")

        confidence = round(min(0.90, score), 2)
        if is_ext and total_out >= 50_000:
            severity = "HIGH"
        elif is_ext:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        earliest = min(flows, key=lambda f: f.first_seen)
        pkt_indices = sorted({idx for f in flows for idx in f.packet_indices})[:200]
        det_hash = hashlib.sha256(f"port:{src_ip}:{dst_ip}:{dst_port}".encode()).hexdigest()[:12]

        return DetectionFinding(
            detection_id=f"det-port-{det_hash}",
            detection_name=f"Connection to Uncommon/High-Risk Port ({dst_port})",
            detector_type=self.detector_name,
            severity=severity,
            confidence=confidence,
            timestamp=earliest.first_seen_utc,
            timestamp_epoch=earliest.first_seen,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=earliest.initiator_port,
            destination_port=dst_port,
            protocol=earliest.application_protocol,
            flow_id=earliest.flow_id,
            packet_indices=pkt_indices,
            evidence={
                "destination_port": dst_port,
                "port_profile": port_label,
                "external_destination": is_ext,
                "flow_count": len(flows),
                "total_bytes": total_bytes,
                "outbound_bytes": total_out,
                "triggered_indicators": indicators,
                "packet_indices": pkt_indices[:100],
            },
            explanation=(
                f"Observed {len(flows)} flow(s) from {src_ip} to {dst_ip}:{dst_port} "
                f"({port_label}). Non-standard ports alone do not prove malicious activity—"
                "custom internal services, development servers, or proxies can legitimately "
                "use these ports."
            ),
            recommended_investigation_steps=[
                f"Verify whether {dst_ip}:{dst_port} is an approved internal or vendor service.",
                f"Inspect running processes and listening/outbound sockets on {src_ip}.",
                "Correlate with firewall rules and DNS queries preceding the connection.",
            ],
            candidate_mitre_ids=["T1041"] if is_ext else [],
        )
