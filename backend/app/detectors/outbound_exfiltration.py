"""Outbound data exfiltration detector based on byte asymmetry, volume, and staging."""

from __future__ import annotations

import hashlib
from collections import defaultdict

from app.detectors.base import BaseDetector
from app.models.detection import DetectionContext, DetectionFinding
from app.models.flow import NetworkFlow
from app.utils.network import is_external_ip


class OutboundExfiltrationDetector(BaseDetector):
    """Identify disproportionate, staged, or sustained outbound data transfers."""

    detector_name = "outbound_exfiltration"

    def detect(self, context: DetectionContext) -> list[DetectionFinding]:
        # Aggregate outbound flows by (initiator_ip, responder_ip)
        pair_flows: dict[tuple[str, str], list[NetworkFlow]] = defaultdict(list)
        for flow in context.flows:
            if flow.direction == "outbound" and is_external_ip(flow.responder_ip):
                pair_flows[(flow.initiator_ip, flow.responder_ip)].append(flow)

        # Also count HTTP POST/PUT uploads toward each destination for corroboration
        http_uploads_by_pair: dict[tuple[str | None, str | None], int] = defaultdict(int)
        for pkt in context.packets:
            if pkt.http and pkt.http.is_request and pkt.http.method in {"POST", "PUT", "PATCH"}:
                http_uploads_by_pair[(pkt.src_ip, pkt.dst_ip)] += 1

        findings: list[DetectionFinding] = []
        for (src_ip, dst_ip), flows in sorted(pair_flows.items()):
            http_up_count = http_uploads_by_pair.get((src_ip, dst_ip), 0)
            finding = self._evaluate_destination(src_ip, dst_ip, flows, http_up_count)
            if finding is not None:
                findings.append(finding)
        return findings

    def _evaluate_destination(
        self,
        src_ip: str,
        dst_ip: str,
        flows: list[NetworkFlow],
        http_upload_count: int,
    ) -> DetectionFinding | None:
        cfg = self.config
        total_out = sum(f.bytes_initiator_to_responder for f in flows)
        total_in = sum(f.bytes_responder_to_initiator for f in flows)
        total_packets = sum(f.total_packets for f in flows)
        ratio = round(total_out / max(total_in, 1), 2)
        total_duration = round(sum(f.duration_seconds for f in flows), 3)
        ports = sorted({f.responder_port for f in flows if f.responder_port is not None})
        protocols = sorted({f.application_protocol for f in flows})

        first_ts = min(f.first_seen for f in flows)
        last_ts = max(f.last_seen for f in flows)
        span_seconds = max(1.0, last_ts - first_ts)
        flows_per_min = round((len(flows) / span_seconds) * 60.0, 2)

        large_volume = total_out >= cfg.exfil_min_outbound_bytes
        min_ratio_bytes = max(10_000, cfg.exfil_min_outbound_bytes // 10)
        high_ratio = ratio >= cfg.exfil_min_ratio and total_out >= min_ratio_bytes
        unusual_ports = [p for p in ports if p not in {80, 443, 53}]
        suspicious_port_hit = [p for p in ports if p in cfg.suspicious_ports]
        repeated = len(flows) >= cfg.exfil_repeated_flow_threshold
        long_session = total_duration >= cfg.exfil_long_session_seconds
        high_frequency = len(flows) >= 3 and flows_per_min >= cfg.exfil_high_frequency_fpm

        # Detect staged small transfers (multiple small/medium asymmetric transfers over time)
        small_out_flows = [
            f for f in flows if f.bytes_initiator_to_responder >= cfg.exfil_staged_min_flow_bytes
        ]
        staged_exfil = (
            len(small_out_flows) >= cfg.exfil_staged_min_flows
            and total_out >= cfg.exfil_staged_min_total_bytes
            and ratio >= cfg.exfil_min_ratio
        )

        # Require meaningful context: never flag a benign single small upload
        if not (
            large_volume
            or staged_exfil
            or (high_ratio and (repeated or unusual_ports or http_upload_count >= 2))
        ):
            return None

        score = 0.25
        indicators: list[str] = []
        if large_volume:
            indicators.append(f"Large outbound byte volume ({total_out:,} bytes)")
            score += 0.22
        if high_ratio:
            indicators.append(f"Asymmetric upload-to-download ratio ({ratio}:1)")
            score += 0.18
        if staged_exfil:
            indicators.append(
                f"Staged small outbound transfers ({len(small_out_flows)} flows totalling "
                f"{total_out:,} B)"
            )
            score += 0.16
        if unusual_ports:
            indicators.append(f"Non-standard external destination port(s): {unusual_ports}")
            score += 0.10
        if suspicious_port_hit:
            indicators.append(f"High-risk destination port(s): {suspicious_port_hit}")
            score += 0.10
        if repeated:
            indicators.append(f"Repeated outbound sessions ({len(flows)} flows)")
            score += 0.08
        if high_frequency:
            indicators.append(f"Elevated outbound transfer frequency ({flows_per_min} flows/min)")
            score += 0.06
        if long_session:
            indicators.append(f"Sustained outbound transfer duration ({total_duration}s)")
            score += 0.06
        if http_upload_count >= 2:
            indicators.append(f"Repeated HTTP upload requests ({http_upload_count} POST/PUT/PATCH)")
            score += 0.08

        confidence = round(min(0.96, score), 2)
        if (
            total_out >= cfg.exfil_min_outbound_bytes * 5
            and high_ratio
            and len(indicators) >= 3
        ):
            severity = "CRITICAL"
        elif (large_volume and high_ratio) or (staged_exfil and len(indicators) >= 3):
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        earliest = min(flows, key=lambda f: f.first_seen)
        snis = sorted({s for f in flows for s in f.observed_tls_snis})
        hosts = sorted({h for f in flows for h in f.observed_http_hosts})
        pkt_indices = sorted({idx for f in flows for idx in f.packet_indices})[:300]
        det_hash = hashlib.sha256(f"exfil:{src_ip}->{dst_ip}".encode()).hexdigest()[:12]

        return DetectionFinding(
            detection_id=f"det-exfil-{det_hash}",
            detection_name="Anomalous Outbound Data Transfer Volume",
            detector_type=self.detector_name,
            severity=severity,
            confidence=confidence,
            timestamp=earliest.first_seen_utc,
            timestamp_epoch=earliest.first_seen,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=earliest.initiator_port,
            destination_port=ports[0] if ports else earliest.responder_port,
            protocol=protocols[0] if len(protocols) == 1 else "MULTI",
            flow_id=earliest.flow_id,
            packet_indices=pkt_indices,
            evidence={
                "outbound_bytes": total_out,
                "inbound_bytes": total_in,
                "outbound_to_inbound_ratio": ratio,
                "packet_count": total_packets,
                "flow_count": len(flows),
                "total_duration_seconds": total_duration,
                "flows_per_minute": flows_per_min,
                "staged_transfer_pattern": staged_exfil,
                "http_upload_count": http_upload_count,
                "destination_ports": ports,
                "protocols": protocols,
                "observed_tls_snis": snis,
                "observed_http_hosts": hosts,
                "triggered_indicators": indicators,
                "flow_ids": [f.flow_id for f in flows[:20]],
                "packet_indices": pkt_indices[:100],
            },
            explanation=(
                f"Observed {total_out:,} bytes outbound vs {total_in:,} bytes inbound "
                f"(ratio {ratio}:1) across {total_packets:,} packets and {len(flows)} flow(s) "
                f"from {src_ip} to external IP {dst_ip} over {total_duration}s. "
                "Note: NAT translations, proxies, or midstream capture boundaries can affect "
                "observed initiator directionality; corroborate with host logs before concluding "
                "unauthorised data exfiltration."
            ),
            recommended_investigation_steps=[
                (
                    f"Check destination IP {dst_ip} reputation, ASN ownership, and observed "
                    f"SNI/Host ({snis or hosts or ['none']})."
                ),
                (
                    f"Verify endpoint {src_ip} for legitimate cloud backup, CI/CD, "
                    "or large file upload tasks."
                ),
                "Correlate with proxy, DLP, or EDR process-network telemetry during this window.",
            ],
            candidate_mitre_ids=(
                ["T1041", "T1048.002"] if "TLS" in protocols else ["T1041", "T1048.003"]
            ),
        )
