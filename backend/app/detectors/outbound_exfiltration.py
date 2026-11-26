"""Outbound data exfiltration detector with time-window, burst, periodicity, and baseline checks."""

from __future__ import annotations

import hashlib
import math
import statistics
from collections import defaultdict

from app.detectors.base import BaseDetector
from app.models.detection import DetectionContext, DetectionFinding
from app.models.flow import NetworkFlow
from app.utils.network import is_external_ip


class OutboundExfiltrationDetector(BaseDetector):
    """Identify disproportionate, staged, bursty, or baseline-anomalous outbound transfers."""

    detector_name = "outbound_exfiltration"

    def detect(self, context: DetectionContext) -> list[DetectionFinding]:
        # Aggregate outbound flows by (initiator_ip, responder_ip) and track per-host peer totals
        pair_flows: dict[tuple[str, str], list[NetworkFlow]] = defaultdict(list)
        host_peer_totals: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for flow in context.flows:
            if flow.direction == "outbound" and is_external_ip(flow.responder_ip):
                pair_flows[(flow.initiator_ip, flow.responder_ip)].append(flow)
                host_peer_totals[flow.initiator_ip][flow.responder_ip] += (
                    flow.bytes_initiator_to_responder
                )

        # Distinguish HTTP request frequency and HTTP body size from transferred flow bytes
        http_uploads_by_pair: dict[tuple[str | None, str | None], int] = defaultdict(int)
        http_declared_by_pair: dict[tuple[str | None, str | None], int] = defaultdict(int)
        for pkt in context.packets:
            if pkt.http and pkt.http.is_request and pkt.http.method in {"POST", "PUT", "PATCH"}:
                http_uploads_by_pair[(pkt.src_ip, pkt.dst_ip)] += 1
                http_declared_by_pair[(pkt.src_ip, pkt.dst_ip)] += max(
                    pkt.http.payload_size, pkt.http.content_length or 0
                )

        findings: list[DetectionFinding] = []
        for (src_ip, dst_ip), flows in sorted(pair_flows.items()):
            peer_map = host_peer_totals.get(src_ip, {})
            other_peers = [v for k, v in peer_map.items() if k != dst_ip]
            host_baseline_median = (
                float(statistics.median(other_peers)) if len(other_peers) >= 2 else None
            )
            finding = self._evaluate_destination(
                src_ip=src_ip,
                dst_ip=dst_ip,
                flows=flows,
                http_upload_count=http_uploads_by_pair.get((src_ip, dst_ip), 0),
                http_declared_bytes=http_declared_by_pair.get((src_ip, dst_ip), 0),
                host_baseline_median=host_baseline_median,
            )
            if finding is not None:
                findings.append(finding)
        return findings

    def _evaluate_destination(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        flows: list[NetworkFlow],
        http_upload_count: int,
        http_declared_bytes: int,
        host_baseline_median: float | None,
    ) -> DetectionFinding | None:
        cfg = self.config
        ordered = sorted(flows, key=lambda f: f.first_seen)
        total_out = sum(f.bytes_initiator_to_responder for f in ordered)
        total_in = sum(f.bytes_responder_to_initiator for f in ordered)
        total_packets = sum(f.total_packets for f in ordered)
        ratio = round(total_out / max(total_in, 1), 2)
        total_duration = round(sum(f.duration_seconds for f in ordered), 3)
        ports = sorted({f.responder_port for f in ordered if f.responder_port is not None})
        protocols = sorted({f.application_protocol for f in ordered})

        first_ts = ordered[0].first_seen
        last_ts = max(f.last_seen for f in ordered)
        span_seconds = max(1.0, last_ts - first_ts)
        flows_per_min = round((len(ordered) / span_seconds) * 60.0, 2)

        # Sliding 60-second time-window burst volume
        max_60s_bytes = 0
        for i, f_start in enumerate(ordered):
            win_sum = 0
            for f_cur in ordered[i:]:
                if f_cur.first_seen - f_start.first_seen <= 60.0:
                    win_sum += f_cur.bytes_initiator_to_responder
                else:
                    break
            max_60s_bytes = max(max_60s_bytes, win_sum)

        peak_bps = round(
            max(
                (f.bytes_initiator_to_responder / max(f.duration_seconds, 0.25) for f in ordered),
                default=0.0,
            ),
            2,
        )

        # Periodic data transfer check
        periodic_transfer = False
        if len(ordered) >= 4:
            intervals = [
                ordered[i + 1].first_seen - ordered[i].first_seen for i in range(len(ordered) - 1)
            ]
            mean_dt = sum(intervals) / len(intervals)
            if mean_dt >= 1.0:
                std_dt = math.sqrt(sum((x - mean_dt) ** 2 for x in intervals) / len(intervals))
                if (std_dt / mean_dt) <= 0.30 and total_out >= 10_000:
                    periodic_transfer = True

        # Host baseline comparison when sufficient historical peers exist
        baseline_anomaly = bool(
            host_baseline_median is not None
            and total_out >= max(50_000, host_baseline_median * 4.0)
        )

        large_volume = total_out >= cfg.exfil_min_outbound_bytes
        min_ratio_bytes = max(10_000, cfg.exfil_min_outbound_bytes // 10)
        high_ratio = ratio >= cfg.exfil_min_ratio and total_out >= min_ratio_bytes
        unusual_ports = [p for p in ports if p not in {80, 443, 53}]
        suspicious_port_hit = [p for p in ports if p in cfg.suspicious_ports]
        repeated = len(ordered) >= cfg.exfil_repeated_flow_threshold
        long_session = total_duration >= cfg.exfil_long_session_seconds
        high_frequency = len(ordered) >= 3 and flows_per_min >= cfg.exfil_high_frequency_fpm
        burst_detected = max_60s_bytes >= cfg.exfil_min_outbound_bytes

        small_out_flows = [
            f for f in ordered if f.bytes_initiator_to_responder >= cfg.exfil_staged_min_flow_bytes
        ]
        staged_exfil = (
            len(small_out_flows) >= cfg.exfil_staged_min_flows
            and total_out >= cfg.exfil_staged_min_total_bytes
            and ratio >= cfg.exfil_min_ratio
        )

        if not (
            large_volume
            or staged_exfil
            or (
                high_ratio
                and (repeated or unusual_ports or http_upload_count >= 2 or periodic_transfer)
            )
        ):
            return None

        score = 0.25
        indicators: list[str] = []
        if large_volume:
            indicators.append(f"Large outbound flow byte volume ({total_out:,} B transferred)")
            score += 0.22
        if high_ratio:
            indicators.append(f"Asymmetric upload-to-download ratio ({ratio}:1)")
            score += 0.18
        if burst_detected:
            indicators.append(f"60s time-window transfer burst ({max_60s_bytes:,} B)")
            score += 0.08
        if staged_exfil:
            indicators.append(
                f"Staged small outbound transfers ({len(small_out_flows)} flows totalling "
                f"{total_out:,} B)"
            )
            score += 0.15
        if periodic_transfer:
            indicators.append(
                f"Periodic outbound data-transfer cadence across {len(ordered)} flows"
            )
            score += 0.10
        if baseline_anomaly and host_baseline_median is not None:
            indicators.append(
                f"Upload exceeds host peer baseline ({total_out:,} B vs median "
                f"{host_baseline_median:,.0f} B)"
            )
            score += 0.10
        if unusual_ports:
            indicators.append(f"Non-standard external destination port(s): {unusual_ports}")
            score += 0.08
        if suspicious_port_hit:
            indicators.append(f"High-risk destination port(s): {suspicious_port_hit}")
            score += 0.08
        if repeated:
            indicators.append(f"Repeated outbound sessions ({len(ordered)} flows)")
            score += 0.06
        if high_frequency:
            indicators.append(f"Elevated outbound transfer frequency ({flows_per_min} flows/min)")
            score += 0.05
        if long_session:
            indicators.append(f"Sustained outbound transfer duration ({total_duration}s)")
            score += 0.05
        if http_upload_count >= 2:
            indicators.append(
                f"Repeated HTTP upload requests ({http_upload_count} reqs, "
                f"declared body={http_declared_bytes:,} B)"
            )
            score += 0.07

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

        earliest = ordered[0]
        snis = sorted({s for f in ordered for s in f.observed_tls_snis})
        hosts = sorted({h for f in ordered for h in f.observed_http_hosts})
        pkt_indices = sorted({idx for f in ordered for idx in f.packet_indices})[:300]
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
                "flow_count": len(ordered),
                "total_duration_seconds": total_duration,
                "flows_per_minute": flows_per_min,
                "max_60s_window_bytes": max_60s_bytes,
                "peak_bytes_per_second": peak_bps,
                "periodic_transfer_detected": periodic_transfer,
                "staged_transfer_pattern": staged_exfil,
                "host_baseline_median_bytes": host_baseline_median,
                "baseline_anomaly": baseline_anomaly,
                "http_upload_count": http_upload_count,
                "http_declared_body_bytes": http_declared_bytes,
                "destination_ports": ports,
                "protocols": protocols,
                "observed_tls_snis": snis,
                "observed_http_hosts": hosts,
                "triggered_indicators": indicators,
                "flow_ids": [f.flow_id for f in ordered[:20]],
                "packet_indices": pkt_indices[:100],
            },
            explanation=(
                f"Observed {total_out:,} flow bytes transferred outbound vs {total_in:,} bytes "
                f"inbound (ratio {ratio}:1) across {total_packets:,} packets and {len(ordered)} "
                f"flow(s) from {src_ip} to external IP {dst_ip} over {total_duration}s "
                f"(HTTP upload requests={http_upload_count}, declared HTTP body="
                f"{http_declared_bytes:,} B). Note: NAT, proxies, or midstream capture "
                "boundaries can affect directionality; these indicators do not confirm "
                "unauthorised data theft without host corroboration."
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
