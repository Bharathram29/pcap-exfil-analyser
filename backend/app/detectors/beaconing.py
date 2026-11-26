"""Periodic outbound C2 / beaconing detector accounting for jitter and capture gaps."""

from __future__ import annotations

import hashlib
from collections import defaultdict

import numpy as np

from app.detectors.base import BaseDetector
from app.models.detection import DetectionContext, DetectionFinding
from app.models.flow import NetworkFlow
from app.utils.network import is_external_ip


class BeaconingDetector(BaseDetector):
    """Detect periodic outbound connections using gap-tolerant statistical interval analysis."""

    detector_name = "network_beaconing"

    def detect(self, context: DetectionContext) -> list[DetectionFinding]:
        grouped: dict[tuple[str, str, int | None], list[NetworkFlow]] = defaultdict(list)
        for flow in context.flows:
            if flow.direction == "outbound" and is_external_ip(flow.responder_ip):
                grouped[(flow.initiator_ip, flow.responder_ip, flow.responder_port)].append(flow)

        findings: list[DetectionFinding] = []
        for (src_ip, dst_ip, dst_port), flows in sorted(
            grouped.items(),
            key=lambda item: (item[0][0], item[0][1], item[0][2] or -1),
        ):
            finding = self._evaluate_beacon_series(src_ip, dst_ip, dst_port, flows)
            if finding is not None:
                findings.append(finding)
        return findings

    def _evaluate_beacon_series(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None,
        flows: list[NetworkFlow],
    ) -> DetectionFinding | None:
        cfg = self.config
        if len(flows) < cfg.beacon_min_connections:
            return None

        ordered = sorted(flows, key=lambda f: f.first_seen)
        timestamps = np.array([f.first_seen for f in ordered], dtype=float)
        intervals = np.diff(timestamps)
        if len(intervals) == 0:
            return None

        raw_mean = float(np.mean(intervals))
        if raw_mean < cfg.beacon_min_mean_interval_seconds:
            return None

        raw_std = float(np.std(intervals))
        raw_cv = round(raw_std / raw_mean, 4)

        effective_mean = raw_mean
        effective_std = raw_std
        effective_cv = raw_cv
        missed_gaps = 0

        if raw_cv > cfg.beacon_max_interval_cv:
            if not cfg.beacon_allow_capture_gaps or len(intervals) < 3:
                return None
            # Estimate base period from lower quartile/median of positive intervals
            pos_intervals = np.sort(intervals[intervals > 0])
            if len(pos_intervals) < 3:
                return None
            base_period = float(np.median(pos_intervals[: max(2, len(pos_intervals) // 2 + 1)]))
            if base_period < cfg.beacon_min_mean_interval_seconds:
                return None

            normalized: list[float] = []
            exact_hits = 0
            for dt in intervals:
                mult = max(1, round(float(dt) / base_period))
                if mult > cfg.beacon_max_gap_multiplier:
                    return None
                rel_err = abs(float(dt) - mult * base_period) / (mult * base_period)
                if rel_err > 0.25:
                    return None
                normalized.append(float(dt) / mult)
                if mult == 1:
                    exact_hits += 1
                else:
                    missed_gaps += mult - 1

            # Require majority of intervals to be 1x base_period so random bursts don't match
            if exact_hits / len(intervals) < 0.55:
                return None

            norm_arr = np.array(normalized, dtype=float)
            effective_mean = float(np.mean(norm_arr))
            effective_std = float(np.std(norm_arr))
            effective_cv = round(effective_std / effective_mean, 4) if effective_mean > 0 else 1.0
            if effective_cv > cfg.beacon_max_interval_cv:
                return None

        out_bytes = np.array([f.bytes_initiator_to_responder for f in ordered], dtype=float)
        mean_bytes = float(np.mean(out_bytes))
        byte_cv = round(float(np.std(out_bytes) / mean_bytes), 4) if mean_bytes > 0 else 0.0

        durations = np.array([f.duration_seconds for f in ordered], dtype=float)
        mean_dur = round(float(np.mean(durations)), 3)
        std_dur = round(float(np.std(durations)), 3)

        low_volume = mean_bytes <= 4096.0
        consistent_size = byte_cv <= cfg.beacon_max_byte_cv
        unusual_port = dst_port is not None and dst_port not in {80, 443, 53}
        syn_only_count = sum(1 for f in ordered if f.connection_state == "SYN_ONLY_UNANSWERED")

        score = 0.45
        indicators = [
            f"Periodic interval regularity (mean={effective_mean:.2f}s, "
            f"std={effective_std:.2f}s, CV={effective_cv})"
        ]
        if len(ordered) >= cfg.beacon_min_connections + 2:
            score += 0.12
            indicators.append(f"Repeated outbound sessions ({len(ordered)} connections)")
        if consistent_size:
            score += 0.15
            indicators.append(f"Consistent outbound payload sizing (byte CV={byte_cv})")
        if low_volume:
            score += 0.10
            indicators.append(f"Low-volume heartbeat pattern (mean={mean_bytes:.1f} B/flow)")
        if unusual_port:
            score += 0.12
            indicators.append(f"Non-standard destination port {dst_port}")

        # Account for capture gaps / unanswered SYN-only probes before assigning high confidence
        if missed_gaps > 0:
            gap_penalty = min(0.22, missed_gaps * 0.06)
            score -= gap_penalty
            indicators.append(
                f"Possible capture gap / missed intervals detected (~{missed_gaps} missed beat(s); "
                "confidence reduced)"
            )
        if syn_only_count == len(ordered):
            score -= 0.10
            indicators.append("All connections unanswered SYN-only (retry loop or blocked C2)")

        confidence = round(max(0.35, min(0.95, score)), 2)
        if confidence >= 0.78 and missed_gaps == 0:
            severity = "HIGH"
        elif confidence >= 0.52:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        earliest = ordered[0]
        protocols = sorted({f.application_protocol for f in ordered})
        snis = sorted({s for f in ordered for s in f.observed_tls_snis})
        pkt_indices = sorted({idx for f in ordered for idx in f.packet_indices})[:300]
        det_hash = hashlib.sha256(
            f"beacon:{src_ip}:{dst_ip}:{dst_port}".encode()
        ).hexdigest()[:12]

        return DetectionFinding(
            detection_id=f"det-beacon-{det_hash}",
            detection_name="Periodic Outbound Beaconing Pattern",
            detector_type=self.detector_name,
            severity=severity,
            confidence=confidence,
            timestamp=earliest.first_seen_utc,
            timestamp_epoch=earliest.first_seen,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=earliest.initiator_port,
            destination_port=dst_port,
            protocol=protocols[0] if len(protocols) == 1 else "TCP",
            flow_id=earliest.flow_id,
            packet_indices=pkt_indices,
            evidence={
                "connection_count": len(ordered),
                "mean_interval_seconds": round(effective_mean, 3),
                "std_interval_seconds": round(effective_std, 3),
                "interval_cv": effective_cv,
                "raw_interval_cv": raw_cv,
                "missed_beacon_gaps": missed_gaps,
                "mean_duration_seconds": mean_dur,
                "std_duration_seconds": std_dur,
                "mean_outbound_bytes": round(mean_bytes, 2),
                "byte_cv": byte_cv,
                "observed_tls_snis": snis,
                "supporting_timestamps": [f.first_seen_utc for f in ordered[:25]],
                "intervals_seconds": [round(float(x), 3) for x in intervals[:25]],
                "flow_ids": [f.flow_id for f in ordered[:25]],
                "packet_indices": pkt_indices[:100],
                "triggered_indicators": indicators,
            },
            explanation=(
                f"Detected {len(ordered)} periodic outbound connections from {src_ip} to "
                f"{dst_ip}:{dst_port} with estimated interval {effective_mean:.2f}s "
                f"(std={effective_std:.2f}s, CV={effective_cv}, missed_gaps={missed_gaps}). "
                "Regular check-in cadence can indicate automated C2 beaconing, though scheduled "
                "health checks, NTP/telemetry polling, or SaaS keepalives can look similar."
            ),
            recommended_investigation_steps=[
                (
                    f"Identify the process on {src_ip} initiating periodic connections "
                    f"to {dst_ip}:{dst_port}."
                ),
                "Compare timing against known cron jobs, software updaters, or monitoring agents.",
                "Inspect observed SNI/HTTP headers or destination threat intelligence reputation.",
            ],
            candidate_mitre_ids=["T1041"],
        )
