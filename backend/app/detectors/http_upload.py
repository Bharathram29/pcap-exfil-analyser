"""Suspicious HTTP upload and request behaviour detector."""

from __future__ import annotations

import hashlib
import ipaddress
from collections import defaultdict

from app.detectors.base import BaseDetector
from app.models.detection import DetectionContext, DetectionFinding
from app.models.packet import NormalizedPacket


def _is_raw_ip_host(host_header: str | None) -> bool:
    if not host_header:
        return False
    host_only = host_header.split(":", 1)[0].strip("[]")
    try:
        ipaddress.ip_address(host_only)
        return True
    except ValueError:
        return False


class HttpUploadDetector(BaseDetector):
    """Detect suspicious HTTP uploads, raw-IP requests, UAs, and non-standard ports."""

    detector_name = "http_upload"

    def detect(self, context: DetectionContext) -> list[DetectionFinding]:
        req_grouped: dict[tuple[str | None, str | None, int | None], list[NormalizedPacket]] = (
            defaultdict(list)
        )
        resp_bytes_by_pair: dict[tuple[str | None, str | None], int] = defaultdict(int)

        for pkt in context.packets:
            if pkt.http is None:
                continue
            if pkt.http.is_request:
                req_grouped[(pkt.src_ip, pkt.dst_ip, pkt.dst_port)].append(pkt)
            else:
                resp_bytes = max(pkt.http.payload_size, pkt.http.content_length or 0)
                resp_bytes_by_pair[(pkt.dst_ip, pkt.src_ip)] += resp_bytes

        findings: list[DetectionFinding] = []
        for (src_ip, dst_ip, dst_port), pkts in sorted(req_grouped.items()):
            resp_bytes = resp_bytes_by_pair.get((src_ip, dst_ip), 0)
            finding = self._evaluate_http_target(src_ip, dst_ip, dst_port, pkts, resp_bytes)
            if finding is not None:
                findings.append(finding)
        return findings

    def _evaluate_http_target(
        self,
        src_ip: str | None,
        dst_ip: str | None,
        dst_port: int | None,
        pkts: list[NormalizedPacket],
        total_response_bytes: int,
    ) -> DetectionFinding | None:
        cfg = self.config
        ordered = sorted(pkts, key=lambda p: p.timestamp)
        upload_pkts = [
            p for p in ordered if p.http and p.http.method in {"POST", "PUT", "PATCH"}
        ]
        raw_ip_hosts = [
            p.http.host for p in ordered if p.http and _is_raw_ip_host(p.http.host)
        ]
        user_agents = sorted({p.http.user_agent for p in ordered if p.http and p.http.user_agent})
        suspicious_uas = [
            ua
            for ua in user_agents
            if any(pat in ua.lower() for pat in cfg.http_suspicious_user_agents)
        ]
        content_types = sorted(
            {p.http.content_type for p in ordered if p.http and p.http.content_type}
        )
        binary_cts = [
            ct
            for ct in content_types
            if any(pat in ct.lower() for pat in cfg.http_suspicious_content_types)
        ]

        unusual_port = dst_port is not None and dst_port not in cfg.http_standard_ports
        methods = sorted({p.http.method for p in ordered if p.http and p.http.method})
        has_put = "PUT" in methods
        has_unusual_method = any(m in {"DELETE", "TRACE", "CONNECT"} for m in methods)

        span = (
            max(1.0, ordered[-1].timestamp - ordered[0].timestamp)
            if len(ordered) > 1
            else 1.0
        )
        req_per_min = round((len(ordered) / span) * 60.0, 2)
        high_freq = len(ordered) >= 5 and req_per_min >= cfg.http_high_frequency_rpm

        # Gate benign GET browsing from triggering unless anomalous markers exist
        if not upload_pkts and not raw_ip_hosts and not has_unusual_method and not (
            suspicious_uas and unusual_port
        ) and not high_freq:
            return None

        max_payload = max(
            (
                max(p.http.payload_size, p.http.content_length or 0)
                for p in ordered
                if p.http
            ),
            default=0,
        )
        total_upload_bytes = sum(
            max(p.http.payload_size, p.http.content_length or 0)
            for p in upload_pkts
            if p.http
        )
        incomplete_payloads = sum(
            1 for p in ordered if p.http and p.http.payload_incomplete
        )

        indicators: list[str] = []
        score = 0.0

        if (
            max_payload >= cfg.http_large_payload_bytes
            or total_upload_bytes >= cfg.http_large_payload_bytes
        ):
            indicators.append(
                f"Large HTTP upload body (max={max_payload:,} B, total={total_upload_bytes:,} B)"
            )
            score += 0.34
        if has_put:
            indicators.append("HTTP PUT upload method observed")
            score += 0.16
        if has_unusual_method:
            indicators.append(f"Uncommon HTTP method(s): {methods}")
            score += 0.15
        if raw_ip_hosts:
            indicators.append(f"HTTP request directed to raw IP Host header ({raw_ip_hosts[0]})")
            score += 0.22
        if unusual_port:
            indicators.append(f"HTTP traffic over non-standard port {dst_port}")
            score += 0.15
        if len(upload_pkts) >= cfg.http_repeated_upload_count:
            indicators.append(f"Repeated HTTP upload attempts ({len(upload_pkts)} requests)")
            score += 0.16
        if suspicious_uas:
            indicators.append(f"Automated/suspicious User-Agent observed: {suspicious_uas[0]}")
            score += 0.12
        if binary_cts and upload_pkts:
            indicators.append(f"Binary/archive upload Content-Type: {binary_cts[0]}")
            score += 0.10
        if high_freq:
            indicators.append(
                f"High HTTP request frequency ({len(ordered)} reqs, ~{req_per_min}/min)"
            )
            score += 0.10

        if not indicators:
            return None

        confidence = round(min(0.96, score), 2)
        if max_payload >= cfg.http_large_payload_bytes * 5 or (confidence >= 0.70 and raw_ip_hosts):
            severity = "CRITICAL"
        elif max_payload >= cfg.http_large_payload_bytes or confidence >= 0.50:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        first_pkt = ordered[0]
        pkt_indices = [p.packet_index for p in ordered[:300]]
        sample_requests = [
            {
                "packet_index": p.packet_index,
                "timestamp": p.timestamp_utc,
                "method": p.http.method,
                "host": p.http.host,
                "uri": p.http.uri,
                "user_agent": p.http.user_agent,
                "content_type": p.http.content_type,
                "content_length": p.http.content_length,
                "observed_payload_size": p.http.payload_size,
                "payload_incomplete": p.http.payload_incomplete,
                "direction": p.http.direction,
            }
            for p in ordered[:8]
            if p.http
        ]
        det_hash = hashlib.sha256(
            f"http_up:{src_ip}:{dst_ip}:{dst_port}".encode()
        ).hexdigest()[:12]

        incomplete_note = (
            f" Note: {incomplete_payloads} request(s) had declared Content-Length exceeding "
            "the initial TCP segment payload captured in the request packet."
            if incomplete_payloads > 0
            else ""
        )

        return DetectionFinding(
            detection_id=f"det-http-{det_hash}",
            detection_name="Suspicious HTTP Upload / Request Behaviour",
            detector_type=self.detector_name,
            severity=severity,
            confidence=confidence,
            timestamp=first_pkt.timestamp_utc,
            timestamp_epoch=first_pkt.timestamp,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=first_pkt.src_port,
            destination_port=dst_port,
            protocol="HTTP",
            packet_indices=pkt_indices,
            evidence={
                "methods": methods,
                "total_requests": len(ordered),
                "upload_request_count": len(upload_pkts),
                "max_payload_bytes": max_payload,
                "total_upload_bytes": total_upload_bytes,
                "total_response_bytes": total_response_bytes,
                "requests_per_minute": req_per_min,
                "destination_port": dst_port,
                "user_agents": user_agents,
                "content_types": content_types,
                "payload_incomplete_count": incomplete_payloads,
                "triggered_indicators": indicators,
                "sample_requests": sample_requests,
                "packet_indices": pkt_indices[:100],
            },
            explanation=(
                f"Detected {len(ordered)} HTTP request(s) from {src_ip} to {dst_ip}:{dst_port} "
                "exhibiting: " + "; ".join(indicators) + f".{incomplete_note} Raw body bytes are "
                "not dumped in evidence, and encrypted HTTPS traffic is not decrypted."
            ),
            recommended_investigation_steps=[
                f"Review HTTP Host, URI, Content-Type, and User-Agent headers to {dst_ip}.",
                f"Identify the initiating process on {src_ip} via endpoint logs.",
                (
                    "Verify whether the destination endpoint is an approved web service "
                    "or file-sharing target."
                ),
            ],
            candidate_mitre_ids=["T1567", "T1041"],
        )
