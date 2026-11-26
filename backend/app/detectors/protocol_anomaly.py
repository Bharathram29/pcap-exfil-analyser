"""Unusual protocol behaviour detector (ports, ICMP, DNS, TCP, TLS, ARP, IPv6)."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import UTC, datetime

from app.detectors.base import BaseDetector
from app.models.detection import DetectionContext, DetectionFinding
from app.models.flow import NetworkFlow
from app.models.packet import NormalizedPacket
from app.utils.network import is_external_ip


class ProtocolAnomalyDetector(BaseDetector):
    """Detect protocol/port mismatches and abnormal TCP/UDP/DNS/TLS/ICMP/ARP behaviour."""

    detector_name = "protocol_anomaly"

    def detect(self, context: DetectionContext) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        findings.extend(self._detect_protocol_port_mismatches(context.flows))
        findings.extend(self._detect_unusual_icmp(context.packets))
        findings.extend(self._detect_abnormal_dns(context.packets))
        findings.extend(self._detect_tls_anomalies(context.packets))
        findings.extend(self._detect_arp_anomalies(context.packets))
        findings.extend(self._detect_tcp_anomalies(context.flows))
        return findings

    def _detect_protocol_port_mismatches(
        self, flows: list[NetworkFlow]
    ) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        for flow in flows:
            port = flow.responder_port
            app = flow.application_protocol
            mismatch_reason: str | None = None

            if app == "HTTP" and port == 443:
                mismatch_reason = "Cleartext HTTP observed on standard TLS port 443"
            elif app == "DNS" and port not in (None, 53, 5353, 853):
                mismatch_reason = f"DNS protocol observed on non-standard port {port}"
            elif app == "TLS" and port == 80:
                mismatch_reason = "TLS handshake observed on standard cleartext HTTP port 80"
            elif (
                flow.transport_protocol == "UDP"
                and port in {22, 80, 443}
                and app not in {"DNS", "TLS"}
                and flow.direction == "outbound"
                and flow.total_packets >= 10
            ):
                mismatch_reason = (
                    f"High-volume UDP exchange observed on TCP-oriented port {port} "
                    "(possible QUIC or UDP tunnel)"
                )

            if not mismatch_reason:
                continue

            det_hash = hashlib.sha256(f"mismatch:{flow.flow_id}".encode()).hexdigest()[:12]
            findings.append(
                DetectionFinding(
                    detection_id=f"det-proto-{det_hash}",
                    detection_name="Unexpected Protocol/Port Combination",
                    detector_type=self.detector_name,
                    severity="MEDIUM",
                    confidence=0.72,
                    timestamp=flow.first_seen_utc,
                    timestamp_epoch=flow.first_seen,
                    source_ip=flow.initiator_ip,
                    destination_ip=flow.responder_ip,
                    source_port=flow.initiator_port,
                    destination_port=port,
                    protocol=app,
                    flow_id=flow.flow_id,
                    packet_indices=list(flow.packet_indices[:100]),
                    evidence={
                        "application_protocol": app,
                        "transport_protocol": flow.transport_protocol,
                        "destination_port": port,
                        "mismatch_reason": mismatch_reason,
                        "total_bytes": flow.total_bytes,
                        "packet_count": flow.total_packets,
                        "packet_indices": list(flow.packet_indices[:100]),
                    },
                    explanation=(
                        f"{mismatch_reason} between {flow.initiator_ip} and "
                        f"{flow.responder_ip}:{port}. Protocol/port mismatches may indicate "
                        "port-hopping evasion or misconfigured services."
                    ),
                    recommended_investigation_steps=[
                        f"Verify service configuration on {flow.responder_ip}:{port}.",
                        (
                            "Inspect packet headers to rule out benign port forwarding, "
                            "QUIC, or proxy tunnels."
                        ),
                    ],
                    candidate_mitre_ids=["T1048.003"] if app != "TLS" else ["T1048.002"],
                )
            )
        return findings

    def _detect_unusual_icmp(self, packets: list[NormalizedPacket]) -> list[DetectionFinding]:
        grouped: dict[tuple[str | None, str | None], list[NormalizedPacket]] = defaultdict(list)
        for pkt in packets:
            if pkt.protocol == "ICMP" and is_external_ip(pkt.dst_ip):
                grouped[(pkt.src_ip, pkt.dst_ip)].append(pkt)

        findings: list[DetectionFinding] = []
        cfg = self.config
        for (src_ip, dst_ip), pkts in sorted(grouped.items()):
            max_len = max(p.length for p in pkts)
            if max_len < cfg.icmp_large_payload_bytes and len(pkts) < cfg.icmp_high_packet_count:
                continue

            earliest = min(pkts, key=lambda p: p.timestamp)
            pkt_indices = [p.packet_index for p in pkts[:200]]
            det_hash = hashlib.sha256(f"icmp:{src_ip}:{dst_ip}".encode()).hexdigest()[:12]
            findings.append(
                DetectionFinding(
                    detection_id=f"det-icmp-{det_hash}",
                    detection_name="Unusual External ICMP Payload / Volume",
                    detector_type=self.detector_name,
                    severity="HIGH" if max_len >= cfg.icmp_large_payload_bytes * 2 else "MEDIUM",
                    confidence=0.68,
                    timestamp=earliest.timestamp_utc,
                    timestamp_epoch=earliest.timestamp,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=None,
                    destination_port=None,
                    protocol="ICMP",
                    packet_indices=pkt_indices,
                    evidence={
                        "icmp_packet_count": len(pkts),
                        "max_packet_length": max_len,
                        "total_bytes": sum(p.length for p in pkts),
                        "packet_indices": pkt_indices[:100],
                    },
                    explanation=(
                        f"Observed {len(pkts)} external ICMP packet(s) from {src_ip} to {dst_ip} "
                        f"(max length {max_len} bytes). Oversized or high-volume ICMP can indicate "
                        "ICMP tunnelling, though network diagnostics (e.g. MTU discovery) can also "
                        "generate large ICMP packets."
                    ),
                    recommended_investigation_steps=[
                        f"Check whether diagnostic ping/traceroute jobs ran on {src_ip}.",
                        "Inspect ICMP echo payloads for non-standard/encoded patterns.",
                    ],
                    candidate_mitre_ids=["T1048.003"],
                )
            )
        return findings

    def _detect_abnormal_dns(self, packets: list[NormalizedPacket]) -> list[DetectionFinding]:
        responses_by_client: dict[str | None, list[NormalizedPacket]] = defaultdict(list)
        for pkt in packets:
            if pkt.dns is not None and pkt.dns.is_response:
                responses_by_client[pkt.dst_ip].append(pkt)

        findings: list[DetectionFinding] = []
        cfg = self.config
        for client_ip, resp_pkts in sorted(responses_by_client.items()):
            nxdomain = [
                p for p in resp_pkts if p.dns and p.dns.response_code == "NXDOMAIN"
            ]
            total = len(resp_pkts)
            ratio = round(len(nxdomain) / total, 2) if total else 0.0
            if len(nxdomain) >= cfg.dns_nxdomain_min_count and ratio >= cfg.dns_nxdomain_min_ratio:
                earliest = min(nxdomain, key=lambda p: p.timestamp)
                pkt_indices = [p.packet_index for p in nxdomain[:200]]
                det_hash = hashlib.sha256(f"nxdomain:{client_ip}".encode()).hexdigest()[:12]
                findings.append(
                    DetectionFinding(
                        detection_id=f"det-dnsanom-{det_hash}",
                        detection_name="High DNS NXDOMAIN Failure Ratio",
                        detector_type=self.detector_name,
                        severity="MEDIUM",
                        confidence=0.65,
                        timestamp=earliest.timestamp_utc,
                        timestamp_epoch=earliest.timestamp,
                        source_ip=client_ip,
                        destination_ip=earliest.src_ip,
                        source_port=None,
                        destination_port=53,
                        protocol="DNS",
                        packet_indices=pkt_indices,
                        evidence={
                            "nxdomain_count": len(nxdomain),
                            "total_dns_responses": total,
                            "nxdomain_ratio": ratio,
                            "sample_domains": sorted(
                                {p.dns.query_name for p in nxdomain if p.dns and p.dns.query_name}
                            )[:5],
                            "packet_indices": pkt_indices[:100],
                        },
                        explanation=(
                            f"Host {client_ip} received {len(nxdomain)} NXDOMAIN responses out of "
                            f"{total} DNS replies ({ratio:.0%}). Elevated NXDOMAIN rates can arise "
                            "from DGA activity, failed DNS tunnelling, or stale local search lists."
                        ),
                        recommended_investigation_steps=[
                            "Inspect the failing domain names for algorithmic/DGA patterns.",
                            (
                                f"Verify DNS resolver configuration and local applications "
                                f"on {client_ip}."
                            ),
                        ],
                        candidate_mitre_ids=["T1071.004"],
                    )
                )
        return findings

    def _detect_tls_anomalies(self, packets: list[NormalizedPacket]) -> list[DetectionFinding]:
        PairKey = tuple[str | None, str | None, int | None]
        deprecated_by_pair: dict[PairKey, list[NormalizedPacket]] = defaultdict(list)
        expired_certs: dict[PairKey, list[NormalizedPacket]] = defaultdict(list)
        now = datetime.now(UTC)

        for pkt in packets:
            if pkt.tls is None:
                continue
            ver = pkt.tls.handshake_version or pkt.tls.record_version
            if (
                pkt.tls.handshake_type == "ClientHello"
                and ver in {"SSLv3", "TLSv1.0", "TLSv1.1"}
                and is_external_ip(pkt.dst_ip)
            ):
                deprecated_by_pair[(pkt.src_ip, pkt.dst_ip, pkt.dst_port)].append(pkt)
            if pkt.tls.certificate_not_after:
                try:
                    exp = datetime.fromisoformat(pkt.tls.certificate_not_after)
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=UTC)
                    if exp < now:
                        expired_certs[(pkt.src_ip, pkt.dst_ip, pkt.dst_port)].append(pkt)
                except ValueError:
                    pass

        findings: list[DetectionFinding] = []
        for (src_ip, dst_ip, dst_port), pkts in sorted(deprecated_by_pair.items()):
            earliest = min(pkts, key=lambda p: p.timestamp)
            pkt_indices = [p.packet_index for p in pkts[:100]]
            versions = sorted(
                {
                    p.tls.handshake_version or p.tls.record_version or ""
                    for p in pkts
                    if p.tls
                }
            )
            det_hash = hashlib.sha256(
                f"tlsold:{src_ip}:{dst_ip}:{dst_port}".encode()
            ).hexdigest()[:12]
            findings.append(
                DetectionFinding(
                    detection_id=f"det-tlsver-{det_hash}",
                    detection_name="Deprecated TLS/SSL Handshake Version",
                    detector_type=self.detector_name,
                    severity="LOW",
                    confidence=0.62,
                    timestamp=earliest.timestamp_utc,
                    timestamp_epoch=earliest.timestamp,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=earliest.src_port,
                    destination_port=dst_port,
                    protocol="TLS",
                    packet_indices=pkt_indices,
                    evidence={
                        "observed_versions": versions,
                        "handshake_count": len(pkts),
                        "observed_tls_snis": sorted(
                            {p.tls.sni for p in pkts if p.tls and p.tls.sni}
                        ),
                        "packet_indices": pkt_indices,
                    },
                    explanation=(
                        f"Observed {len(pkts)} external TLS ClientHello handshake(s) proposing "
                        f"deprecated protocol version(s) {versions}. Deprecated TLS can reflect "
                        "legacy tooling or custom implants; payloads remain encrypted."
                    ),
                    recommended_investigation_steps=[
                        f"Identify client binary on {src_ip} negotiating {versions}.",
                    ],
                    candidate_mitre_ids=[],
                )
            )

        for (src_ip, dst_ip, dst_port), pkts in sorted(expired_certs.items()):
            earliest = min(pkts, key=lambda p: p.timestamp)
            pkt_indices = [p.packet_index for p in pkts[:100]]
            det_hash = hashlib.sha256(
                f"tlsexp:{src_ip}:{dst_ip}:{dst_port}".encode()
            ).hexdigest()[:12]
            findings.append(
                DetectionFinding(
                    detection_id=f"det-tlscert-{det_hash}",
                    detection_name="Expired X.509 Certificate Observed in TLS Handshake",
                    detector_type=self.detector_name,
                    severity="LOW",
                    confidence=0.68,
                    timestamp=earliest.timestamp_utc,
                    timestamp_epoch=earliest.timestamp,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=earliest.src_port,
                    destination_port=dst_port,
                    protocol="TLS",
                    packet_indices=pkt_indices,
                    evidence={
                        "certificate_subject": (
                            earliest.tls.certificate_subject if earliest.tls else None
                        ),
                        "certificate_not_after": (
                            earliest.tls.certificate_not_after if earliest.tls else None
                        ),
                        "packet_indices": pkt_indices,
                    },
                    explanation=(
                        f"Server {src_ip}:{earliest.src_port} presented an expired X.509 "
                        "certificate during TLS handshake."
                    ),
                    recommended_investigation_steps=[
                        f"Inspect certificate chain and host reputation for {src_ip}.",
                    ],
                    candidate_mitre_ids=[],
                )
            )
        return findings

    def _detect_arp_anomalies(self, packets: list[NormalizedPacket]) -> list[DetectionFinding]:
        arp_pkts = [p for p in packets if p.protocol == "ARP" or p.transport_protocol == "ARP"]
        if len(arp_pkts) < self.config.arp_gratuitous_burst_threshold:
            return []

        earliest = min(arp_pkts, key=lambda p: p.timestamp)
        pkt_indices = [p.packet_index for p in arp_pkts[:200]]
        det_hash = hashlib.sha256(f"arp_burst:{len(arp_pkts)}".encode()).hexdigest()[:12]
        return [
            DetectionFinding(
                detection_id=f"det-arp-{det_hash}",
                detection_name="Elevated Local ARP Activity Burst",
                detector_type=self.detector_name,
                severity="LOW",
                confidence=0.55,
                timestamp=earliest.timestamp_utc,
                timestamp_epoch=earliest.timestamp,
                source_ip=earliest.src_ip,
                destination_ip=earliest.dst_ip,
                source_port=None,
                destination_port=None,
                protocol="ARP",
                packet_indices=pkt_indices,
                evidence={
                    "arp_packet_count": len(arp_pkts),
                    "packet_indices": pkt_indices[:100],
                },
                explanation=(
                    f"Observed {len(arp_pkts)} ARP frames in capture, which may indicate local "
                    "subnet scanning, failover churn, or ARP cache probing."
                ),
                recommended_investigation_steps=[
                    "Review ARP sender MAC-to-IP mappings in packet evidence for conflicts."
                ],
                candidate_mitre_ids=[],
            )
        ]

    def _detect_tcp_anomalies(self, flows: list[NetworkFlow]) -> list[DetectionFinding]:
        unanswered_by_src: dict[str, list[NetworkFlow]] = defaultdict(list)
        findings: list[DetectionFinding] = []
        cfg = self.config

        for flow in flows:
            if flow.connection_state == "SYN_ONLY_UNANSWERED":
                unanswered_by_src[flow.initiator_ip].append(flow)
            if flow.retransmission_count >= cfg.tcp_high_retransmission_threshold:
                det_hash = hashlib.sha256(f"retx:{flow.flow_id}".encode()).hexdigest()[:12]
                findings.append(
                    DetectionFinding(
                        detection_id=f"det-tcpanom-{det_hash}",
                        detection_name="Excessive TCP Retransmissions",
                        detector_type=self.detector_name,
                        severity="LOW",
                        confidence=0.50,
                        timestamp=flow.first_seen_utc,
                        timestamp_epoch=flow.first_seen,
                        source_ip=flow.initiator_ip,
                        destination_ip=flow.responder_ip,
                        source_port=flow.initiator_port,
                        destination_port=flow.responder_port,
                        protocol="TCP",
                        flow_id=flow.flow_id,
                        packet_indices=list(flow.packet_indices[:100]),
                        evidence={
                            "retransmission_count": flow.retransmission_count,
                            "total_packets": flow.total_packets,
                            "connection_state": flow.connection_state,
                            "packet_indices": list(flow.packet_indices[:100]),
                        },
                        explanation=(
                            f"Flow {flow.flow_id} exhibited {flow.retransmission_count} TCP "
                            "retransmissions, indicating packet loss, firewall dropping, or "
                            "unstable C2 connectivity."
                        ),
                        recommended_investigation_steps=[
                            "Correlate with firewall drop logs or network congestion telemetry."
                        ],
                        candidate_mitre_ids=[],
                    )
                )

        for src_ip, syn_flows in sorted(unanswered_by_src.items()):
            unique_targets = {
                (f.responder_ip, f.responder_port) for f in syn_flows
            }
            if len(syn_flows) >= cfg.syn_scan_unanswered_threshold:
                earliest = min(syn_flows, key=lambda f: f.first_seen)
                pkt_indices = sorted({idx for f in syn_flows for idx in f.packet_indices})[:200]
                det_hash = hashlib.sha256(f"synscan:{src_ip}".encode()).hexdigest()[:12]
                findings.append(
                    DetectionFinding(
                        detection_id=f"det-synscan-{det_hash}",
                        detection_name="Multiple Unanswered TCP SYN Attempts",
                        detector_type=self.detector_name,
                        severity="MEDIUM",
                        confidence=0.66,
                        timestamp=earliest.first_seen_utc,
                        timestamp_epoch=earliest.first_seen,
                        source_ip=src_ip,
                        destination_ip=earliest.responder_ip,
                        source_port=earliest.initiator_port,
                        destination_port=earliest.responder_port,
                        protocol="TCP",
                        packet_indices=pkt_indices,
                        evidence={
                            "unanswered_syn_flows": len(syn_flows),
                            "unique_target_endpoints": len(unique_targets),
                            "sample_targets": sorted(
                                f"{ip}:{port}" for ip, port in list(unique_targets)[:10]
                            ),
                            "packet_indices": pkt_indices[:100],
                        },
                        explanation=(
                            f"Host {src_ip} initiated {len(syn_flows)} unanswered TCP SYN flows "
                            f"across {len(unique_targets)} target endpoint(s). This pattern is "
                            "consistent with reconnaissance probing or blocked C2 fallback."
                        ),
                        recommended_investigation_steps=[
                            f"Inspect {src_ip} for unauthorized port scanning or C2 retry loops.",
                            "Check perimeter firewall logs for blocked outbound SYN attempts.",
                        ],
                        candidate_mitre_ids=[],
                    )
                )

        return findings
