"""Aggregated investigation data model powering reports and API endpoints."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.models.alert import SecurityAlert, TimelineEvent
from app.models.flow import FlowReconstructionResult, NetworkFlow
from app.models.incident import CorrelatedIncident
from app.models.mitre import MitreMapping
from app.models.packet import CaptureMetadata, NormalizedPacket
from app.services.alert_manager import SEVERITY_RANK, AlertPipelineResult
from app.utils.network import is_external_ip


@dataclass(slots=True)
class InvestigationBundle:
    """Complete structured output of an end-to-end PCAP forensic investigation."""

    analysis_id: str
    status: str
    generated_at_utc: str
    processing_duration_ms: float
    capture_metadata: CaptureMetadata
    summary: dict[str, Any]
    protocol_distribution: list[dict[str, Any]]
    traffic_over_time: list[dict[str, Any]]
    top_hosts: list[dict[str, Any]]
    top_ports: list[dict[str, Any]]
    dns_analysis: dict[str, Any]
    http_analysis: dict[str, Any]
    tls_analysis: dict[str, Any]
    flows: list[NetworkFlow]
    alerts: list[SecurityAlert]
    active_alerts: list[SecurityAlert]
    suppressed_alerts: list[SecurityAlert]
    incidents: list[CorrelatedIncident]
    active_incidents: list[CorrelatedIncident]
    suppressed_incidents: list[CorrelatedIncident]
    mitre_mappings: list[MitreMapping]
    timeline: list[TimelineEvent]
    limitations: list[str] = field(default_factory=list)
    threat_intelligence: dict[str, Any] = field(default_factory=dict)
    integrity: dict[str, Any] = field(default_factory=dict)
    packet_flow_map: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "status": self.status,
            "generated_at_utc": self.generated_at_utc,
            "processing_duration_ms": self.processing_duration_ms,
            "capture_metadata": self.capture_metadata.to_dict(),
            "summary": self.summary,
            "protocol_distribution": self.protocol_distribution,
            "traffic_over_time": self.traffic_over_time,
            "top_hosts": self.top_hosts,
            "top_ports": self.top_ports,
            "dns_analysis": self.dns_analysis,
            "http_analysis": self.http_analysis,
            "tls_analysis": self.tls_analysis,
            "flows": [f.to_dict() for f in self.flows],
            "alerts": [a.to_dict() for a in self.alerts],
            "active_alerts": [a.to_dict() for a in self.active_alerts],
            "suppressed_alerts": [a.to_dict() for a in self.suppressed_alerts],
            "incidents": [inc.to_dict() for inc in self.incidents],
            "active_incidents": [inc.to_dict() for inc in self.active_incidents],
            "suppressed_incidents": [inc.to_dict() for inc in self.suppressed_incidents],
            "mitre_mappings": [m.to_dict() for m in self.mitre_mappings],
            "timeline": [t.to_dict() for t in self.timeline],
            "limitations": self.limitations,
            "threat_intelligence": self.threat_intelligence,
            "integrity": self.integrity,
            "packet_flow_map": self.packet_flow_map,
        }


def build_investigation_bundle(
    metadata: CaptureMetadata,
    packets: list[NormalizedPacket],
    flow_result: FlowReconstructionResult,
    alert_result: AlertPipelineResult,
    processing_duration_ms: float,
    status: str = "COMPLETED",
) -> InvestigationBundle:
    """Assemble analytics, host summaries, and forensic structures from pipeline stages."""
    proto_counts = Counter(p.protocol for p in packets)
    proto_bytes: Counter[str] = Counter()
    for p in packets:
        proto_bytes[p.protocol] += p.length

    protocol_distribution = [
        {
            "protocol": proto,
            "packet_count": count,
            "byte_count": proto_bytes[proto],
        }
        for proto, count in proto_counts.most_common()
    ]

    # Time-series buckets (10-second or 1-second buckets depending on capture span)
    traffic_over_time = _build_time_buckets(packets, alert_result.alerts)

    # Top communicating hosts (by total bytes sent + received)
    host_stats: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "ip": "",
            "bytes_sent": 0,
            "bytes_received": 0,
            "packets_sent": 0,
            "packets_received": 0,
            "alert_count": 0,
            "is_external": False,
        }
    )
    for f in flow_result.flows:
        s = host_stats[f.initiator_ip]
        s["ip"] = f.initiator_ip
        s["bytes_sent"] += f.bytes_initiator_to_responder
        s["bytes_received"] += f.bytes_responder_to_initiator
        s["packets_sent"] += f.packets_initiator_to_responder
        s["packets_received"] += f.packets_responder_to_initiator
        s["is_external"] = is_external_ip(f.initiator_ip)

        r = host_stats[f.responder_ip]
        r["ip"] = f.responder_ip
        r["bytes_sent"] += f.bytes_responder_to_initiator
        r["bytes_received"] += f.bytes_initiator_to_responder
        r["packets_sent"] += f.packets_responder_to_initiator
        r["packets_received"] += f.packets_initiator_to_responder
        r["is_external"] = is_external_ip(f.responder_ip)

    for a in alert_result.active_alerts:
        if a.source_ip and a.source_ip in host_stats:
            host_stats[a.source_ip]["alert_count"] += 1
        if a.destination_ip and a.destination_ip in host_stats:
            host_stats[a.destination_ip]["alert_count"] += 1

    top_hosts = sorted(
        (
            {**vals, "total_bytes": vals["bytes_sent"] + vals["bytes_received"]}
            for vals in host_stats.values()
        ),
        key=lambda item: -item["total_bytes"],
    )[:15]

    port_counts: Counter[int] = Counter()
    port_bytes: Counter[int] = Counter()
    for f in flow_result.flows:
        if f.responder_port is not None:
            port_counts[f.responder_port] += 1
            port_bytes[f.responder_port] += f.total_bytes
    top_ports = [
        {"port": port, "flow_count": cnt, "total_bytes": port_bytes[port]}
        for port, cnt in port_counts.most_common(12)
    ]

    dns_analysis = _summarize_dns(packets)
    http_analysis = _summarize_http(packets)
    tls_analysis = _summarize_tls(packets)

    sev_counts = Counter(a.severity for a in alert_result.active_alerts)
    inbound_bytes = sum(
        f.bytes_responder_to_initiator for f in flow_result.flows if f.direction == "outbound"
    ) + sum(
        f.bytes_initiator_to_responder for f in flow_result.flows if f.direction == "inbound"
    )
    outbound_bytes = sum(
        f.bytes_initiator_to_responder for f in flow_result.flows if f.direction == "outbound"
    ) + sum(
        f.bytes_responder_to_initiator for f in flow_result.flows if f.direction == "inbound"
    )

    summary = {
        "total_packets": len(packets),
        "total_bytes": sum(p.length for p in packets),
        "total_flows": flow_result.total_flows,
        "unique_source_ips": flow_result.unique_source_ips,
        "unique_destination_ips": flow_result.unique_destination_ips,
        "dns_queries": dns_analysis["total_queries"],
        "http_requests": http_analysis["total_requests"],
        "tls_handshakes": tls_analysis["total_handshakes"],
        "suspicious_events": len(alert_result.active_alerts),
        "suppressed_events": len(alert_result.suppressed_alerts),
        "total_alerts": len(alert_result.alerts),
        "allowlisted_alerts": len(alert_result.suppressed_alerts),
        "correlated_incidents": len(alert_result.incidents),
        "active_incidents": len(alert_result.active_incidents),
        "allowlisted_incidents": len(alert_result.suppressed_incidents),
        "total_incidents": len(alert_result.incidents),
        "critical_alerts": sev_counts.get("CRITICAL", 0),
        "high_alerts": sev_counts.get("HIGH", 0),
        "medium_alerts": sev_counts.get("MEDIUM", 0),
        "low_alerts": sev_counts.get("LOW", 0),
        "informational_alerts": sev_counts.get("INFORMATIONAL", 0),
        "severity_distribution": {
            sev: sev_counts.get(sev, 0)
            for sev in sorted(SEVERITY_RANK.keys(), key=lambda s: -SEVERITY_RANK[s])
        },
        "outbound_bytes": outbound_bytes,
        "inbound_bytes": inbound_bytes,
        "processing_duration_ms": round(processing_duration_ms, 2),
    }

    limitations = [
        (
            "Encrypted TLS/HTTPS application payloads are not decrypted; analysis relies on "
            "observable metadata (SNI, TLS version, endpoints, timing, and byte volumes)."
        ),
        (
            "Network Address Translation (NAT), proxies, or midstream capture boundaries may "
            "obscure true originating host identity or flow directionality."
        ),
        (
            "Heuristic detections and YAML rules identify suspicious indicators and cannot "
            "independently prove unauthorised data theft without endpoint/host corroboration."
        ),
        (
            "Capture truncation, packet loss, or clock differences across capture sensors can "
            "affect timing/beaconing intervals, retransmission counts, and payload completeness."
        ),
        (
            "MITRE ATT&CK mappings represent inferred adversary techniques justified by observed "
            "network indicators and confidence thresholds."
        ),
        (
            "Integrity hashing verifies local capture and report artifacts against recorded "
            "SHA-256 digests; it is not a legal certification or complete chain-of-custody control."
        ),
    ]

    referenced_pkts: set[int] = set()
    for a in alert_result.alerts:
        referenced_pkts.update(a.packet_indices)
    for rec in dns_analysis.get("records", []):
        if isinstance(rec, dict) and isinstance(rec.get("packet_index"), int):
            referenced_pkts.add(rec["packet_index"])
    pkt_flow_refs = {
        str(pidx): flow_result.packet_flow_map[pidx]
        for pidx in sorted(referenced_pkts)
        if pidx in flow_result.packet_flow_map
    }

    return InvestigationBundle(
        analysis_id=metadata.analysis_id,
        status=status,
        generated_at_utc=datetime.now(UTC).isoformat(),
        processing_duration_ms=round(processing_duration_ms, 2),
        capture_metadata=metadata,
        summary=summary,
        protocol_distribution=protocol_distribution,
        traffic_over_time=traffic_over_time,
        top_hosts=top_hosts,
        top_ports=top_ports,
        dns_analysis=dns_analysis,
        http_analysis=http_analysis,
        tls_analysis=tls_analysis,
        flows=flow_result.flows,
        alerts=alert_result.alerts,
        active_alerts=alert_result.active_alerts,
        suppressed_alerts=alert_result.suppressed_alerts,
        incidents=alert_result.incidents,
        active_incidents=alert_result.active_incidents,
        suppressed_incidents=alert_result.suppressed_incidents,
        mitre_mappings=alert_result.mitre_summary,
        timeline=alert_result.timeline,
        limitations=limitations,
        packet_flow_map=pkt_flow_refs,
    )


def _build_time_buckets(
    packets: list[NormalizedPacket],
    alerts: list[SecurityAlert],
) -> list[dict[str, Any]]:
    if not packets:
        return []
    min_ts = min(p.timestamp for p in packets)
    max_ts = max(p.timestamp for p in packets)
    span = max(1.0, max_ts - min_ts)
    bucket_size = 1.0 if span <= 60 else (10.0 if span <= 600 else 60.0)

    buckets: dict[int, dict[str, Any]] = defaultdict(
        lambda: {"bytes": 0, "packets": 0, "dns_queries": 0, "suspicious_events": 0}
    )
    for p in packets:
        b_idx = int((p.timestamp - min_ts) // bucket_size)
        buckets[b_idx]["bytes"] += p.length
        buckets[b_idx]["packets"] += 1
        if p.dns is not None and not p.dns.is_response:
            buckets[b_idx]["dns_queries"] += 1

    for a in alerts:
        if not a.suppressed:
            b_idx = max(0, int((a.timestamp_epoch - min_ts) // bucket_size))
            buckets[b_idx]["suspicious_events"] += 1

    rows: list[dict[str, Any]] = []
    for b_idx in sorted(buckets.keys()):
        b_ts = min_ts + b_idx * bucket_size
        rows.append(
            {
                "timestamp": datetime.fromtimestamp(b_ts, tz=UTC).strftime("%H:%M:%S"),
                "timestamp_epoch": round(b_ts, 3),
                **buckets[b_idx],
            }
        )
    return rows


def _summarize_dns(packets: list[NormalizedPacket]) -> dict[str, Any]:
    queries = [p for p in packets if p.dns is not None and not p.dns.is_response]
    responses = [p for p in packets if p.dns is not None and p.dns.is_response]
    domain_counts = Counter(
        p.dns.query_name for p in queries if p.dns and p.dns.query_name
    )
    parent_counts = Counter(
        p.dns.parent_domain for p in queries if p.dns and p.dns.parent_domain
    )
    qtype_counts = Counter(
        p.dns.query_type for p in queries if p.dns and p.dns.query_type
    )
    rcode_counts = Counter(
        p.dns.response_code for p in responses if p.dns and p.dns.response_code
    )
    return {
        "total_queries": len(queries),
        "total_responses": len(responses),
        "unique_domains": len(domain_counts),
        "unique_parent_domains": len(parent_counts),
        "nxdomain_count": rcode_counts.get("NXDOMAIN", 0),
        "query_types": dict(qtype_counts),
        "response_codes": dict(rcode_counts),
        "top_queried_domains": [
            {"domain": dom, "count": cnt} for dom, cnt in domain_counts.most_common(12)
        ],
        "top_parent_domains": [
            {"domain": dom, "count": cnt} for dom, cnt in parent_counts.most_common(10)
        ],
    }


def _summarize_http(packets: list[NormalizedPacket]) -> dict[str, Any]:
    reqs = [p for p in packets if p.http is not None and p.http.is_request]
    resps = [p for p in packets if p.http is not None and not p.http.is_request]
    methods = Counter(p.http.method for p in reqs if p.http and p.http.method)
    hosts = Counter(p.http.host for p in reqs if p.http and p.http.host)
    user_agents = Counter(p.http.user_agent for p in reqs if p.http and p.http.user_agent)
    total_upload = sum(
        max(p.http.payload_size, p.http.content_length or 0)
        for p in reqs
        if p.http and p.http.method in {"POST", "PUT", "PATCH"}
    )
    return {
        "total_requests": len(reqs),
        "total_responses": len(resps),
        "methods": dict(methods),
        "total_upload_payload_bytes": total_upload,
        "top_hosts": [{"host": h, "count": c} for h, c in hosts.most_common(10)],
        "top_user_agents": [{"user_agent": ua, "count": c} for ua, c in user_agents.most_common(8)],
        "sample_requests": [
            {
                "timestamp": p.timestamp_utc,
                "src_ip": p.src_ip,
                "dst_ip": p.dst_ip,
                "method": p.http.method,
                "host": p.http.host,
                "uri": p.http.uri,
                "user_agent": p.http.user_agent,
                "payload_size": max(p.http.payload_size, p.http.content_length or 0),
                "direction": p.http.direction,
            }
            for p in reqs[:15]
            if p.http
        ],
    }


def _summarize_tls(packets: list[NormalizedPacket]) -> dict[str, Any]:
    tls_pkts = [p for p in packets if p.tls is not None]
    snis = Counter(p.tls.sni for p in tls_pkts if p.tls and p.tls.sni)
    versions = Counter(
        p.tls.handshake_version or p.tls.record_version
        for p in tls_pkts
        if p.tls and (p.tls.handshake_version or p.tls.record_version)
    )
    return {
        "total_handshakes": len(tls_pkts),
        "observed_snis": [{"sni": s, "count": c} for s, c in snis.most_common(12)],
        "versions": dict(versions),
        "note": "TLS application payloads remain encrypted and were not inspected.",
    }
