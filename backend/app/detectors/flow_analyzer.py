"""Bidirectional network flow reconstruction engine."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from app.models.flow import FlowReconstructionResult, NetworkFlow
from app.models.packet import NormalizedPacket
from app.utils.network import classify_direction

CanonicalFlowKey = tuple[str, str, int | None, str, int | None]


@dataclass(slots=True)
class _ActiveFlowState:
    """Mutable accumulator for an active bidirectional flow."""

    flow_seq: int
    canonical_key: CanonicalFlowKey
    transport_protocol: str
    application_protocol: str
    initiator_ip: str
    initiator_port: int | None
    responder_ip: str
    responder_port: int | None
    direction: str

    first_seen: float
    last_seen: float
    first_seen_utc: str
    last_seen_utc: str

    packets_i2r: int = 0
    packets_r2i: int = 0
    bytes_i2r: int = 0
    bytes_r2i: int = 0

    tcp_flag_counts: Counter[str] = field(default_factory=Counter)
    saw_syn: bool = False
    saw_syn_ack: bool = False
    saw_ack_after_synack: bool = False
    saw_fin_i2r: bool = False
    saw_fin_r2i: bool = False
    saw_rst: bool = False
    retransmission_count: int = 0

    dns_queries: set[str] = field(default_factory=set)
    http_hosts: set[str] = field(default_factory=set)
    http_methods: set[str] = field(default_factory=set)
    tls_snis: set[str] = field(default_factory=set)
    packet_indices: list[int] = field(default_factory=list)

    # Incremental stats for packet sizes and inter-arrival times (capped sample or Welford)
    min_pkt_size: int | None = None
    max_pkt_size: int = 0
    pkt_size_mean: float = 0.0
    pkt_size_m2: float = 0.0
    iat_count: int = 0
    iat_mean: float = 0.0
    iat_m2: float = 0.0
    min_iat: float | None = None
    max_iat: float | None = None
    prev_pkt_ts: float | None = None

    def resolved_flow_id(self) -> str:
        return _build_flow_id(
            self.transport_protocol,
            self.initiator_ip,
            self.initiator_port,
            self.responder_ip,
            self.responder_port,
            self.flow_seq,
        )

    def is_initiator_packet(self, pkt: NormalizedPacket) -> bool:
        return pkt.src_ip == self.initiator_ip and pkt.src_port == self.initiator_port

    def record_size_and_iat(self, pkt_len: int, pkt_ts: float) -> None:
        n = self.packets_i2r + self.packets_r2i
        if self.min_pkt_size is None or pkt_len < self.min_pkt_size:
            self.min_pkt_size = pkt_len
        if pkt_len > self.max_pkt_size:
            self.max_pkt_size = pkt_len

        delta = pkt_len - self.pkt_size_mean
        self.pkt_size_mean += delta / n
        delta2 = pkt_len - self.pkt_size_mean
        self.pkt_size_m2 += delta * delta2

        if self.prev_pkt_ts is not None:
            iat = max(0.0, pkt_ts - self.prev_pkt_ts)
            self.iat_count += 1
            if self.min_iat is None or iat < self.min_iat:
                self.min_iat = iat
            if self.max_iat is None or iat > self.max_iat:
                self.max_iat = iat
            d_iat = iat - self.iat_mean
            self.iat_mean += d_iat / self.iat_count
            self.iat_m2 += d_iat * (iat - self.iat_mean)
        self.prev_pkt_ts = pkt_ts

    def finalize(self) -> NetworkFlow:
        total_packets = self.packets_i2r + self.packets_r2i
        total_bytes = self.bytes_i2r + self.bytes_r2i
        duration = max(0.0, round(self.last_seen - self.first_seen, 6))
        avg_size = round(total_bytes / total_packets, 2) if total_packets > 0 else 0.0
        std_size = (
            round(math.sqrt(self.pkt_size_m2 / total_packets), 2)
            if total_packets > 1
            else 0.0
        )

        mean_iat = round(self.iat_mean, 6) if self.iat_count > 0 else None
        min_iat = round(self.min_iat, 6) if self.min_iat is not None else None
        max_iat = round(self.max_iat, 6) if self.max_iat is not None else None
        std_iat = (
            round(math.sqrt(self.iat_m2 / self.iat_count), 6)
            if self.iat_count > 1
            else (0.0 if self.iat_count == 1 else None)
        )

        ratio: float | None = None
        if self.bytes_r2i > 0:
            ratio = round(self.bytes_i2r / self.bytes_r2i, 4)
        elif self.bytes_i2r > 0:
            ratio = float(self.bytes_i2r)

        state, state_basis, is_midstream = self._infer_connection_state()
        eff_dur = max(duration, 0.001)
        bps = round(total_bytes / eff_dur, 2) if total_bytes > 0 and duration > 0 else 0.0
        pps = round(total_packets / eff_dur, 2) if total_packets > 0 and duration > 0 else 0.0
        retx_rel = (
            "observed_tcp_seq_retransmissions"
            if self.transport_protocol == "TCP"
            else "not_applicable"
        )

        return NetworkFlow(
            flow_id=self.resolved_flow_id(),
            transport_protocol=self.transport_protocol,
            application_protocol=self.application_protocol,
            initiator_ip=self.initiator_ip,
            initiator_port=self.initiator_port,
            responder_ip=self.responder_ip,
            responder_port=self.responder_port,
            direction=self.direction,
            packets_initiator_to_responder=self.packets_i2r,
            packets_responder_to_initiator=self.packets_r2i,
            bytes_initiator_to_responder=self.bytes_i2r,
            bytes_responder_to_initiator=self.bytes_r2i,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            first_seen_utc=self.first_seen_utc,
            last_seen_utc=self.last_seen_utc,
            duration_seconds=duration,
            total_packets=total_packets,
            total_bytes=total_bytes,
            avg_packet_size=avg_size,
            min_packet_size=self.min_pkt_size or 0,
            max_packet_size=self.max_pkt_size,
            std_packet_size=std_size,
            mean_iat_seconds=mean_iat,
            min_iat_seconds=min_iat,
            max_iat_seconds=max_iat,
            std_iat_seconds=std_iat,
            outbound_to_inbound_ratio=ratio,
            tcp_flags_distribution=dict(sorted(self.tcp_flag_counts.items())),
            connection_state=state,
            state_basis=state_basis,
            handshake_completed=self.saw_ack_after_synack,
            is_midstream=is_midstream,
            retransmission_count=self.retransmission_count,
            retransmission_reliability=retx_rel,
            bytes_per_second=bps,
            packets_per_second=pps,
            observed_dns_queries=sorted(self.dns_queries),
            observed_http_hosts=sorted(self.http_hosts),
            observed_http_methods=sorted(self.http_methods),
            observed_tls_snis=sorted(self.tls_snis),
            packet_indices=list(self.packet_indices),
        )

    def _infer_connection_state(self) -> tuple[str, str, bool]:
        if self.transport_protocol == "TCP":
            if self.saw_rst:
                basis = "observed_rst_after_syn" if self.saw_syn else "inferred_midstream_rst"
                return "RESET", basis, not self.saw_syn
            if self.saw_fin_i2r and self.saw_fin_r2i:
                basis = "observed_full_teardown" if self.saw_syn else "inferred_midstream_close"
                return "CLOSED_GRACEFUL", basis, not self.saw_syn
            if self.saw_fin_i2r or self.saw_fin_r2i:
                basis = "observed_half_close" if self.saw_syn else "inferred_midstream_half_close"
                return "HALF_CLOSED", basis, not self.saw_syn
            if self.saw_syn and self.saw_syn_ack:
                basis = (
                    "observed_3way_handshake"
                    if self.saw_ack_after_synack
                    else "inferred_syn_synack"
                )
                return "ESTABLISHED", basis, False
            if self.saw_syn and not self.saw_syn_ack and self.packets_r2i == 0:
                return "SYN_ONLY_UNANSWERED", "observed_unanswered_syn", False
            if not self.saw_syn and (self.packets_i2r + self.packets_r2i) > 0:
                return "MIDSTREAM_ACTIVE", "inferred_midstream_no_syn", True
            return "UNKNOWN", "insufficient_tcp_flags", not self.saw_syn

        if self.transport_protocol == "UDP":
            if self.packets_i2r > 0 and self.packets_r2i > 0:
                return "BIDIRECTIONAL_UDP", "observed_bidirectional_datagrams", False
            return "UNIDIRECTIONAL_UDP", "observed_unidirectional_datagrams", False

        if self.transport_protocol == "ICMP":
            return "ICMP_EXCHANGE", "observed_icmp_packets", False

        return "STATELESS", "observed_stateless_packets", False


def _build_flow_id(
    transport: str,
    init_ip: str,
    init_port: int | None,
    resp_ip: str,
    resp_port: int | None,
    seq: int,
) -> str:
    raw = f"{transport}:{init_ip}:{init_port}->{resp_ip}:{resp_port}#{seq}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"flow-{digest}"


def _canonical_key(pkt: NormalizedPacket) -> CanonicalFlowKey:
    transport = pkt.transport_protocol or pkt.protocol
    ep_a = (pkt.src_ip or "", pkt.src_port)
    ep_b = (pkt.dst_ip or "", pkt.dst_port)
    ep1, ep2 = sorted(
        [ep_a, ep_b],
        key=lambda ep: (ep[0], ep[1] if ep[1] is not None else -1),
    )
    return (transport, ep1[0], ep1[1], ep2[0], ep2[1])


class FlowAnalyzer:
    """Reconstruct bidirectional flows with idle-timeout and TCP lifecycle splitting."""

    def __init__(
        self,
        idle_timeout_seconds: float = 120.0,
        split_on_new_syn_after_close: bool = True,
    ) -> None:
        if idle_timeout_seconds <= 0:
            raise ValueError("idle_timeout_seconds must be positive.")
        self.idle_timeout_seconds = idle_timeout_seconds
        self.split_on_new_syn_after_close = split_on_new_syn_after_close

    def reconstruct_flows(self, packets: Iterable[NormalizedPacket]) -> list[NetworkFlow]:
        """Reconstruct sorted bidirectional NetworkFlow objects from packets."""
        return self.analyze(packets).flows

    def analyze(self, packets: Iterable[NormalizedPacket]) -> FlowReconstructionResult:
        """Process packets in chronological order and return flows + aggregate counts."""
        active_flows: dict[CanonicalFlowKey, _ActiveFlowState] = {}
        flow_seq_counters: dict[CanonicalFlowKey, int] = {}
        completed_flows: list[NetworkFlow] = []
        packet_flow_map: dict[int, str] = {}
        skipped_non_ip = 0
        src_ips: set[str] = set()
        dst_ips: set[str] = set()

        for pkt in packets:
            if not pkt.src_ip or not pkt.dst_ip:
                skipped_non_ip += 1
                continue

            src_ips.add(pkt.src_ip)
            dst_ips.add(pkt.dst_ip)
            key = _canonical_key(pkt)
            existing = active_flows.get(key)

            if existing is not None and self._should_rotate_flow(existing, pkt):
                completed_flows.append(existing.finalize())
                existing = None

            if existing is None:
                seq = flow_seq_counters.get(key, 0) + 1
                flow_seq_counters[key] = seq
                existing = self._start_flow(pkt, key, seq)
                active_flows[key] = existing

            self._update_flow(existing, pkt)
            packet_flow_map[pkt.packet_index] = existing.resolved_flow_id()

        for remaining in active_flows.values():
            completed_flows.append(remaining.finalize())

        completed_flows.sort(key=lambda f: (f.first_seen, f.flow_id))

        # Compute per-(initiator, responder) connection frequency across the capture
        pair_times: dict[tuple[str, str], list[float]] = {}
        for f in completed_flows:
            pair_times.setdefault((f.initiator_ip, f.responder_ip), []).append(f.first_seen)
        pair_freq: dict[tuple[str, str], float] = {}
        for pair, times in pair_times.items():
            span = max(1.0, max(times) - min(times)) if len(times) > 1 else 60.0
            pair_freq[pair] = round((len(times) / span) * 60.0, 2)
        for f in completed_flows:
            f.connection_frequency_per_min = pair_freq.get((f.initiator_ip, f.responder_ip), 0.0)

        total_flow_packets = sum(f.total_packets for f in completed_flows)
        total_flow_bytes = sum(f.total_bytes for f in completed_flows)

        return FlowReconstructionResult(
            flows=completed_flows,
            total_flows=len(completed_flows),
            total_flow_packets=total_flow_packets,
            total_flow_bytes=total_flow_bytes,
            skipped_non_ip_packets=skipped_non_ip,
            unique_source_ips=len(src_ips),
            unique_destination_ips=len(dst_ips),
            packet_flow_map=packet_flow_map,
        )

    def _should_rotate_flow(self, flow: _ActiveFlowState, pkt: NormalizedPacket) -> bool:
        if (pkt.timestamp - flow.last_seen) > self.idle_timeout_seconds:
            return True
        if (
            self.split_on_new_syn_after_close
            and pkt.tcp is not None
            and pkt.tcp.is_syn
            and (flow.saw_rst or (flow.saw_fin_i2r and flow.saw_fin_r2i))
        ):
            return True
        return False

    def _start_flow(
        self,
        pkt: NormalizedPacket,
        key: CanonicalFlowKey,
        seq: int,
    ) -> _ActiveFlowState:
        transport = pkt.transport_protocol or pkt.protocol
        src_ip = pkt.src_ip or ""
        dst_ip = pkt.dst_ip or ""
        return _ActiveFlowState(
            flow_seq=seq,
            canonical_key=key,
            transport_protocol=transport,
            application_protocol=pkt.protocol,
            initiator_ip=src_ip,
            initiator_port=pkt.src_port,
            responder_ip=dst_ip,
            responder_port=pkt.dst_port,
            direction=classify_direction(src_ip, dst_ip),
            first_seen=pkt.timestamp,
            last_seen=pkt.timestamp,
            first_seen_utc=pkt.timestamp_utc,
            last_seen_utc=pkt.timestamp_utc,
        )

    def _update_flow(self, flow: _ActiveFlowState, pkt: NormalizedPacket) -> None:
        if pkt.timestamp < flow.first_seen:
            flow.first_seen = pkt.timestamp
            flow.first_seen_utc = pkt.timestamp_utc
        if pkt.timestamp > flow.last_seen:
            flow.last_seen = pkt.timestamp
            flow.last_seen_utc = pkt.timestamp_utc

        if pkt.protocol in {"DNS", "HTTP", "TLS"}:
            flow.application_protocol = pkt.protocol

        is_i2r = flow.is_initiator_packet(pkt)
        if is_i2r:
            flow.packets_i2r += 1
            flow.bytes_i2r += pkt.length
        else:
            flow.packets_r2i += 1
            flow.bytes_r2i += pkt.length

        flow.record_size_and_iat(pkt.length, pkt.timestamp)

        if pkt.tcp is not None:
            self._update_tcp_state(flow, pkt, is_i2r)

        if pkt.dns is not None and pkt.dns.query_name:
            flow.dns_queries.add(pkt.dns.query_name)
        if pkt.http is not None:
            if pkt.http.host:
                flow.http_hosts.add(pkt.http.host)
            if pkt.http.method:
                flow.http_methods.add(pkt.http.method)
        if pkt.tls is not None and pkt.tls.sni:
            flow.tls_snis.add(pkt.tls.sni)
        if len(flow.packet_indices) < 500:
            flow.packet_indices.append(pkt.packet_index)

    def _update_tcp_state(
        self,
        flow: _ActiveFlowState,
        pkt: NormalizedPacket,
        is_i2r: bool,
    ) -> None:
        tcp = pkt.tcp
        if tcp is None:
            return
        if tcp.flag_names:
            flow.tcp_flag_counts[tcp.flag_names] += 1
        if tcp.is_syn:
            flow.saw_syn = True
        if tcp.is_syn_ack:
            flow.saw_syn_ack = True
        if tcp.is_fin:
            if is_i2r:
                flow.saw_fin_i2r = True
            else:
                flow.saw_fin_r2i = True
        if tcp.is_rst:
            flow.saw_rst = True
        if tcp.is_retransmission:
            flow.retransmission_count += 1
        if flow.saw_syn_ack and (tcp.flags & 0x10) and not tcp.is_syn_ack:
            flow.saw_ack_after_synack = True
