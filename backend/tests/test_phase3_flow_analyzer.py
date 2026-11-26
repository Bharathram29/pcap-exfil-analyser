"""Phase 3 tests: bidirectional network flow reconstruction and state inference."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from app.core.database import DatabaseManager
from app.detectors.flow_analyzer import FlowAnalyzer
from app.models.packet import DnsMetadata, HttpMetadata, NormalizedPacket, TcpMetadata
from app.parsers.packet_parser import PacketParser
from app.services.ingestion import PcapIngestor


def _pkt(
    idx: int,
    ts: float,
    src_ip: str | None,
    dst_ip: str | None,
    src_port: int | None,
    dst_port: int | None,
    proto: str,
    transport: str | None,
    length: int,
    tcp_flags: int | None = None,
    flag_names: str = "",
    http: HttpMetadata | None = None,
    dns: DnsMetadata | None = None,
) -> NormalizedPacket:
    tcp_meta = None
    if transport == "TCP" and tcp_flags is not None:
        is_syn = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)
        is_syn_ack = bool(tcp_flags & 0x02) and bool(tcp_flags & 0x10)
        tcp_meta = TcpMetadata(
            seq=idx * 100,
            ack=idx * 10,
            flags=tcp_flags,
            flag_names=flag_names,
            window_size=65535,
            payload_size=max(0, length - 54),
            is_syn=is_syn,
            is_syn_ack=is_syn_ack,
            is_fin=bool(tcp_flags & 0x01),
            is_rst=bool(tcp_flags & 0x04),
            is_retransmission=False,
        )

    return NormalizedPacket(
        packet_index=idx,
        timestamp=ts,
        timestamp_utc=datetime.fromtimestamp(ts, tz=UTC).isoformat(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        transport_protocol=transport,
        length=length,
        ttl=64 if src_ip else None,
        ip_version=4 if src_ip else None,
        tcp=tcp_meta,
        http=http,
        dns=dns,
    )


def test_bidirectional_tcp_flow_no_double_counting() -> None:
    t0 = 1700000100.0
    packets = [
        _pkt(1, t0, "10.0.0.5", "198.51.100.20", 51000, 80, "TCP", "TCP", 66, 0x02, "S"),
        _pkt(2, t0 + 0.02, "198.51.100.20", "10.0.0.5", 80, 51000, "TCP", "TCP", 66, 0x12, "SA"),
        _pkt(3, t0 + 0.03, "10.0.0.5", "198.51.100.20", 51000, 80, "TCP", "TCP", 54, 0x10, "A"),
        _pkt(
            4,
            t0 + 0.05,
            "10.0.0.5",
            "198.51.100.20",
            51000,
            80,
            "HTTP",
            "TCP",
            1054,
            0x18,
            "PA",
            http=HttpMetadata(is_request=True, method="POST", host="exfil.example.org"),
        ),
        _pkt(5, t0 + 0.10, "198.51.100.20", "10.0.0.5", 80, 51000, "TCP", "TCP", 154, 0x18, "PA"),
        _pkt(6, t0 + 0.20, "10.0.0.5", "198.51.100.20", 51000, 80, "TCP", "TCP", 54, 0x11, "FA"),
        _pkt(7, t0 + 0.22, "198.51.100.20", "10.0.0.5", 80, 51000, "TCP", "TCP", 54, 0x11, "FA"),
    ]

    result = FlowAnalyzer().analyze(packets)
    assert result.total_flows == 1
    flow = result.flows[0]

    assert flow.initiator_ip == "10.0.0.5"
    assert flow.initiator_port == 51000
    assert flow.responder_ip == "198.51.100.20"
    assert flow.responder_port == 80
    assert flow.direction == "outbound"
    assert flow.application_protocol == "HTTP"
    assert flow.connection_state == "CLOSED_GRACEFUL"

    # Initiator sent pkts 1,3,4,6 -> 66 + 54 + 1054 + 54 = 1228 bytes
    assert flow.packets_initiator_to_responder == 4
    assert flow.bytes_initiator_to_responder == 1228

    # Responder sent pkts 2,5,7 -> 66 + 154 + 54 = 274 bytes
    assert flow.packets_responder_to_initiator == 3
    assert flow.bytes_responder_to_initiator == 274

    # Strict invariant: no double-counting
    assert flow.total_packets == 7
    assert flow.total_bytes == 1502
    assert result.total_flow_packets == 7
    assert result.total_flow_bytes == 1502
    assert flow.duration_seconds == pytest.approx(0.22)
    assert flow.outbound_to_inbound_ratio == pytest.approx(round(1228 / 274, 4))
    assert flow.tcp_flags_distribution == {"A": 1, "FA": 2, "PA": 2, "S": 1, "SA": 1}
    assert flow.observed_http_hosts == ["exfil.example.org"]


def test_idle_timeout_splits_flows_and_udp_states() -> None:
    t0 = 1700000200.0
    dns_meta = DnsMetadata(
        transaction_id=1, is_response=False, query_name="sub.example.net", query_type="A"
    )
    packets = [
        _pkt(1, t0, "10.0.0.5", "8.8.8.8", 55000, 53, "DNS", "UDP", 75, dns=dns_meta),
        _pkt(2, t0 + 0.05, "8.8.8.8", "10.0.0.5", 53, 55000, "DNS", "UDP", 95),
        # 15 seconds later (> 5s idle timeout) on same 5-tuple
        _pkt(3, t0 + 15.0, "10.0.0.5", "8.8.8.8", 55000, 53, "DNS", "UDP", 75, dns=dns_meta),
    ]

    flows = FlowAnalyzer(idle_timeout_seconds=5.0).reconstruct_flows(packets)
    assert len(flows) == 2
    assert flows[0].flow_id != flows[1].flow_id
    assert flows[0].connection_state == "BIDIRECTIONAL_UDP"
    assert flows[0].total_packets == 2
    assert flows[1].connection_state == "UNIDIRECTIONAL_UDP"
    assert flows[1].total_packets == 1


def test_tcp_unanswered_reset_midstream_and_close_rotation() -> None:
    t0 = 1700000300.0
    packets = [
        # Flow 1: SYN only unanswered
        _pkt(1, t0, "10.0.0.8", "203.0.113.10", 40001, 4444, "TCP", "TCP", 60, 0x02, "S"),
        # Flow 2: Reset, followed quickly by new SYN reusing same 5-tuple -> rotated
        _pkt(2, t0 + 1.0, "10.0.0.8", "203.0.113.11", 40002, 8080, "TCP", "TCP", 60, 0x02, "S"),
        _pkt(3, t0 + 1.01, "203.0.113.11", "10.0.0.8", 8080, 40002, "TCP", "TCP", 54, 0x04, "R"),
        _pkt(4, t0 + 2.0, "10.0.0.8", "203.0.113.11", 40002, 8080, "TCP", "TCP", 60, 0x02, "S"),
        _pkt(5, t0 + 2.02, "203.0.113.11", "10.0.0.8", 8080, 40002, "TCP", "TCP", 60, 0x12, "SA"),
        # Flow 4: Midstream active (no SYN seen)
        _pkt(6, t0 + 3.0, "10.0.0.9", "93.184.216.34", 49152, 443, "TLS", "TCP", 200, 0x18, "PA"),
    ]

    flows = FlowAnalyzer(idle_timeout_seconds=120.0).reconstruct_flows(packets)
    assert len(flows) == 4
    assert flows[0].connection_state == "SYN_ONLY_UNANSWERED"
    assert flows[1].connection_state == "RESET"
    assert flows[2].connection_state == "ESTABLISHED"
    assert flows[3].connection_state == "MIDSTREAM_ACTIVE"


def test_end_to_end_scapy_parse_to_flow_reconstruction(
    temp_settings, tmp_path: Path
) -> None:
    temp_settings.ensure_directories()
    db = DatabaseManager(temp_settings.database_path)
    db.init_schema()
    ingestor = PcapIngestor(temp_settings, db)
    parser = PacketParser()

    t0 = 1700000400.0
    p1 = Ether() / ARP(psrc="10.0.0.5", pdst="10.0.0.1")
    p1.time = t0
    p2 = (
        Ether()
        / IP(src="10.0.0.5", dst="198.51.100.30")
        / TCP(sport=52000, dport=80, flags="PA", seq=100, ack=1)
        / Raw(load=b"POST /up HTTP/1.1\r\nHost: bad.example\r\nContent-Length: 4\r\n\r\ntest")
    )
    p2.time = t0 + 0.1
    p3 = (
        Ether()
        / IP(src="198.51.100.30", dst="10.0.0.5")
        / UDP(sport=53, dport=5353)
    )
    p3.time = t0 + 0.2

    pcap_path = tmp_path / "mixed.pcap"
    wrpcap(str(pcap_path), [p1, p2, p3])

    meta = ingestor.ingest_existing_file(pcap_path)
    parsed = parser.parse_capture(meta)
    flow_res = FlowAnalyzer().analyze(parsed.packets)

    assert flow_res.skipped_non_ip_packets == 1
    assert flow_res.total_flows == 2
    assert flow_res.total_flow_packets == 2
    assert flow_res.unique_source_ips == 2
    assert flow_res.unique_destination_ips == 2
