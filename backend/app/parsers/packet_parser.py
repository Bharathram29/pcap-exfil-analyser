"""Streaming Scapy-based packet parser and traffic normalizer."""

from __future__ import annotations

import struct
from collections import defaultdict
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scapy.error import Scapy_Exception
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Packet, Raw
from scapy.utils import PcapNgReader, PcapReader

from app.core.logging import get_logger
from app.models.packet import (
    CaptureMetadata,
    NormalizedPacket,
    ParsedCaptureResult,
    TcpMetadata,
)
from app.parsers.protocol_extractors import (
    extract_dns_metadata,
    extract_http_metadata,
    extract_tls_metadata,
)

logger = get_logger("parsers.packet_parser")


class PacketParser:
    """Dissect PCAP/PCAPNG captures into normalized packet metadata without full-file loads."""

    def __init__(self, max_packets: int | None = None) -> None:
        self.max_packets = max_packets

    def parse_capture(self, metadata: CaptureMetadata) -> ParsedCaptureResult:
        """Stream-parse an ingested capture and update its CaptureMetadata counters."""
        packets = list(self.iter_packets(Path(metadata.stored_path), metadata=metadata))
        metadata.packet_count = len(packets)
        metadata.is_empty = metadata.packet_count == 0
        return ParsedCaptureResult(metadata=metadata, packets=packets)

    def iter_packets(
        self,
        pcap_path: Path,
        metadata: CaptureMetadata | None = None,
    ) -> Iterator[NormalizedPacket]:
        """Yield NormalizedPacket records one by one using Scapy streaming readers."""
        warnings_target = metadata.warnings if metadata is not None else []
        dns_query_cache: dict[tuple[str | None, str | None, int, str], float] = {}
        seen_tcp_segments: dict[tuple[str | None, int, str | None, int], set[tuple[int, int]]] = (
            defaultdict(set)
        )

        reader = self._open_reader(pcap_path, metadata)
        packet_index = 0
        try:
            iterator = iter(reader)
            while True:
                if self.max_packets is not None and packet_index >= self.max_packets:
                    warnings_target.append(
                        f"Packet processing capped at configured limit ({self.max_packets})."
                    )
                    break
                try:
                    raw_pkt = next(iterator)
                except StopIteration:
                    break
                except (EOFError, Scapy_Exception, struct.error, OSError, ValueError) as exc:
                    msg = (
                        f"Capture truncated or unreadable at packet index {packet_index}: {exc}"
                    )
                    logger.warning(msg)
                    warnings_target.append(msg)
                    if metadata is not None:
                        metadata.malformed_packet_count += 1
                    break

                packet_index += 1
                wirelen = getattr(raw_pkt, "wirelen", None)
                pkt_truncated = isinstance(wirelen, int) and len(raw_pkt) < wirelen
                normalized = self._normalize_packet(
                    pkt=raw_pkt,
                    packet_index=packet_index,
                    dns_query_cache=dns_query_cache,
                    seen_tcp_segments=seen_tcp_segments,
                )
                if pkt_truncated:
                    normalized.is_malformed = True
                    warnings_target.append(
                        f"Packet {packet_index} truncated ({len(raw_pkt)} of {wirelen} bytes)."
                    )
                if normalized.is_malformed and metadata is not None:
                    metadata.malformed_packet_count += 1
                yield normalized
        finally:
            reader.close()

    def _open_reader(
        self,
        pcap_path: Path,
        metadata: CaptureMetadata | None,
    ) -> PcapReader | PcapNgReader:
        is_pcapng = (
            metadata.capture_format == "pcapng"
            if metadata is not None
            else pcap_path.suffix.lower() == ".pcapng"
        )
        if is_pcapng:
            return PcapNgReader(str(pcap_path))
        return PcapReader(str(pcap_path))

    def _normalize_packet(
        self,
        pkt: Packet,
        packet_index: int,
        dns_query_cache: dict[tuple[str | None, str | None, int, str], float],
        seen_tcp_segments: dict[tuple[str | None, int, str | None, int], set[tuple[int, int]]],
    ) -> NormalizedPacket:
        missing_fields: list[str] = []
        is_malformed = False

        try:
            timestamp = float(pkt.time)
            timestamp_utc = datetime.fromtimestamp(timestamp, tz=UTC).isoformat(
                timespec="microseconds"
            )
        except Exception:
            timestamp = 0.0
            timestamp_utc = datetime.fromtimestamp(0.0, tz=UTC).isoformat(
                timespec="microseconds"
            )
            missing_fields.append("timestamp")
        length = len(pkt)

        src_ip: str | None = None
        dst_ip: str | None = None
        ttl: int | None = None
        ip_version: int | None = None

        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            ttl = int(ip_layer.ttl)
            ip_version = 4
        elif pkt.haslayer(IPv6):
            ip6_layer = pkt[IPv6]
            src_ip = str(ip6_layer.src)
            dst_ip = str(ip6_layer.dst)
            ttl = int(ip6_layer.hlim)
            ip_version = 6
        else:
            missing_fields.extend(["src_ip", "dst_ip", "ttl", "ip_version"])

        src_port: int | None = None
        dst_port: int | None = None
        transport_protocol: str | None = None
        tcp_meta: TcpMetadata | None = None
        payload_bytes = b""

        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            transport_protocol = "TCP"
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            payload_bytes = self._extract_payload_bytes(tcp_layer)
            tcp_meta = self._build_tcp_metadata(
                tcp_layer=tcp_layer,
                payload_size=len(payload_bytes),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                seen_tcp_segments=seen_tcp_segments,
            )
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            transport_protocol = "UDP"
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
            payload_bytes = self._extract_payload_bytes(udp_layer)
        elif pkt.haslayer(ICMP):
            transport_protocol = "ICMP"
            missing_fields.extend(["src_port", "dst_port"])
        elif pkt.haslayer(ARP):
            transport_protocol = "ARP"
            missing_fields.extend(["src_port", "dst_port"])
        else:
            missing_fields.extend(["src_port", "dst_port"])

        dns_meta = None
        http_meta = None
        tls_meta = None
        protocol = transport_protocol or "OTHER"

        try:
            dns_meta = extract_dns_metadata(
                pkt=pkt,
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                query_cache=dns_query_cache,
            )
            if dns_meta is not None:
                protocol = "DNS"
            elif transport_protocol == "TCP" and payload_bytes:
                http_meta = extract_http_metadata(payload_bytes, src_ip, dst_ip)
                if http_meta is not None:
                    protocol = "HTTP"
                else:
                    tls_meta = extract_tls_metadata(payload_bytes)
                    if tls_meta is not None:
                        protocol = "TLS"
            elif transport_protocol == "TCP" and payload_bytes and (
                src_port == 443 or dst_port == 443
            ):
                # Encrypted application data after handshake on 443 still classified as TLS
                protocol = "TLS"
        except Exception as exc:
            is_malformed = True
            logger.debug("Partial dissection error at packet %d: %s", packet_index, exc)

        try:
            summary = pkt.summary()
        except Exception:
            summary = f"Packet#{packet_index} ({protocol})"
            is_malformed = True

        return NormalizedPacket(
            packet_index=packet_index,
            timestamp=timestamp,
            timestamp_utc=timestamp_utc,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            transport_protocol=transport_protocol,
            length=length,
            ttl=ttl,
            ip_version=ip_version,
            is_malformed=is_malformed,
            missing_fields=sorted(set(missing_fields)),
            dns=dns_meta,
            http=http_meta,
            tls=tls_meta,
            tcp=tcp_meta,
            raw_summary=summary,
        )

    def _extract_payload_bytes(self, transport_layer: Any) -> bytes:
        if transport_layer.haslayer(Raw):
            return bytes(transport_layer[Raw].load)
        payload = transport_layer.payload
        if payload is None or len(payload) == 0:
            return b""
        try:
            return bytes(payload)
        except Exception:
            return b""

    def _build_tcp_metadata(
        self,
        tcp_layer: Any,
        payload_size: int,
        src_ip: str | None,
        dst_ip: str | None,
        src_port: int,
        dst_port: int,
        seen_tcp_segments: dict[tuple[str | None, int, str | None, int], set[tuple[int, int]]],
    ) -> TcpMetadata:
        flags_obj = tcp_layer.flags
        flags_int = int(flags_obj)
        flag_names = str(flags_obj)
        seq = int(tcp_layer.seq)
        ack = int(tcp_layer.ack)
        window = int(tcp_layer.window)

        is_syn = bool(flags_int & 0x02) and not bool(flags_int & 0x10)
        is_syn_ack = bool(flags_int & 0x02) and bool(flags_int & 0x10)
        is_fin = bool(flags_int & 0x01)
        is_rst = bool(flags_int & 0x04)

        is_retransmission = False
        if payload_size > 0 or is_syn or is_syn_ack or is_fin:
            flow_dir_key = (src_ip, src_port, dst_ip, dst_port)
            seg_sig = (seq, payload_size)
            seen = seen_tcp_segments[flow_dir_key]
            if seg_sig in seen:
                is_retransmission = True
            else:
                if len(seen) > 50_000:
                    seen.clear()
                seen.add(seg_sig)

        return TcpMetadata(
            seq=seq,
            ack=ack,
            flags=flags_int,
            flag_names=flag_names,
            window_size=window,
            payload_size=payload_size,
            is_syn=is_syn,
            is_syn_ack=is_syn_ack,
            is_fin=is_fin,
            is_rst=is_rst,
            is_retransmission=is_retransmission,
        )
