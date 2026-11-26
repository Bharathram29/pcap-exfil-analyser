"""Reproducible synthetic PCAP generator for PCAP Exfiltration Analyser.

Generates safe, deterministic normal and suspicious-simulated network traffic
without real credentials, malware, or sensitive data.
"""

from __future__ import annotations

import argparse
import hashlib
import random
import struct
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "sample_data" / "test_exfil.pcap"
BASE_TIMESTAMP = 1735689600.0  # 2025-01-01T00:00:00Z
SRC_MAC = "02:11:22:33:44:55"
DST_MAC = "02:aa:bb:cc:dd:ee"


def _build_tls_client_hello(sni: str) -> bytes:
    """Construct a benign TLS 1.2 ClientHello payload with SNI extension."""
    sni_bytes = sni.encode("ascii")
    sni_entry = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    extensions = struct.pack("!H", len(sni_ext)) + sni_ext
    body = (
        b"\x03\x03"
        + b"\x42" * 32
        + b"\x00"
        + struct.pack("!HH", 2, 0x1301)
        + b"\x01\x00"
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _tcp_handshake_and_data(
    packets: list[Packet],
    ts: float,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    outbound_payloads: list[bytes],
    inbound_payload: bytes,
    close_gracefully: bool = True,
) -> None:
    """Append a realistic 3-way TCP handshake, data exchange, and optional FIN teardown."""
    seq_c = 1000
    seq_s = 5000

    syn = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src_ip, dst=dst_ip) / TCP(
        sport=sport, dport=dport, flags="S", seq=seq_c
    )
    syn.time = ts
    packets.append(syn)
    seq_c += 1

    synack = Ether(src=DST_MAC, dst=SRC_MAC) / IP(src=dst_ip, dst=src_ip) / TCP(
        sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c
    )
    synack.time = ts + 0.02
    packets.append(synack)
    seq_s += 1

    ack = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src_ip, dst=dst_ip) / TCP(
        sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s
    )
    ack.time = ts + 0.03
    packets.append(ack)

    cur_ts = ts + 0.05
    for chunk in outbound_payloads:
        pkt = (
            Ether(src=SRC_MAC, dst=DST_MAC)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s)
            / Raw(load=chunk)
        )
        pkt.time = cur_ts
        packets.append(pkt)
        seq_c += len(chunk)
        cur_ts += 0.01

    if inbound_payload:
        resp = (
            Ether(src=DST_MAC, dst=SRC_MAC)
            / IP(src=dst_ip, dst=src_ip)
            / TCP(sport=dport, dport=sport, flags="PA", seq=seq_s, ack=seq_c)
            / Raw(load=inbound_payload)
        )
        resp.time = cur_ts + 0.02
        packets.append(resp)
        seq_s += len(inbound_payload)
        cur_ts += 0.03

    if close_gracefully:
        fin1 = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src_ip, dst=dst_ip) / TCP(
            sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s
        )
        fin1.time = cur_ts + 0.02
        packets.append(fin1)

        fin2 = Ether(src=DST_MAC, dst=SRC_MAC) / IP(src=dst_ip, dst=src_ip) / TCP(
            sport=dport, dport=sport, flags="FA", seq=seq_s, ack=seq_c + 1
        )
        fin2.time = cur_ts + 0.04
        packets.append(fin2)


def generate_synthetic_pcap(output_path: Path = DEFAULT_OUTPUT, seed: int = 20250101) -> str:
    """Generate reproducible synthetic PCAP and return its SHA-256 hex digest."""
    rng = random.Random(seed)  # noqa: S311 - deterministic synthetic test traffic only
    packets: list[Packet] = []
    client_ip = "10.0.10.25"
    dns_server = "8.8.8.8"

    # 1. Normal DNS Queries & Responses (api.example.com, cdn.example.com, dl.windowsupdate.com)
    normal_domains = [
        ("api.example.com", "93.184.216.34"),
        ("cdn.example.com", "93.184.216.35"),
        ("dl.windowsupdate.com", "93.184.216.36"),
    ]
    for idx, (domain, ans_ip) in enumerate(normal_domains):
        q = (
            Ether(src=SRC_MAC, dst=DST_MAC)
            / IP(src=client_ip, dst=dns_server)
            / UDP(sport=51000 + idx, dport=53)
            / DNS(id=100 + idx, qr=0, qd=DNSQR(qname=domain, qtype="A"))
        )
        q.time = BASE_TIMESTAMP + idx * 0.5
        packets.append(q)

        r = (
            Ether(src=DST_MAC, dst=SRC_MAC)
            / IP(src=dns_server, dst=client_ip)
            / UDP(sport=53, dport=51000 + idx)
            / DNS(
                id=100 + idx,
                qr=1,
                rcode=0,
                qd=DNSQR(qname=domain, qtype="A"),
                an=DNSRR(rrname=domain, type="A", rdata=ans_ip),
            )
        )
        r.time = BASE_TIMESTAMP + idx * 0.5 + 0.03
        packets.append(r)

    # 2. Normal HTTP GET & Normal TLS Connection
    http_get = (
        b"GET /api/status HTTP/1.1\r\n"
        b"Host: api.example.com\r\n"
        b"User-Agent: HealthProbe/1.0\r\n\r\n"
    )
    http_ok = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 15\r\n\r\n"
        b'{"status":"ok"}'
    )
    _tcp_handshake_and_data(
        packets,
        ts=BASE_TIMESTAMP + 2.0,
        src_ip=client_ip,
        dst_ip="93.184.216.34",
        sport=52001,
        dport=80,
        outbound_payloads=[http_get],
        inbound_payload=http_ok,
    )

    _tcp_handshake_and_data(
        packets,
        ts=BASE_TIMESTAMP + 4.0,
        src_ip=client_ip,
        dst_ip="93.184.216.35",
        sport=52002,
        dport=443,
        outbound_payloads=[_build_tls_client_hello("cdn.example.com")],
        inbound_payload=b"\x16\x03\x03\x00\x05hello",
    )

    # 3. Suspicious Simulated Traffic A: DNS Tunnelling Burst (10 long high-entropy TXT queries)
    for i in range(10):
        # Deterministic high-entropy hex/alphanumeric synthetic label
        hex_label = "".join(rng.choice("0123456789abcdef") for _ in range(52))
        qname = f"{hex_label}.exfil-example.net"
        q_tun = (
            Ether(src=SRC_MAC, dst=DST_MAC)
            / IP(src=client_ip, dst=dns_server)
            / UDP(sport=53000 + i, dport=53)
            / DNS(id=500 + i, qr=0, qd=DNSQR(qname=qname, qtype="TXT"))
        )
        q_tun.time = BASE_TIMESTAMP + 8.0 + i * 0.25
        packets.append(q_tun)

        r_tun = (
            Ether(src=DST_MAC, dst=SRC_MAC)
            / IP(src=dns_server, dst=client_ip)
            / UDP(sport=53, dport=53000 + i)
            / DNS(id=500 + i, qr=1, rcode=0, qd=DNSQR(qname=qname, qtype="TXT"))
        )
        r_tun.time = BASE_TIMESTAMP + 8.0 + i * 0.25 + 0.02
        packets.append(r_tun)

    # 4. Suspicious Simulated Traffic B: Large HTTP POST Upload (> 550 KB total outbound)
    declared_len = 560_000
    post_header = (
        f"POST /v1/archive/drop HTTP/1.1\r\n"
        f"Host: 203.0.113.75:8081\r\n"
        f"User-Agent: SyntheticUploader/2.0\r\n"
        f"Content-Length: {declared_len}\r\n\r\n"
    ).encode("ascii")
    filler_chunk = b"SYNTHETIC_BENCHMARK_BLOCK_" * 50  # 1300 bytes per segment
    outbound_chunks = [post_header + filler_chunk] + [filler_chunk for _ in range(430)]
    _tcp_handshake_and_data(
        packets,
        ts=BASE_TIMESTAMP + 15.0,
        src_ip=client_ip,
        dst_ip="203.0.113.75",
        sport=54000,
        dport=8081,
        outbound_payloads=outbound_chunks,
        inbound_payload=b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok",
    )

    # 5. Suspicious Simulated Traffic C: Periodic Outbound Beaconing (6 flows, ~15.0s interval)
    for b_idx in range(6):
        jitter = (b_idx % 2 - 0.5) * 0.2
        beacon_ts = BASE_TIMESTAMP + 30.0 + b_idx * 15.0 + jitter
        _tcp_handshake_and_data(
            packets,
            ts=beacon_ts,
            src_ip=client_ip,
            dst_ip="198.51.100.88",
            sport=55000 + b_idx,
            dport=8443,
            outbound_payloads=[_build_tls_client_hello("beacon-sync.example.net")],
            inbound_payload=b"\x17\x03\x03\x00\x10ack",
        )

    # 6. Suspicious Simulated Traffic D: Unusual External Connection on High-Risk Port 4444
    unusual_chunks = [b"DIAG_CHANNEL_PAYLOAD_" * 50 for _ in range(60)]
    _tcp_handshake_and_data(
        packets,
        ts=BASE_TIMESTAMP + 125.0,
        src_ip=client_ip,
        dst_ip="198.51.100.99",
        sport=56000,
        dport=4444,
        outbound_payloads=unusual_chunks,
        inbound_payload=b"ACK_READY",
    )

    # Sort chronologically so packet timestamps increase monotonically
    packets.sort(key=lambda pkt: float(pkt.time))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    return hashlib.sha256(output_path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate reproducible synthetic test PCAP.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=20250101)
    args = parser.parse_args()

    sha256 = generate_synthetic_pcap(output_path=args.output, seed=args.seed)
    print(f"Generated {args.output} ({args.output.stat().st_size} bytes, sha256={sha256})")


if __name__ == "__main__":
    main()
