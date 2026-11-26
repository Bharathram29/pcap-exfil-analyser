"""Phase 2 tests: secure PCAP/PCAPNG ingestion and Scapy packet parsing engine."""

from __future__ import annotations

import datetime
import hashlib
import io
import struct
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import PcapNgWriter, wrpcap

from app.core.config import Settings
from app.core.database import DatabaseManager
from app.parsers.packet_parser import PacketParser
from app.services.ingestion import (
    FileTooLargeError,
    InvalidExtensionError,
    InvalidSignatureError,
    PcapIngestor,
)
from app.utils.security import UnsafePathError, safe_resolve_within, sanitize_filename


def _build_tls_client_hello(sni: str) -> bytes:
    """Build a minimal valid TLS 1.2 ClientHello carrying an SNI extension."""
    server_name_bytes = sni.encode("ascii")
    sni_entry = b"\x00" + struct.pack("!H", len(server_name_bytes)) + server_name_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    extensions = struct.pack("!H", len(sni_ext)) + sni_ext
    body = (
        b"\x03\x03"  # Client version TLS 1.2
        + b"\x11" * 32  # Random
        + b"\x00"  # Session ID length
        + struct.pack("!HH", 2, 0x1301)  # Cipher suites
        + b"\x01\x00"  # Compression methods (null)
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


def _build_tls_certificate_record() -> bytes:
    """Build a TLS 1.2 Certificate handshake containing a self-signed X.509 DER cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "exfil-test.example")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    cert_entry = len(der).to_bytes(3, "big") + der
    cert_list = len(cert_entry).to_bytes(3, "big") + cert_entry
    handshake = b"\x0b" + len(cert_list).to_bytes(3, "big") + cert_list
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def _make_ingestor(settings: Settings) -> PcapIngestor:
    settings.ensure_directories()
    db = DatabaseManager(settings.database_path)
    db.init_schema()
    return PcapIngestor(settings, db)


def test_sanitize_and_path_confinement(tmp_path: Path) -> None:
    assert sanitize_filename("../../evil/..\\capture.pcap") == "capture.pcap"
    with pytest.raises(UnsafePathError):
        sanitize_filename("..")
    with pytest.raises(UnsafePathError):
        sanitize_filename("bad\x00.pcap")
    with pytest.raises(UnsafePathError):
        safe_resolve_within(tmp_path, tmp_path / ".." / "escape.pcap")


def test_ingest_valid_pcap_and_pcapng(temp_settings: Settings, tmp_path: Path) -> None:
    ingestor = _make_ingestor(temp_settings)

    pkt = Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(
        id=0x1234, qr=0, qd=DNSQR(qname="api.example.com", qtype="A")
    )
    pcap_path = tmp_path / "sample.pcap"
    wrpcap(str(pcap_path), [pkt])

    with pcap_path.open("rb") as f:
        meta_pcap = ingestor.ingest_stream(f, "../../sample.pcap")

    expected_sha = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
    assert meta_pcap.capture_format == "pcap"
    assert meta_pcap.sanitized_filename == "sample.pcap"
    assert meta_pcap.sha256 == expected_sha
    assert meta_pcap.supported_link_layer is True
    assert meta_pcap.link_layer_type == 1

    # Verify DB row persisted
    with ingestor.db.connection() as conn:
        row = conn.execute(
            "SELECT * FROM investigations WHERE analysis_id = ?",
            (meta_pcap.analysis_id,),
        ).fetchone()
    assert row is not None
    assert row["sha256"] == expected_sha
    assert row["status"] == "INGESTED"

    # Now test PCAPNG
    pcapng_path = tmp_path / "sample.pcapng"
    writer = PcapNgWriter(str(pcapng_path))
    writer.write(pkt)
    writer.close()

    meta_ng = ingestor.ingest_existing_file(pcapng_path)
    assert meta_ng.capture_format == "pcapng"
    assert meta_ng.supported_link_layer is True


def test_ingest_rejects_invalid_extension_signature_and_oversize(
    temp_settings: Settings, tmp_path: Path
) -> None:
    temp_settings.max_upload_size_bytes = 64
    ingestor = _make_ingestor(temp_settings)

    with pytest.raises(InvalidExtensionError):
        ingestor.ingest_stream(io.BytesIO(b"hello"), "notes.txt")

    with pytest.raises(InvalidSignatureError):
        ingestor.ingest_stream(io.BytesIO(b"NOT_A_PCAP_FILE_HEADER_1234"), "fake.pcap")

    with pytest.raises(FileTooLargeError):
        ingestor.ingest_stream(io.BytesIO(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100), "big.pcap")


def test_empty_and_unsupported_link_layer_pcap(temp_settings: Settings, tmp_path: Path) -> None:
    ingestor = _make_ingestor(temp_settings)
    parser = PacketParser()

    # Empty PCAP (valid 24-byte global header, 0 packets, Ethernet DLT=1)
    empty_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    meta_empty = ingestor.ingest_stream(io.BytesIO(empty_header), "empty.pcap")
    result_empty = parser.parse_capture(meta_empty)
    assert result_empty.metadata.is_empty is True
    assert result_empty.metadata.packet_count == 0
    assert result_empty.packets == []

    # Unsupported link-layer type (DLT=147 USER0)
    unsupported_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 147)
    meta_unsup = ingestor.ingest_stream(io.BytesIO(unsupported_header), "user0.pcap")
    assert meta_unsup.supported_link_layer is False
    assert any("Unsupported link-layer type" in w for w in meta_unsup.warnings)


def test_truncated_pcap_handled_gracefully(temp_settings: Settings, tmp_path: Path) -> None:
    ingestor = _make_ingestor(temp_settings)
    parser = PacketParser()

    p1 = Ether() / IP(src="10.0.0.2", dst="10.0.0.3") / ICMP()
    p2 = Ether() / IP(src="10.0.0.3", dst="10.0.0.2") / ICMP()
    pcap_path = tmp_path / "good.pcap"
    wrpcap(str(pcap_path), [p1, p2])

    raw = pcap_path.read_bytes()
    # Append partial packet record header + incomplete payload
    truncated_bytes = raw + struct.pack("<IIII", 1700000000, 0, 500, 500) + b"\x00" * 20
    meta = ingestor.ingest_stream(io.BytesIO(truncated_bytes), "truncated.pcap")
    result = parser.parse_capture(meta)

    assert result.metadata.packet_count >= 2
    assert result.packets[0].protocol == "ICMP"
    assert result.packets[1].protocol == "ICMP"
    assert result.metadata.malformed_packet_count >= 1
    assert any("truncated" in w.lower() for w in result.metadata.warnings)


def test_packet_parser_extracts_dns_http_tls_tcp_ipv6_and_arp(
    temp_settings: Settings, tmp_path: Path
) -> None:
    ingestor = _make_ingestor(temp_settings)
    parser = PacketParser()

    base_ts = 1700000000.0
    packets = []

    # 1. DNS query + 2. DNS response
    q_pkt = (
        Ether()
        / IP(src="192.168.1.10", dst="8.8.8.8", ttl=64)
        / UDP(sport=51000, dport=53)
        / DNS(id=4242, qr=0, qd=DNSQR(qname="4a7f9c2e.exfil-example.net", qtype="TXT"))
    )
    q_pkt.time = base_ts
    packets.append(q_pkt)

    r_pkt = (
        Ether()
        / IP(src="8.8.8.8", dst="192.168.1.10", ttl=55)
        / UDP(sport=53, dport=51000)
        / DNS(
            id=4242,
            qr=1,
            rcode=0,
            qd=DNSQR(qname="4a7f9c2e.exfil-example.net", qtype="A"),
            an=DNSRR(rrname="4a7f9c2e.exfil-example.net", type="A", rdata="203.0.113.50"),
        )
    )
    r_pkt.time = base_ts + 0.02
    packets.append(r_pkt)

    # 3. TCP SYN + 4. Retransmitted SYN + 5. HTTP POST
    syn_pkt = Ether() / IP(src="192.168.1.10", dst="198.51.100.10") / TCP(
        sport=55555, dport=80, flags="S", seq=1000
    )
    syn_pkt.time = base_ts + 0.1
    packets.append(syn_pkt)

    syn_retx = Ether() / IP(src="192.168.1.10", dst="198.51.100.10") / TCP(
        sport=55555, dport=80, flags="S", seq=1000
    )
    syn_retx.time = base_ts + 0.3
    packets.append(syn_retx)

    http_body = b"chunk=" + b"A" * 120
    http_req = (
        f"POST /upload HTTP/1.1\r\n"
        f"Host: drop.example.org\r\n"
        f"User-Agent: CustomAgent/1.0\r\n"
        f"Content-Length: {len(http_body)}\r\n\r\n"
    ).encode("ascii") + http_body
    http_pkt = (
        Ether()
        / IP(src="192.168.1.10", dst="198.51.100.10")
        / TCP(sport=55555, dport=80, flags="PA", seq=1001, ack=1)
        / Raw(load=http_req)
    )
    http_pkt.time = base_ts + 0.4
    packets.append(http_pkt)

    # 6. TLS ClientHello (SNI) + 7. TLS Certificate
    tls_ch_pkt = (
        Ether()
        / IP(src="192.168.1.10", dst="93.184.216.34")
        / TCP(sport=55556, dport=443, flags="PA", seq=2000, ack=1)
        / Raw(load=_build_tls_client_hello("cdn.exfil-test.org"))
    )
    tls_ch_pkt.time = base_ts + 0.5
    packets.append(tls_ch_pkt)

    tls_cert_pkt = (
        Ether()
        / IP(src="93.184.216.34", dst="192.168.1.10")
        / TCP(sport=443, dport=55556, flags="PA", seq=3000, ack=200)
        / Raw(load=_build_tls_certificate_record())
    )
    tls_cert_pkt.time = base_ts + 0.6
    packets.append(tls_cert_pkt)

    # 8. IPv6 + 9. ARP (tests partial fields & missing_fields)
    ip6_pkt = (
        Ether()
        / IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=64)
        / TCP(sport=44444, dport=443, flags="S", seq=10)
    )
    ip6_pkt.time = base_ts + 0.7
    packets.append(ip6_pkt)

    arp_pkt = Ether() / ARP(psrc="192.168.1.10", pdst="192.168.1.1")
    arp_pkt.time = base_ts + 0.8
    packets.append(arp_pkt)

    pcap_path = tmp_path / "protocols.pcap"
    wrpcap(str(pcap_path), packets)

    meta = ingestor.ingest_existing_file(pcap_path)
    result = parser.parse_capture(meta)
    assert result.metadata.packet_count == 9

    dns_q, dns_r, syn1, syn2, http_n, tls_ch, tls_cert, ip6_n, arp_n = result.packets

    # DNS query & correlated response
    assert dns_q.protocol == "DNS"
    assert dns_q.dns is not None
    assert dns_q.dns.query_name == "4a7f9c2e.exfil-example.net"
    assert dns_q.dns.query_type == "TXT"
    assert dns_q.dns.parent_domain == "exfil-example.net"
    assert dns_q.dns.subdomain_labels == ["4a7f9c2e"]
    assert dns_q.dns.subdomain_length == 8
    assert dns_q.dns.query_length == 26

    assert dns_r.dns is not None
    assert dns_r.dns.is_response is True
    assert dns_r.dns.response_code == "NOERROR"
    assert dns_r.dns.response_ips == ["203.0.113.50"]
    assert dns_r.dns.matched_query_timestamp == pytest.approx(base_ts)

    # TCP SYN & retransmission
    assert syn1.tcp is not None and syn1.tcp.is_syn is True and syn1.tcp.is_retransmission is False
    assert syn2.tcp is not None and syn2.tcp.is_retransmission is True

    # HTTP POST
    assert http_n.protocol == "HTTP"
    assert http_n.http is not None
    assert http_n.http.method == "POST"
    assert http_n.http.host == "drop.example.org"
    assert http_n.http.uri == "/upload"
    assert http_n.http.user_agent == "CustomAgent/1.0"
    assert http_n.http.content_length == len(http_body)
    assert http_n.http.payload_size == len(http_body)
    assert http_n.http.direction == "outbound_request"

    # TLS ClientHello + Certificate
    assert tls_ch.protocol == "TLS"
    assert tls_ch.tls is not None
    assert tls_ch.tls.sni == "cdn.exfil-test.org"
    assert tls_ch.tls.handshake_version == "TLSv1.2"
    assert tls_ch.tls.encrypted_payload_not_inspected is True

    assert tls_cert.protocol == "TLS"
    assert tls_cert.tls is not None
    assert tls_cert.tls.handshake_type == "Certificate"
    assert tls_cert.tls.certificate_subject is not None
    assert "exfil-test.example" in tls_cert.tls.certificate_subject

    # IPv6 & ARP missing_fields
    assert ip6_n.ip_version == 6
    assert ip6_n.ttl == 64
    assert arp_n.protocol == "ARP"
    assert "src_ip" in arp_n.missing_fields
    assert "src_port" in arp_n.missing_fields
