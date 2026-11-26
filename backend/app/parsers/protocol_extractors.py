"""Protocol-specific metadata extractors for DNS, HTTP, and observable TLS."""

from __future__ import annotations

import struct
from typing import Any

from cryptography import x509
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Packet

from app.models.packet import DnsMetadata, HttpMetadata, TlsMetadata
from app.utils.network import classify_direction

DNS_QTYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
    255: "ANY",
}

DNS_RCODES: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "CONNECT",
    "TRACE",
}

TLS_VERSIONS: dict[int, str] = {
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}

TLS_HANDSHAKE_TYPES: dict[int, str] = {
    1: "ClientHello",
    2: "ServerHello",
    11: "Certificate",
    12: "ServerKeyExchange",
    14: "ServerHelloDone",
    16: "ClientKeyExchange",
}


def extract_dns_metadata(
    pkt: Packet,
    timestamp: float,
    src_ip: str | None,
    dst_ip: str | None,
    query_cache: dict[tuple[str | None, str | None, int, str], float],
) -> DnsMetadata | None:
    """Extract DNS query/response metadata and correlate responses to prior queries."""
    if not pkt.haslayer(DNS):
        return None

    dns = pkt[DNS]
    dns_id = int(getattr(dns, "id", 0) or 0)
    is_response = bool(getattr(dns, "qr", 0))

    qname: str | None = None
    qtype_str: str | None = None
    qd_layer = _first_dns_query(dns, pkt)
    if qd_layer is not None:
        raw_qname = qd_layer.qname
        if isinstance(raw_qname, bytes):
            qname = raw_qname.decode("utf-8", errors="replace").rstrip(".").lower()
        elif raw_qname is not None:
            qname = str(raw_qname).rstrip(".").lower()
        qtype_int = int(getattr(qd_layer, "qtype", 0) or 0)
        qtype_str = DNS_QTYPES.get(qtype_int, f"TYPE{qtype_int}")

    rcode_str: str | None = None
    response_ips: list[str] = []
    answer_count = 0
    response_size_bytes = 0
    if is_response:
        rcode_int = int(getattr(dns, "rcode", 0) or 0)
        rcode_str = DNS_RCODES.get(rcode_int, f"RCODE{rcode_int}")
        response_ips = _extract_dns_response_ips(dns)
        answer_count = int(getattr(dns, "ancount", 0) or len(response_ips))
        try:
            response_size_bytes = len(bytes(dns))
        except Exception:
            response_size_bytes = 0

    subdomain_labels: list[str] = []
    parent_domain: str | None = None
    subdomain_length = 0
    label_count = 0
    query_length = len(qname) if qname else 0

    if qname:
        labels = [lbl for lbl in qname.split(".") if lbl]
        label_count = len(labels)
        if label_count >= 2:
            parent_domain = ".".join(labels[-2:])
            subdomain_labels = labels[:-2]
            subdomain_length = len(".".join(subdomain_labels)) if subdomain_labels else 0
        else:
            parent_domain = qname

    matched_ts: float | None = None
    if qname:
        if not is_response:
            query_cache[(src_ip, dst_ip, dns_id, qname)] = timestamp
        else:
            matched_ts = query_cache.get((dst_ip, src_ip, dns_id, qname))

    return DnsMetadata(
        transaction_id=dns_id,
        is_response=is_response,
        query_name=qname,
        query_type=qtype_str,
        response_code=rcode_str,
        response_ips=response_ips,
        query_length=query_length,
        subdomain_labels=subdomain_labels,
        subdomain_length=subdomain_length,
        parent_domain=parent_domain,
        label_count=label_count,
        matched_query_timestamp=matched_ts,
        answer_count=answer_count,
        response_size_bytes=response_size_bytes,
    )


def _first_dns_query(dns: Any, pkt: Packet) -> DNSQR | None:
    """Return the primary DNSQR record across Scapy list or single-object representations."""
    qd = getattr(dns, "qd", None)
    if isinstance(qd, list) and qd:
        for item in qd:
            if isinstance(item, DNSQR):
                return item
    elif isinstance(qd, DNSQR):
        return qd
    if pkt.haslayer(DNSQR):
        return pkt[DNSQR]
    return None


def _extract_dns_response_ips(dns: Any) -> list[str]:
    """Collect A/AAAA answer IP strings from DNSRR lists or chains."""
    ips: list[str] = []
    for section_attr in ("an", "ar"):
        section = getattr(dns, section_attr, None)
        records: list[DNSRR] = []
        if isinstance(section, list):
            records = [item for item in section if isinstance(item, DNSRR)]
        else:
            rr = section
            while rr is not None and isinstance(rr, DNSRR):
                records.append(rr)
                rr = rr.payload if isinstance(rr.payload, DNSRR) else None

        for rr in records:
            rr_type = int(getattr(rr, "type", 0) or 0)
            if rr_type in (1, 28) and getattr(rr, "rdata", None) is not None:
                rdata = rr.rdata
                ip_val = (
                    rdata.decode("utf-8", errors="replace")
                    if isinstance(rdata, bytes)
                    else str(rdata)
                )
                ips.append(ip_val)
    return ips


def extract_http_metadata(
    payload: bytes,
    src_ip: str | None,
    dst_ip: str | None,
) -> HttpMetadata | None:
    """Extract observable HTTP/1.x request or response metadata from TCP payload."""
    if not payload or len(payload) < 12:
        return None

    sep = b"\r\n\r\n"
    sep_idx = payload.find(sep)
    if sep_idx == -1:
        sep = b"\n\n"
        sep_idx = payload.find(sep)

    head_bytes = payload[:sep_idx] if sep_idx != -1 else payload[:2048]
    body_bytes = payload[sep_idx + len(sep) :] if sep_idx != -1 else b""

    try:
        head_text = head_bytes.decode("latin-1")
    except Exception:
        return None

    lines = [line.strip("\r") for line in head_text.split("\n") if line.strip("\r")]
    if not lines:
        return None

    first_line = lines[0]
    parts = first_line.split(" ", 2)
    if len(parts) < 2:
        return None

    is_request = parts[0].upper() in HTTP_METHODS and "HTTP/" in first_line
    is_response = parts[0].upper().startswith("HTTP/1.")
    if not is_request and not is_response:
        return None

    headers: dict[str, str] = {}
    header_names: list[str] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key_clean = k.strip()
        headers[key_clean.lower()] = v.strip()
        header_names.append(key_clean)

    content_length: int | None = None
    if "content-length" in headers:
        try:
            content_length = int(headers["content-length"])
        except ValueError:
            content_length = None

    content_type = headers.get("content-type")
    transfer_encoding = headers.get("transfer-encoding")
    payload_incomplete = bool(
        content_length is not None and content_length > len(body_bytes)
    )

    flow_dir = classify_direction(src_ip, dst_ip)
    if is_request:
        direction = f"{flow_dir}_request" if flow_dir != "unknown" else "request"
        return HttpMetadata(
            is_request=True,
            method=parts[0].upper(),
            host=headers.get("host"),
            uri=parts[1],
            user_agent=headers.get("user-agent"),
            content_length=content_length,
            payload_size=len(body_bytes),
            direction=direction,
            headers_present=header_names,
            content_type=content_type,
            transfer_encoding=transfer_encoding,
            payload_incomplete=payload_incomplete,
        )

    status_code: int | None = None
    try:
        status_code = int(parts[1])
    except ValueError:
        status_code = None

    direction = f"{flow_dir}_response" if flow_dir != "unknown" else "response"
    return HttpMetadata(
        is_request=False,
        host=headers.get("host"),
        content_length=content_length,
        payload_size=len(body_bytes),
        status_code=status_code,
        direction=direction,
        headers_present=header_names,
        content_type=content_type,
        transfer_encoding=transfer_encoding,
        payload_incomplete=payload_incomplete,
    )


def extract_tls_metadata(payload: bytes) -> TlsMetadata | None:
    """Extract observable TLS handshake metadata (SNI, versions, clear certificates)."""
    if not payload or len(payload) < 9:
        return None

    # TLS Record Layer: ContentType=0x16 (Handshake), LegacyVersion 0x0300..0x0304
    content_type = payload[0]
    record_ver_num = struct.unpack("!H", payload[1:3])[0]
    if content_type != 0x16 or record_ver_num not in TLS_VERSIONS:
        return None

    record_len = struct.unpack("!H", payload[3:5])[0]
    if record_len < 4:
        return None

    record_ver = TLS_VERSIONS[record_ver_num]
    hs_data = payload[5 : 5 + min(record_len, len(payload) - 5)]
    if len(hs_data) < 4:
        return TlsMetadata(record_version=record_ver)

    hs_type_num = hs_data[0]
    hs_type = TLS_HANDSHAKE_TYPES.get(hs_type_num, f"HandshakeType({hs_type_num})")
    meta = TlsMetadata(record_version=record_ver, handshake_type=hs_type)

    if hs_type_num == 1:
        _parse_client_hello(hs_data[4:], meta)
    elif hs_type_num == 2 and len(hs_data) >= 6:
        hs_ver_num = struct.unpack("!H", hs_data[4:6])[0]
        meta.handshake_version = TLS_VERSIONS.get(hs_ver_num, f"0x{hs_ver_num:04x}")
    elif hs_type_num == 11:
        _parse_certificate_message(hs_data[4:], meta)

    return meta


def _parse_client_hello(body: bytes, meta: TlsMetadata) -> None:
    """Safely parse TLS ClientHello body for version, SNI, and ALPN extensions."""
    if len(body) < 35:
        return

    client_ver_num = struct.unpack("!H", body[0:2])[0]
    meta.handshake_version = TLS_VERSIONS.get(client_ver_num, f"0x{client_ver_num:04x}")

    offset = 34  # 2 bytes version + 32 bytes random
    if offset >= len(body):
        return
    session_id_len = body[offset]
    offset += 1 + session_id_len

    if offset + 2 > len(body):
        return
    cipher_suites_len = struct.unpack("!H", body[offset : offset + 2])[0]
    offset += 2 + cipher_suites_len

    if offset + 1 > len(body):
        return
    compression_len = body[offset]
    offset += 1 + compression_len

    if offset + 2 > len(body):
        return
    extensions_len = struct.unpack("!H", body[offset : offset + 2])[0]
    offset += 2

    end = min(len(body), offset + extensions_len)
    while offset + 4 <= end:
        ext_type, ext_len = struct.unpack("!HH", body[offset : offset + 4])
        offset += 4
        if offset + ext_len > end:
            break
        ext_data = body[offset : offset + ext_len]

        if ext_type == 0x0000:
            meta.sni = _parse_sni_extension(ext_data)
        elif ext_type == 0x0010:
            meta.alpn = _parse_alpn_extension(ext_data)
        elif ext_type == 0x002B:
            _parse_supported_versions_extension(ext_data, meta)

        offset += ext_len


def _parse_sni_extension(ext_data: bytes) -> str | None:
    if len(ext_data) < 5:
        return None
    list_len = struct.unpack("!H", ext_data[0:2])[0]
    offset = 2
    end = min(len(ext_data), 2 + list_len)
    while offset + 3 <= end:
        name_type = ext_data[offset]
        name_len = struct.unpack("!H", ext_data[offset + 1 : offset + 3])[0]
        offset += 3
        if offset + name_len > end:
            break
        if name_type == 0:
            return ext_data[offset : offset + name_len].decode("utf-8", errors="replace").lower()
        offset += name_len
    return None


def _parse_alpn_extension(ext_data: bytes) -> list[str]:
    if len(ext_data) < 2:
        return []
    list_len = struct.unpack("!H", ext_data[0:2])[0]
    offset = 2
    end = min(len(ext_data), 2 + list_len)
    protocols: list[str] = []
    while offset < end:
        proto_len = ext_data[offset]
        offset += 1
        if offset + proto_len > end:
            break
        protocols.append(ext_data[offset : offset + proto_len].decode("utf-8", errors="replace"))
        offset += proto_len
    return protocols


def _parse_supported_versions_extension(ext_data: bytes, meta: TlsMetadata) -> None:
    if len(ext_data) < 3:
        return
    vec_len = ext_data[0]
    versions: list[int] = []
    for pos in range(1, min(len(ext_data), 1 + vec_len) - 1, 2):
        ver = struct.unpack("!H", ext_data[pos : pos + 2])[0]
        if ver in TLS_VERSIONS:
            versions.append(ver)
    if versions:
        highest = max(versions)
        meta.handshake_version = TLS_VERSIONS[highest]


def _parse_certificate_message(body: bytes, meta: TlsMetadata) -> None:
    """Extract subject, issuer, and expiry from the first unencrypted X.509 certificate."""
    if len(body) < 6:
        return
    # 3-byte total cert list length, then 3-byte first cert length
    first_cert_len = int.from_bytes(body[3:6], "big")
    if first_cert_len <= 0 or 6 + first_cert_len > len(body):
        return
    der_bytes = body[6 : 6 + first_cert_len]
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
        meta.certificate_subject = cert.subject.rfc4514_string()
        meta.certificate_issuer = cert.issuer.rfc4514_string()
        meta.certificate_not_after = cert.not_valid_after_utc.isoformat()
    except Exception:
        return
