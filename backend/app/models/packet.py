"""Domain models representing ingested captures and normalized packet metadata."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class CaptureMetadata:
    """Forensic provenance and structural metadata for an ingested PCAP/PCAPNG file."""

    analysis_id: str
    original_filename: str
    sanitized_filename: str
    stored_path: str
    file_size_bytes: int
    sha256: str
    capture_format: str
    ingested_at_utc: str
    link_layer_type: int | None = None
    link_layer_name: str | None = None
    supported_link_layer: bool = True
    packet_count: int = 0
    malformed_packet_count: int = 0
    is_empty: bool = False
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize metadata to a JSON-compatible dictionary."""
        return asdict(self)


@dataclass(slots=True)
class DnsMetadata:
    """Observable DNS query/response metadata extracted from a packet."""

    transaction_id: int | None
    is_response: bool
    query_name: str | None
    query_type: str | None
    response_code: str | None = None
    response_ips: list[str] = field(default_factory=list)
    query_length: int = 0
    subdomain_labels: list[str] = field(default_factory=list)
    subdomain_length: int = 0
    parent_domain: str | None = None
    label_count: int = 0
    matched_query_timestamp: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class HttpMetadata:
    """Observable HTTP/1.x request or response metadata."""

    is_request: bool
    method: str | None = None
    host: str | None = None
    uri: str | None = None
    user_agent: str | None = None
    content_length: int | None = None
    payload_size: int = 0
    status_code: int | None = None
    direction: str = "unknown"
    headers_present: list[str] = field(default_factory=list)
    content_type: str | None = None
    transfer_encoding: str | None = None
    payload_incomplete: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TlsMetadata:
    """Observable TLS handshake metadata without claiming payload decryption."""

    record_version: str | None = None
    handshake_version: str | None = None
    handshake_type: str | None = None
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    certificate_not_after: str | None = None
    encrypted_payload_not_inspected: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TcpMetadata:
    """TCP header flags, sequence tracking, and retransmission indicators."""

    seq: int | None = None
    ack: int | None = None
    flags: int = 0
    flag_names: str = ""
    window_size: int | None = None
    payload_size: int = 0
    is_syn: bool = False
    is_syn_ack: bool = False
    is_fin: bool = False
    is_rst: bool = False
    is_retransmission: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class NormalizedPacket:
    """Protocol-normalized representation of a single captured packet."""

    packet_index: int
    timestamp: float
    timestamp_utc: str
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str
    transport_protocol: str | None
    length: int
    ttl: int | None
    ip_version: int | None
    is_malformed: bool = False
    missing_fields: list[str] = field(default_factory=list)
    dns: DnsMetadata | None = None
    http: HttpMetadata | None = None
    tls: TlsMetadata | None = None
    tcp: TcpMetadata | None = None
    raw_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ParsedCaptureResult:
    """Container holding capture metadata and normalized packets."""

    metadata: CaptureMetadata
    packets: list[NormalizedPacket]
