"""Domain models for reconstructed bidirectional network flows."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class NetworkFlow:
    """Bidirectional network conversation reconstructed from normalized packets."""

    flow_id: str
    transport_protocol: str
    application_protocol: str
    initiator_ip: str
    initiator_port: int | None
    responder_ip: str
    responder_port: int | None
    direction: str

    packets_initiator_to_responder: int = 0
    packets_responder_to_initiator: int = 0
    bytes_initiator_to_responder: int = 0
    bytes_responder_to_initiator: int = 0

    first_seen: float = 0.0
    last_seen: float = 0.0
    first_seen_utc: str = ""
    last_seen_utc: str = ""
    duration_seconds: float = 0.0

    total_packets: int = 0
    total_bytes: int = 0
    avg_packet_size: float = 0.0
    min_packet_size: int = 0
    max_packet_size: int = 0
    std_packet_size: float = 0.0
    mean_iat_seconds: float | None = None
    min_iat_seconds: float | None = None
    max_iat_seconds: float | None = None
    std_iat_seconds: float | None = None
    outbound_to_inbound_ratio: float | None = None

    tcp_flags_distribution: dict[str, int] = field(default_factory=dict)
    connection_state: str = "UNKNOWN"
    state_basis: str = "inferred"
    handshake_completed: bool = False
    is_midstream: bool = False
    retransmission_count: int = 0

    observed_dns_queries: list[str] = field(default_factory=list)
    observed_http_hosts: list[str] = field(default_factory=list)
    observed_http_methods: list[str] = field(default_factory=list)
    observed_tls_snis: list[str] = field(default_factory=list)
    packet_indices: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize flow record to a JSON-compatible dictionary."""
        return asdict(self)


@dataclass(slots=True)
class FlowReconstructionResult:
    """Aggregate output of flow reconstruction across a capture."""

    flows: list[NetworkFlow]
    total_flows: int
    total_flow_packets: int
    total_flow_bytes: int
    skipped_non_ip_packets: int
    unique_source_ips: int
    unique_destination_ips: int
    packet_flow_map: dict[int, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_flows": self.total_flows,
            "total_flow_packets": self.total_flow_packets,
            "total_flow_bytes": self.total_flow_bytes,
            "skipped_non_ip_packets": self.skipped_non_ip_packets,
            "unique_source_ips": self.unique_source_ips,
            "unique_destination_ips": self.unique_destination_ips,
            "flows": [flow.to_dict() for flow in self.flows],
        }
