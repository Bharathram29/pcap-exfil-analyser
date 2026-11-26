"""Base detector contract and configurable heuristic threshold definitions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, fields
from pathlib import Path

import yaml

from app.models.detection import DetectionContext, DetectionFinding


@dataclass(slots=True)
class DetectorConfig:
    """Configurable thresholds for all statistical and behavioral detectors."""

    # DNS Tunnelling
    dns_min_query_length: int = 50
    dns_min_avg_query_length: float = 42.0
    dns_min_subdomain_length: int = 30
    dns_min_entropy: float = 3.5
    dns_min_unique_subdomains: int = 5
    dns_min_unique_subdomain_ratio: float = 0.7
    dns_min_query_count: int = 6
    dns_min_queries_per_minute: float = 20.0
    dns_min_txt_count: int = 3
    dns_min_txt_ratio: float = 0.5
    dns_suspicious_parent_domains: list[str] = field(default_factory=list)

    # Outbound Data Exfiltration
    exfil_min_outbound_bytes: int = 100_000
    exfil_min_ratio: float = 4.0
    exfil_min_duration_seconds: float = 0.0
    exfil_long_session_seconds: float = 30.0
    exfil_repeated_flow_threshold: int = 3
    exfil_staged_min_flows: int = 5
    exfil_staged_min_flow_bytes: int = 4_000
    exfil_staged_min_total_bytes: int = 30_000
    exfil_high_frequency_fpm: float = 12.0

    # HTTP Upload & Request Analysis
    http_large_payload_bytes: int = 50_000
    http_repeated_upload_count: int = 3
    http_high_frequency_rpm: float = 30.0
    http_standard_ports: set[int] = field(default_factory=lambda: {80, 8080, 8000, 8008})
    http_suspicious_user_agents: list[str] = field(
        default_factory=lambda: [
            "curl/",
            "wget/",
            "python-requests",
            "python-urllib",
            "powershell",
            "go-http-client",
            "syntheticuploader",
            "exfilclient",
            "masscan",
            "sqlmap",
        ]
    )
    http_suspicious_content_types: list[str] = field(
        default_factory=lambda: [
            "application/octet-stream",
            "application/x-gzip",
            "application/zip",
            "application/x-tar",
        ]
    )

    # Network Beaconing
    beacon_min_connections: int = 4
    beacon_max_interval_cv: float = 0.25
    beacon_min_mean_interval_seconds: float = 1.0
    beacon_max_byte_cv: float = 0.35
    beacon_allow_capture_gaps: bool = True
    beacon_max_gap_multiplier: int = 4

    # Suspicious Ports
    suspicious_ports: dict[int, str] = field(
        default_factory=lambda: {
            1080: "SOCKS Proxy",
            1337: "Common C2 / Backdoor Port",
            2222: "Alternate SSH / Tunnel Port",
            4444: "Common Reverse Shell / Metasploit Default",
            5555: "Common Remote Shell / ADB Port",
            6666: "IRC / Potential Botnet C2",
            6667: "IRC / Potential Botnet C2",
            8888: "Alternate HTTP / Proxy",
            9001: "Tor ORPort / Alternate C2",
            9050: "Tor SOCKS Proxy",
            31337: "Back Orifice / Legacy Backdoor Port",
        }
    )

    # Protocol Anomalies
    icmp_large_payload_bytes: int = 128
    icmp_high_packet_count: int = 15
    dns_nxdomain_min_count: int = 5
    dns_nxdomain_min_ratio: float = 0.4
    syn_scan_unanswered_threshold: int = 5
    tcp_high_retransmission_threshold: int = 5
    arp_gratuitous_burst_threshold: int = 15

    @classmethod
    def from_yaml(cls, config_path: Path) -> DetectorConfig:
        """Load overrides from a YAML file, falling back cleanly to defaults."""
        cfg = cls()
        if not config_path.is_file():
            return cfg
        try:
            raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            return cfg
        if not isinstance(raw, dict):
            return cfg

        valid_fields = {f.name for f in fields(cls)}
        for key, val in raw.items():
            if key not in valid_fields:
                continue
            if key == "http_standard_ports" and isinstance(val, list):
                setattr(cfg, key, {int(x) for x in val})
            elif key == "suspicious_ports" and isinstance(val, dict):
                setattr(cfg, key, {int(k): str(v) for k, v in val.items()})
            else:
                setattr(cfg, key, val)
        return cfg


class BaseDetector(ABC):
    """Abstract interface implemented by all heuristic and ML-ready detectors."""

    detector_name: str = "base"

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()

    @abstractmethod
    def detect(self, context: DetectionContext) -> list[DetectionFinding]:
        """Inspect normalized packets and flows and return explainable findings."""
