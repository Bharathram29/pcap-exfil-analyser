"""Application configuration with typed, environment-overridable settings."""

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent


class Settings(BaseSettings):
    """Central configuration for the PCAP Exfiltration Analyser backend."""

    model_config = SettingsConfigDict(
        env_prefix="PCAP_ANALYSER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "PCAP Exfiltration Analyser"
    app_tagline: str = "From Raw Packets to Actionable Security Intelligence."
    app_version: str = "0.1.0"
    environment: str = "development"
    log_level: str = "INFO"
    json_logs: bool = False

    base_dir: Path = BACKEND_DIR
    project_root: Path = PROJECT_ROOT
    upload_dir: Path = Field(default_factory=lambda: BACKEND_DIR / "data" / "uploads")
    analyses_dir: Path = Field(default_factory=lambda: BACKEND_DIR / "data" / "analyses")
    reports_dir: Path = Field(default_factory=lambda: PROJECT_ROOT / "reports")
    rules_dir: Path = Field(default_factory=lambda: BACKEND_DIR / "rules")
    database_path: Path = Field(default_factory=lambda: BACKEND_DIR / "data" / "forensics.db")

    max_upload_size_bytes: int = 100 * 1024 * 1024  # 100 MiB default limit
    max_packets_per_capture: int | None = None
    max_stored_packets_per_analysis: int = 100_000
    flow_idle_timeout_seconds: float = 120.0
    correlation_time_window_seconds: float = 300.0
    correlation_match_source_port: bool = False
    correlation_match_destination_port: bool = False
    correlation_match_protocol: bool = False
    correlation_match_rule: bool = False

    # Optional API authentication (open in local dev when unset; enforced when set)
    api_key: SecretStr | None = None

    # Optional external threat intelligence enrichment (never blocks core PCAP analysis)
    threat_intel_enabled: bool = False
    threat_intel_enable_dns_whois: bool = False
    threat_intel_timeout_seconds: float = 3.0
    threat_intel_cache_ttl_seconds: int = 3600
    threat_intel_max_lookups: int = 15
    virustotal_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
        ]
    )

    def ensure_directories(self) -> None:
        """Create required runtime directories if they do not exist."""
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.analyses_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    """Return a fresh Settings instance."""
    return Settings()
