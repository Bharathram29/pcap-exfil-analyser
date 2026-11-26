"""Allowlist loader and matcher preserving suppressed alerts for analyst review."""

from __future__ import annotations

import fnmatch
import ipaddress
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError

from app.core.logging import get_logger
from app.models.alert import AllowlistMatch
from app.models.detection import DetectionFinding
from app.utils.network import is_internal_ip

logger = get_logger("services.allowlist")


class TrustedDomainEntry(BaseModel):
    pattern: str = Field(min_length=1)
    reason: str = "Trusted domain"


class TrustedIpEntry(BaseModel):
    ip: str = Field(min_length=1)
    reason: str = "Trusted IP"


class InternalRangeEntry(BaseModel):
    cidr: str = Field(min_length=1)
    suppress_internal_only: bool = True
    reason: str = "Internal network range"


class ApprovedServiceEntry(BaseModel):
    name: str = Field(min_length=1)
    ip: str | None = None
    domain: str | None = None
    port: int | None = None
    protocol: str | None = None
    reason: str = "Approved service"


class MonitoringSystemEntry(BaseModel):
    name: str = Field(min_length=1)
    cidr: str = Field(min_length=1)
    reason: str = "Known monitoring system"


class ExclusionEntry(BaseModel):
    id: str = Field(min_length=1)
    rule_id: str | None = None
    detector_type: str | None = None
    ip: str | None = None
    domain: str | None = None
    port: int | None = None
    internal_only: bool = False
    reason: str = "Configured exclusion"


class AllowlistConfig(BaseModel):
    """Validated schema for rules/allowlist.yaml."""

    version: str = "1.0"
    description: str = ""
    trusted_domains: list[TrustedDomainEntry] = Field(default_factory=list)
    trusted_ips: list[TrustedIpEntry] = Field(default_factory=list)
    internal_network_ranges: list[InternalRangeEntry] = Field(default_factory=list)
    approved_services: list[ApprovedServiceEntry] = Field(default_factory=list)
    known_monitoring_systems: list[MonitoringSystemEntry] = Field(default_factory=list)
    exclusions: list[ExclusionEntry] = Field(default_factory=list)


def _ip_in_cidr(ip_str: str | None, cidr_str: str) -> bool:
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        net = ipaddress.ip_network(cidr_str, strict=False)
        return addr in net
    except ValueError:
        return False


def _domain_matches(candidate: str, pattern: str) -> bool:
    c = candidate.strip().lower().rstrip(".")
    p = pattern.strip().lower().rstrip(".")
    if p.startswith("*."):
        base = p[2:]
        return c == base or c.endswith(f".{base}")
    return fnmatch.fnmatch(c, p)


def _extract_candidate_domains(finding: DetectionFinding) -> list[str]:
    ev = finding.evidence
    domains: list[str] = []
    for key in ("parent_domain",):
        if isinstance(ev.get(key), str):
            domains.append(ev[key])
    for list_key in (
        "observed_tls_snis",
        "observed_http_hosts",
        "sample_queries",
        "sample_domains",
    ):
        vals = ev.get(list_key)
        if isinstance(vals, list):
            for v in vals:
                if isinstance(v, str):
                    domains.append(v.split(":", 1)[0])
    sample_reqs = ev.get("sample_requests")
    if isinstance(sample_reqs, list):
        for req in sample_reqs:
            if isinstance(req, dict) and isinstance(req.get("host"), str):
                domains.append(req["host"].split(":", 1)[0])
    sample_attrs = ev.get("sample_attributes")
    if isinstance(sample_attrs, dict):
        for attr_key in ("host", "query_name", "sni"):
            if isinstance(sample_attrs.get(attr_key), str):
                domains.append(sample_attrs[attr_key].split(":", 1)[0])
    return sorted({d.lower() for d in domains if d})


class AllowlistManager:
    """Evaluate alerts/findings against allowlist rules without discarding events."""

    def __init__(self, config: AllowlistConfig | None = None) -> None:
        self.config = config or AllowlistConfig()
        self.load_errors: list[str] = []

    @classmethod
    def from_yaml(cls, allowlist_path: Path) -> AllowlistManager:
        manager = cls()
        if not allowlist_path.is_file():
            manager.load_errors.append(f"Allowlist file not found: {allowlist_path}")
            return manager
        try:
            raw: Any = yaml.safe_load(allowlist_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            msg = f"Failed to parse allowlist YAML {allowlist_path.name}: {exc}"
            logger.error(msg)
            manager.load_errors.append(msg)
            return manager

        if not isinstance(raw, dict):
            manager.load_errors.append("Allowlist root must be a YAML mapping.")
            return manager

        try:
            manager.config = AllowlistConfig.model_validate(raw)
        except ValidationError as exc:
            msg = f"Allowlist validation error: {exc.errors()[0]['msg']}"
            logger.warning(msg)
            manager.load_errors.append(msg)
        return manager

    def check_finding(self, finding: DetectionFinding) -> AllowlistMatch | None:
        """Return an AllowlistMatch if the finding matches any configured allowlist rule."""
        src = finding.source_ip
        dst = finding.destination_ip
        domains = _extract_candidate_domains(finding)

        # 1. Known monitoring systems (source or destination inside monitoring CIDR)
        for mon in self.config.known_monitoring_systems:
            if _ip_in_cidr(src, mon.cidr) or _ip_in_cidr(dst, mon.cidr):
                return AllowlistMatch(
                    category="known_monitoring_system",
                    matched_entry=f"{mon.name} ({mon.cidr})",
                    reason=mon.reason,
                )

        # 2. Trusted IPs
        for tip in self.config.trusted_ips:
            if src == tip.ip or dst == tip.ip:
                return AllowlistMatch(
                    category="trusted_ip",
                    matched_entry=tip.ip,
                    reason=tip.reason,
                )

        # 3. Approved services (destination IP/domain + port/protocol match)
        for svc in self.config.approved_services:
            ip_ok = svc.ip is None or dst == svc.ip
            port_ok = svc.port is None or finding.destination_port == svc.port
            proto_ok = (
                svc.protocol is None or finding.protocol.upper() == svc.protocol.upper()
            )
            domain_ok = svc.domain is None or any(
                _domain_matches(d, svc.domain) for d in domains
            )
            if ip_ok and port_ok and proto_ok and domain_ok and (svc.ip or svc.domain):
                return AllowlistMatch(
                    category="approved_service",
                    matched_entry=svc.name,
                    reason=svc.reason,
                )

        # 4. Trusted domains (all candidate domains must be trusted if domains exist)
        if domains:
            matched_domains: list[tuple[str, str, str]] = []
            for dom in domains:
                match_td = next(
                    (td for td in self.config.trusted_domains if _domain_matches(dom, td.pattern)),
                    None,
                )
                if match_td is None:
                    matched_domains = []
                    break
                matched_domains.append((dom, match_td.pattern, match_td.reason))
            if matched_domains:
                first_dom, first_pat, first_reason = matched_domains[0]
                return AllowlistMatch(
                    category="trusted_domain",
                    matched_entry=f"{first_dom} (pattern {first_pat})",
                    reason=first_reason,
                )

        # 5. Internal-only network ranges
        if is_internal_ip(src) and is_internal_ip(dst):
            for net_entry in self.config.internal_network_ranges:
                if net_entry.suppress_internal_only and (
                    _ip_in_cidr(src, net_entry.cidr) and _ip_in_cidr(dst, net_entry.cidr)
                ):
                    return AllowlistMatch(
                        category="internal_network_range",
                        matched_entry=net_entry.cidr,
                        reason=net_entry.reason,
                    )

        # 6. Configurable exclusions
        for excl in self.config.exclusions:
            if excl.rule_id and finding.rule_id != excl.rule_id:
                continue
            if excl.detector_type and finding.detector_type != excl.detector_type:
                continue
            if excl.port is not None and finding.destination_port != excl.port:
                continue
            if excl.ip and excl.ip not in {src, dst}:
                continue
            if excl.domain and not any(_domain_matches(d, excl.domain) for d in domains):
                continue
            if excl.internal_only and not (is_internal_ip(src) and is_internal_ip(dst)):
                continue
            return AllowlistMatch(
                category="exclusion",
                matched_entry=excl.id,
                reason=excl.reason,
            )

        return None
