"""Optional, modular external Threat Intelligence enrichment service."""

from __future__ import annotations

import socket
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml

from app.core.config import Settings
from app.core.logging import get_logger
from app.utils.network import is_external_ip, is_internal_ip

logger = get_logger("services.threat_intel")


@dataclass(slots=True)
class ThreatIntelIndicatorResult:
    """Supplemental external intelligence result kept strictly separate from packet facts."""

    indicator: str
    indicator_type: str  # "ip" | "domain"
    provider: str
    reputation: str  # "malicious" | "suspicious" | "clean" | "unknown" | "private_reserved"
    confidence: float
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    source_type: str = "EXTERNAL_THREAT_INTEL"
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ThreatIntelProvider(ABC):
    """Base contract for pluggable threat intelligence enrichment providers."""

    provider_name: str = "base"

    @abstractmethod
    def lookup_ip(self, ip: str) -> ThreatIntelIndicatorResult | None:
        """Query reputation or context for an external IP address."""

    @abstractmethod
    def lookup_domain(self, domain: str) -> ThreatIntelIndicatorResult | None:
        """Query reputation or context for a domain name."""


class LocalFeedProvider(ThreatIntelProvider):
    """Offline local indicator list (YAML) for custom known-bad IPs/domains."""

    provider_name = "local_ioc_feed"

    def __init__(self, feed_path: Path) -> None:
        self.bad_ips: dict[str, str] = {}
        self.bad_domains: dict[str, str] = {}
        if feed_path.is_file():
            try:
                raw = yaml.safe_load(feed_path.read_text(encoding="utf-8")) or {}
                if isinstance(raw, dict):
                    for item in raw.get("malicious_ips", []):
                        if isinstance(item, dict) and item.get("ip"):
                            self.bad_ips[str(item["ip"]).strip()] = str(
                                item.get("reason", "Listed in local IOC feed")
                            )
                    for item in raw.get("malicious_domains", []):
                        if isinstance(item, dict) and item.get("domain"):
                            self.bad_domains[str(item["domain"]).strip().lower()] = str(
                                item.get("reason", "Listed in local IOC feed")
                            )
            except Exception as exc:
                logger.warning("Failed to load local threat intel feed: %s", exc)

    def lookup_ip(self, ip: str) -> ThreatIntelIndicatorResult | None:
        reason = self.bad_ips.get(ip)
        if not reason:
            return None
        return ThreatIntelIndicatorResult(
            indicator=ip,
            indicator_type="ip",
            provider=self.provider_name,
            reputation="malicious",
            confidence=0.85,
            summary=reason,
            details={"feed": "local_ioc_feed"},
        )

    def lookup_domain(self, domain: str) -> ThreatIntelIndicatorResult | None:
        reason = self.bad_domains.get(domain.lower().rstrip("."))
        if not reason:
            return None
        return ThreatIntelIndicatorResult(
            indicator=domain,
            indicator_type="domain",
            provider=self.provider_name,
            reputation="malicious",
            confidence=0.85,
            summary=reason,
            details={"feed": "local_ioc_feed"},
        )


class AbuseIpDbProvider(ThreatIntelProvider):
    """AbuseIPDB v2 API lookup using SecretStr credentials and strict timeout."""

    provider_name = "abuseipdb"

    def __init__(self, api_key: str, timeout: float = 3.0) -> None:
        self._api_key = api_key
        self._timeout = timeout

    def lookup_ip(self, ip: str) -> ThreatIntelIndicatorResult | None:
        try:
            resp = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Key": self._api_key, "Accept": "application/json"},
                timeout=self._timeout,
            )
            if resp.status_code == 429:
                logger.warning("AbuseIPDB rate limit reached for lookup.")
                return None
            if resp.status_code != 200:
                return None
            data = resp.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            rep = "malicious" if score >= 75 else ("suspicious" if score >= 25 else "clean")
            return ThreatIntelIndicatorResult(
                indicator=ip,
                indicator_type="ip",
                provider=self.provider_name,
                reputation=rep,
                confidence=round(min(0.95, max(0.3, score / 100.0)), 2),
                summary=f"AbuseIPDB confidence={score}%, reports={data.get('totalReports', 0)}",
                details={
                    "abuse_confidence_score": score,
                    "isp": data.get("isp"),
                    "country_code": data.get("countryCode"),
                    "usage_type": data.get("usageType"),
                },
            )
        except Exception as exc:
            logger.debug("AbuseIPDB lookup skipped for %s: %s", ip, exc)
            return None

    def lookup_domain(self, domain: str) -> ThreatIntelIndicatorResult | None:
        return None


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal v3 API lookup for external IPs and domains."""

    provider_name = "virustotal"

    def __init__(self, api_key: str, timeout: float = 3.0) -> None:
        self._api_key = api_key
        self._timeout = timeout

    def lookup_ip(self, ip: str) -> ThreatIntelIndicatorResult | None:
        return self._query(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", ip, "ip")

    def lookup_domain(self, domain: str) -> ThreatIntelIndicatorResult | None:
        return self._query(f"https://www.virustotal.com/api/v3/domains/{domain}", domain, "domain")

    def _query(
        self, url: str, indicator: str, indicator_type: str
    ) -> ThreatIntelIndicatorResult | None:
        try:
            resp = httpx.get(
                url,
                headers={"x-apikey": self._api_key},
                timeout=self._timeout,
            )
            if resp.status_code == 429 or resp.status_code != 200:
                return None
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            mal = int(stats.get("malicious", 0))
            susp = int(stats.get("suspicious", 0))
            rep = "malicious" if mal >= 3 else ("suspicious" if (mal + susp) >= 1 else "clean")
            return ThreatIntelIndicatorResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.provider_name,
                reputation=rep,
                confidence=0.85 if mal >= 3 else 0.65,
                summary=f"VirusTotal detections: malicious={mal}, suspicious={susp}",
                details={
                    "last_analysis_stats": stats,
                    "as_owner": attrs.get("as_owner"),
                    "country": attrs.get("country"),
                },
            )
        except Exception as exc:
            logger.debug("VirusTotal lookup skipped for %s: %s", indicator, exc)
            return None


class RdapDnsProvider(ThreatIntelProvider):
    """Optional RDAP WHOIS and reverse/forward DNS context lookup."""

    provider_name = "rdap_dns"

    def __init__(self, timeout: float = 3.0) -> None:
        self._timeout = timeout

    def lookup_ip(self, ip: str) -> ThreatIntelIndicatorResult | None:
        details: dict[str, Any] = {}
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            details["ptr_record"] = host
        except OSError:
            pass
        try:
            resp = httpx.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=self._timeout)
            if resp.status_code == 200:
                body = resp.json()
                details["rdap_name"] = body.get("name")
                details["rdap_country"] = body.get("country")
                details["rdap_handle"] = body.get("handle")
        except Exception as exc:
            logger.debug("RDAP lookup skipped for %s: %s", ip, exc)
        if not details:
            return None
        return ThreatIntelIndicatorResult(
            indicator=ip,
            indicator_type="ip",
            provider=self.provider_name,
            reputation="unknown",
            confidence=0.50,
            summary=f"WHOIS/DNS context: {details.get('rdap_name') or details.get('ptr_record')}",
            details=details,
        )

    def lookup_domain(self, domain: str) -> ThreatIntelIndicatorResult | None:
        try:
            infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
            ips = sorted({str(info[4][0]) for info in infos})[:8]
            if not ips:
                return None
            return ThreatIntelIndicatorResult(
                indicator=domain,
                indicator_type="domain",
                provider=self.provider_name,
                reputation="unknown",
                confidence=0.50,
                summary=f"Current DNS resolution: {', '.join(ips)}",
                details={"resolved_ips": ips},
            )
        except OSError:
            return None


class ThreatIntelService:
    """Coordinate cached, rate-limited, non-blocking threat intelligence enrichment."""

    def __init__(
        self,
        settings: Settings,
        providers: list[ThreatIntelProvider] | None = None,
    ) -> None:
        self.settings = settings
        self._cache: dict[tuple[str, str, str], tuple[float, ThreatIntelIndicatorResult]] = {}
        if providers is not None:
            self.providers = providers
        else:
            self.providers = self._build_default_providers(settings)

    def _build_default_providers(self, settings: Settings) -> list[ThreatIntelProvider]:
        items: list[ThreatIntelProvider] = [
            LocalFeedProvider(settings.rules_dir / "threat_intel_indicators.yaml")
        ]
        if settings.threat_intel_enabled:
            if settings.virustotal_api_key is not None:
                items.append(
                    VirusTotalProvider(
                        settings.virustotal_api_key.get_secret_value(),
                        timeout=settings.threat_intel_timeout_seconds,
                    )
                )
            if settings.abuseipdb_api_key is not None:
                items.append(
                    AbuseIpDbProvider(
                        settings.abuseipdb_api_key.get_secret_value(),
                        timeout=settings.threat_intel_timeout_seconds,
                    )
                )
            if settings.threat_intel_enable_dns_whois:
                items.append(RdapDnsProvider(timeout=settings.threat_intel_timeout_seconds))
        return items

    def enrich_indicators(
        self,
        ips: list[str],
        domains: list[str],
    ) -> dict[str, Any]:
        """Enrich external IPs and domains without ever blocking core PCAP analysis."""
        results: list[dict[str, Any]] = []
        skipped_private: list[str] = []
        lookups_done = 0
        max_lookups = max(1, self.settings.threat_intel_max_lookups)

        for ip in sorted(set(ips)):
            if is_internal_ip(ip) or not is_external_ip(ip):
                skipped_private.append(ip)
                results.append(
                    ThreatIntelIndicatorResult(
                        indicator=ip,
                        indicator_type="ip",
                        provider="policy_guard",
                        reputation="private_reserved",
                        confidence=1.0,
                        summary="Private/reserved IP excluded from external malicious reputation.",
                    ).to_dict()
                )
                continue
            if lookups_done >= max_lookups:
                break
            lookups_done += 1
            for prov in self.providers:
                res = self._cached_lookup(prov, "ip", ip)
                if res is not None:
                    results.append(res.to_dict())

        for dom in sorted({d.lower().rstrip(".") for d in domains if d}):
            if lookups_done >= max_lookups:
                break
            lookups_done += 1
            for prov in self.providers:
                res = self._cached_lookup(prov, "domain", dom)
                if res is not None:
                    results.append(res.to_dict())

        return {
            "enabled": self.settings.threat_intel_enabled,
            "providers_configured": [p.provider_name for p in self.providers],
            "source_label": "EXTERNAL_THREAT_INTEL",
            "disclaimer": (
                "External threat intelligence is supplemental context and is strictly separate "
                "from packet-derived forensic evidence. Private/reserved IPs are never flagged "
                "as malicious by external reputation checks."
            ),
            "skipped_private_ips": skipped_private,
            "results": results,
        }

    def _cached_lookup(
        self,
        provider: ThreatIntelProvider,
        ind_type: str,
        value: str,
    ) -> ThreatIntelIndicatorResult | None:
        now = time.monotonic()
        ckey = (provider.provider_name, ind_type, value)
        cached = self._cache.get(ckey)
        if cached is not None:
            expires_at, prev_res = cached
            if now < expires_at:
                return ThreatIntelIndicatorResult(
                    indicator=prev_res.indicator,
                    indicator_type=prev_res.indicator_type,
                    provider=prev_res.provider,
                    reputation=prev_res.reputation,
                    confidence=prev_res.confidence,
                    summary=prev_res.summary,
                    details=dict(prev_res.details),
                    source_type=prev_res.source_type,
                    cached=True,
                )

        res = provider.lookup_ip(value) if ind_type == "ip" else provider.lookup_domain(value)
        if res is not None:
            ttl = max(1.0, float(self.settings.threat_intel_cache_ttl_seconds))
            if len(self._cache) > 2000:
                self._cache.clear()
            self._cache[ckey] = (now + ttl, res)
        return res
