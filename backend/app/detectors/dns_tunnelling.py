"""DNS tunnelling detector combining entropy, structural, response, timing, and window analysis."""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict

from app.detectors.base import BaseDetector
from app.models.detection import DetectionContext, DetectionFinding
from app.models.packet import NormalizedPacket
from app.utils.entropy import character_distribution_metrics, shannon_entropy

UNUSUAL_DNS_TYPES = {"TXT", "ANY", "NULL", "CNAME", "MX", "SRV", "DNSKEY", "HINFO"}


class DnsTunnellingDetector(BaseDetector):
    """Detect suspected DNS tunnelling using multi-indicator correlation."""

    detector_name = "dns_tunnelling"

    def detect(self, context: DetectionContext) -> list[DetectionFinding]:
        queries: dict[tuple[str | None, str | None, str], list[NormalizedPacket]] = defaultdict(
            list
        )
        responses: dict[tuple[str | None, str | None, str], list[NormalizedPacket]] = defaultdict(
            list
        )
        for pkt in context.packets:
            if pkt.dns is None or not pkt.dns.query_name:
                continue
            parent = pkt.dns.parent_domain or pkt.dns.query_name
            if pkt.dns.is_response:
                responses[(pkt.dst_ip, pkt.src_ip, parent)].append(pkt)
            else:
                queries[(pkt.src_ip, pkt.dst_ip, parent)].append(pkt)

        findings: list[DetectionFinding] = []
        for (src_ip, dst_ip, parent), pkts in sorted(queries.items()):
            resp_pkts = responses.get((src_ip, dst_ip, parent), [])
            finding = self._evaluate_domain_group(src_ip, dst_ip, parent, pkts, resp_pkts)
            if finding is not None:
                findings.append(finding)
        return findings

    def _evaluate_domain_group(
        self,
        src_ip: str | None,
        dst_ip: str | None,
        parent: str,
        pkts: list[NormalizedPacket],
        resp_pkts: list[NormalizedPacket],
    ) -> DetectionFinding | None:
        cfg = self.config
        ordered = sorted(pkts, key=lambda p: p.timestamp)
        subdomains = [
            ".".join(p.dns.subdomain_labels)
            for p in ordered
            if p.dns and p.dns.subdomain_labels
        ]
        qnames = [p.dns.query_name for p in ordered if p.dns and p.dns.query_name]

        entropies = [shannon_entropy(s) for s in subdomains] or [0.0]
        qname_entropies = [shannon_entropy(q) for q in qnames] or [0.0]
        max_entropy = max(entropies)
        avg_entropy = round(sum(entropies) / len(entropies), 4)
        avg_qname_entropy = round(sum(qname_entropies) / len(qname_entropies), 4)

        q_lengths = [p.dns.query_length for p in ordered if p.dns]
        sub_lengths = [p.dns.subdomain_length for p in ordered if p.dns]
        max_qlen = max(q_lengths, default=0)
        avg_qlen = round(sum(q_lengths) / len(q_lengths), 2) if q_lengths else 0.0
        max_sublen = max(sub_lengths, default=0)
        avg_sublen = round(sum(sub_lengths) / len(sub_lengths), 2) if sub_lengths else 0.0

        query_count = len(ordered)
        unique_subs = len(set(subdomains))
        unique_sub_ratio = round(unique_subs / query_count, 4) if query_count else 0.0

        unusual_type_count = sum(
            1
            for p in ordered
            if p.dns
            and (
                (p.dns.query_type or "").upper() in UNUSUAL_DNS_TYPES
                or (p.dns.query_type or "").upper().startswith("TYPE")
            )
        )
        txt_count = sum(
            1 for p in ordered if p.dns and (p.dns.query_type or "").upper() == "TXT"
        )
        unusual_type_ratio = round(unusual_type_count / query_count, 4) if query_count else 0.0

        # Repeated fixed-length chunked subdomain pattern
        repeated_chunk_pattern = False
        long_sub_lens = [s_len for s_len in sub_lengths if s_len >= 20]
        if len(long_sub_lens) >= 5 and unique_subs >= 5:
            if max(long_sub_lens) - min(long_sub_lens) <= 4:
                repeated_chunk_pattern = True

        # Encoded-looking pattern prevalence across all subdomains
        encoded_count = 0
        for sub in subdomains:
            if len(sub) < 16:
                continue
            cm = character_distribution_metrics(sub)
            if (
                cm["hex_ratio"] >= 0.75
                or cm["digit_ratio"] >= 0.30
                or cm["uppercase_ratio"] >= 0.25
            ):
                encoded_count += 1

        longest_sub = max(subdomains, key=len, default="")
        char_metrics = character_distribution_metrics(longest_sub)

        timestamps = [p.timestamp for p in ordered]
        span = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.0
        qpm = round((query_count / max(span, 1.0)) * 60.0, 2)

        # Time-window 10-second burst count
        max_10s_burst = 0
        for i, ts_start in enumerate(timestamps):
            cnt = 0
            for ts_cur in timestamps[i:]:
                if ts_cur - ts_start <= 10.0:
                    cnt += 1
                else:
                    break
            max_10s_burst = max(max_10s_burst, cnt)

        # Response size & query-to-response correlation
        resp_sizes = [
            p.dns.response_size_bytes or p.length
            for p in resp_pkts
            if p.dns
        ]
        max_resp_bytes = max(resp_sizes, default=0)
        avg_resp_bytes = round(sum(resp_sizes) / len(resp_sizes), 2) if resp_sizes else 0.0
        matched_resps = sum(
            1 for p in resp_pkts if p.dns and p.dns.matched_query_timestamp is not None
        )
        resp_ratio = round(len(resp_pkts) / query_count, 2) if query_count else 0.0

        # Query timing analysis
        mean_interval = 0.0
        interval_cv: float | None = None
        if len(timestamps) >= 3:
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
            mean_interval = round(sum(intervals) / len(intervals), 4)
            if mean_interval > 0:
                var = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
                interval_cv = round(math.sqrt(var) / mean_interval, 4)

        indicators: list[str] = []
        score = 0.0

        if max_entropy >= cfg.dns_min_entropy:
            indicators.append(
                f"High subdomain Shannon entropy (max={max_entropy}, avg={avg_entropy})"
            )
            score += 0.18
        if (
            max_qlen >= cfg.dns_min_query_length
            or avg_qlen >= cfg.dns_min_avg_query_length
            or max_sublen >= cfg.dns_min_subdomain_length
        ):
            indicators.append(
                f"Long DNS query/subdomain length (avg_qlen={avg_qlen}, max_qlen={max_qlen}, "
                f"max_sublen={max_sublen})"
            )
            score += 0.18
        if unique_subs >= cfg.dns_min_unique_subdomains and (
            unique_sub_ratio >= cfg.dns_min_unique_subdomain_ratio or unique_subs >= 10
        ):
            indicators.append(
                f"High unique subdomain fan-out ({unique_subs}/{query_count}, "
                f"ratio={unique_sub_ratio})"
            )
            score += 0.18
        if query_count >= cfg.dns_min_query_count or (
            query_count >= 4 and qpm >= cfg.dns_min_queries_per_minute
        ) or max_10s_burst >= 6:
            indicators.append(
                f"Elevated DNS query burst ({query_count} queries, ~{qpm}/min, "
                f"10s peak={max_10s_burst})"
            )
            score += 0.13
        if unusual_type_count >= cfg.dns_min_txt_count or (
            query_count >= 4 and unusual_type_ratio >= cfg.dns_min_txt_ratio
        ):
            indicators.append(
                f"Unusual DNS record distribution ({unusual_type_count}/{query_count}, "
                f"TXT={txt_count}, ratio={unusual_type_ratio:.0%})"
            )
            score += 0.14
        if encoded_count >= 3:
            indicators.append(
                f"Repeated encoded-looking subdomains ({encoded_count}/{len(subdomains)} queries)"
            )
            score += 0.13
        if repeated_chunk_pattern:
            indicators.append("Repeated fixed-width subdomain chunk pattern across unique queries")
            score += 0.08
        if max_resp_bytes >= 220:
            indicators.append(
                "Large DNS response payload observed "
                f"(max={max_resp_bytes} B, avg={avg_resp_bytes} B)"
            )
            score += 0.10
        if interval_cv is not None and interval_cv <= 0.30 and query_count >= 5:
            indicators.append(
                f"Automated query timing cadence (mean={mean_interval}s, CV={interval_cv})"
            )
            score += 0.08
        if parent in {d.lower() for d in cfg.dns_suspicious_parent_domains}:
            indicators.append(f"Parent domain {parent} matches suspicious domain list")
            score += 0.16

        # Never rely on a single indicator or entropy alone
        if len(indicators) < 2:
            return None

        confidence = round(min(0.98, score), 2)
        if confidence >= 0.78 and len(indicators) >= 4:
            severity = "CRITICAL"
        elif confidence >= 0.55 and len(indicators) >= 3:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        first_pkt = ordered[0]
        sample_queries = sorted({p.dns.query_name for p in ordered if p.dns and p.dns.query_name})[
            :8
        ]
        pkt_indices = sorted({p.packet_index for p in [*ordered[:200], *resp_pkts[:100]]})
        det_hash = hashlib.sha256(f"dns_tunnel:{src_ip}:{parent}".encode()).hexdigest()[:12]

        return DetectionFinding(
            detection_id=f"det-dnstun-{det_hash}",
            detection_name="Potential DNS Tunnelling Activity",
            detector_type=self.detector_name,
            severity=severity,
            confidence=confidence,
            timestamp=first_pkt.timestamp_utc,
            timestamp_epoch=first_pkt.timestamp,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=first_pkt.src_port,
            destination_port=first_pkt.dst_port or 53,
            protocol="DNS",
            packet_indices=pkt_indices,
            evidence={
                "parent_domain": parent,
                "query_count": query_count,
                "response_count": len(resp_pkts),
                "matched_response_count": matched_resps,
                "query_to_response_ratio": resp_ratio,
                "max_response_bytes": max_resp_bytes,
                "avg_response_bytes": avg_resp_bytes,
                "unique_subdomains": unique_subs,
                "unique_subdomain_ratio": unique_sub_ratio,
                "avg_query_length": avg_qlen,
                "max_query_length": max_qlen,
                "avg_subdomain_length": avg_sublen,
                "max_subdomain_length": max_sublen,
                "max_entropy": max_entropy,
                "avg_entropy": avg_entropy,
                "avg_query_name_entropy": avg_qname_entropy,
                "txt_count": txt_count,
                "txt_or_any_count": unusual_type_count,
                "txt_or_any_ratio": unusual_type_ratio,
                "encoded_subdomain_count": encoded_count,
                "repeated_chunk_pattern": repeated_chunk_pattern,
                "max_10s_burst_queries": max_10s_burst,
                "queries_per_minute_estimate": qpm,
                "mean_query_interval_seconds": mean_interval,
                "query_interval_cv": interval_cv,
                "character_distribution": char_metrics,
                "triggered_indicators": indicators,
                "sample_queries": sample_queries,
                "packet_indices": pkt_indices[:100],
            },
            explanation=(
                f"Observed {query_count} DNS queries and {len(resp_pkts)} responses from "
                f"{src_ip} toward parent domain '{parent}' triggering {len(indicators)} "
                "independent indicators: "
                + "; ".join(indicators)
                + ". Entropy or length alone does not prove DNS tunnelling; benign CDN, "
                "DNSSEC, or telemetry traffic can produce elevated label entropy."
            ),
            recommended_investigation_steps=[
                f"Inspect passive DNS and WHOIS/registrar age for '{parent}'.",
                (
                    f"Review process/command-line telemetry on source host {src_ip} "
                    f"around {first_pkt.timestamp_utc}."
                ),
                "Check DNS server logs for corresponding TXT/NULL response sizes.",
                (
                    f"Validate whether '{parent}' belongs to an approved security/EDR "
                    "or telemetry service."
                ),
            ],
            candidate_mitre_ids=["T1071.004", "T1048.003"],
        )
