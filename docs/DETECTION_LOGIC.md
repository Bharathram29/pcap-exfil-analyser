# Detection Logic, Correlation & Scoring Methodology

## 1. Philosophy: Evidence-Driven Multi-Indicator Detection

The detection engine combines **statistical behavioral heuristics** (`backend/app/detectors/`) with **configurable YAML rules** (`backend/rules/detection_rules.yaml`) and **audit-preserving allowlists** (`backend/rules/allowlist.yaml`). Every finding separates:

1. **Confirmed Observations:** Packet counts, byte volumes, ports, DNS query lengths, HTTP headers, TLS handshake metadata (`SNI`, `ALPN`, versions, unencrypted certificates).
2. **Suspicious Indicators:** Multi-signal statistical or rule-based anomalies.
3. **Inferred Conclusions:** Correlated incidents and MITRE ATT&CK mappings requiring host/EDR corroboration.

## 2. Heuristic Detection Modules (`DetectorConfig`)

Thresholds are defined in `app/detectors/base.py` (`DetectorConfig`) and optionally overridden via `rules/detector_config.yaml`.

### A. DNS Tunnelling (`app/detectors/dns_tunnelling.py`)
Groups DNS queries by `(src_ip, dst_ip, parent_domain)` and evaluates:
- Subdomain and full-query Shannon entropy (`max_entropy`, `avg_entropy`, `avg_query_name_entropy`)
- Average & maximum query/subdomain lengths
- Unique subdomain count & `unique_subdomain_ratio`
- Query burst frequency (`queries_per_minute_estimate`) & inter-query timing regularity (`query_interval_cv`)
- `TXT`/`ANY`/`NULL`/`CNAME` record ratio
- Prevalence of encoded-looking subdomains (hex/digit/uppercase ratios across all labels)
- **Gate:** Requires `>= 2` independent indicators; entropy alone never alerts.

### B. Outbound Data Exfiltration (`app/detectors/outbound_exfiltration.py`)
Aggregates outbound external flows per `(initiator_ip, responder_ip)`:
- Outbound byte volume & outbound-to-inbound byte ratio
- **Staged small transfers:** Detects `>= 5` smaller asymmetric flows (`>= 4,000 B` each, `>= 30,000 B` total, ratio `>= 4.0`)
- Transfer frequency (`flows_per_minute`), long session duration, non-standard/high-risk ports, and repeated HTTP `POST`/`PUT`/`PATCH` uploads.

### C. HTTP Upload & Request Analysis (`app/detectors/http_upload.py`)
Inspects HTTP/1.x requests grouped by `(src_ip, dst_ip, dst_port)`:
- Large `POST`/`PUT`/`PATCH` request bodies (`Content-Length` or observed body size) and flags `payload_incomplete` when `Content-Length` exceeds the captured first segment
- Raw-IP `Host` headers, non-standard ports, uncommon methods (`PUT`, `DELETE`, `TRACE`, `CONNECT`)
- Suspicious `User-Agent` patterns, binary/archive `Content-Type` uploads, request frequency, and response-byte totals
- Never claims to inspect encrypted HTTPS payloads.

### D. Gap-Tolerant Network Beaconing (`app/detectors/beaconing.py`)
Groups outbound external flows by `(initiator_ip, responder_ip, responder_port)` (`>= 4` sessions):
- Computes inter-connection intervals and Coefficient of Variation (`CV = std / mean`).
- When raw `CV` exceeds `0.25`, tests whether intervals align with integer multiples ($1\times$..$4\times$) of a fundamental period $T_0$ to handle **missed packets or capture gaps**, then applies a **confidence penalty** proportional to `missed_beacon_gaps`.
- Also evaluates payload size consistency (`byte_cv`), connection duration statistics, and `SYN_ONLY_UNANSWERED` retry loops.

### E. Suspicious Ports (`app/detectors/suspicious_ports.py`)
Contextualises connections to configurable high-risk ports (`1080`, `1337`, `2222`, `4444`, `5555`, `6666`, `6667`, `8888`, `9001`, `9050`, `31337`) by external destination, outbound volume, and flow count.

### F. Protocol Anomalies (`app/detectors/protocol_anomaly.py`)
- Protocol/port mismatches (HTTP on `443`, DNS on non-standard ports, TLS on `80`, high-volume outbound UDP on `22`/`80`/`443`)
- Oversized (`>= 128 B`) or high-volume (`>= 15`) external ICMP traffic
- Elevated DNS `NXDOMAIN` failure ratio
- Deprecated TLS versions (`SSLv3`, `TLSv1.0`, `TLSv1.1`) & expired X.509 certificates
- Elevated local ARP activity bursts
- Unanswered TCP `SYN` bursts & excessive TCP retransmissions.

## 3. Intelligent Alert Correlation (`app/services/incident_correlator.py`)

1. `AlertManager` deduplicates overlapping heuristic + YAML findings on `(src_ip, dst_ip, dst_port, protocol, behavior_family)` into `SecurityAlert` records.
2. `IncidentCorrelator` clusters alerts via Union-Find across configurable criteria (`CorrelationConfig`: `time_window_seconds=300.0`, `match_source_ip`, `match_destination_ip`, optional `match_source_port`, `match_destination_port`, `match_protocol`, `match_rule`, `match_flow_id`, `separate_suppressed`) into `CorrelatedIncident` objects while preserving all individual alerts and packet references.

## 4. Separate Risk & Confidence Scoring (`app/services/alert_manager.py`)

- **Confidence (`0.0–1.0`):** Reflects indicator strength and evidence completeness (`packet_indices`, `flow_id`, indicator count, penalties for partial HTTP payloads or beaconing capture gaps).
- **Risk Score (`0–100`):** Configurable weighted sum (`ScoringConfig`) of Severity (`4–44`), Confidence (`0–16`), Evidence Quality (`0–8`), Log-scaled Volume (`0–12`), External Destination (`0–8`), Frequency (`0–8`), and Correlation (`0–10`).
- **Severity Guard:** Alerts with `confidence < 0.65` are capped below `CRITICAL`, preventing multiple low-quality indicators from artificially fabricating `CRITICAL` severity.
