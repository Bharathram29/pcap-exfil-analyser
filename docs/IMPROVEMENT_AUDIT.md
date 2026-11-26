# Improvement Audit — PCAP Exfiltration Analyser

**Audit Date:** 2026-11-26  
**Scope:** Complete end-to-end review of backend, detection modules, YAML rules, correlation/scoring, SQLite schema, API routes, frontend React components, HTML/PDF reporting, integrity/audit logging, and test suite.  
**Baseline State:** `52 passed` (`pytest`), `ruff check .` clean, `bandit` 0 issues, `npm run build` (`tsc && vite build`) clean.

---

## 1. Existing Functionality (Verified Working)

- **Ingestion & Validation (`backend/app/services/ingestion.py`, `api/pcap.py`):** Extension (`.pcap`/`.pcapng`), magic-byte and DLT link-layer validation, streaming chunked upload size caps, path traversal sanitization (`sanitize_filename`, `safe_resolve_within`), SHA-256 hashing before analysis, SQLite `investigations` persistence.
- **Packet Dissection (`backend/app/parsers/packet_parser.py`, `protocol_extractors.py`):** Streaming `PcapReader`/`PcapNgReader`, IPv4/IPv6, TCP flags/retransmissions, UDP, ICMP, ARP, DNS query/response parsing, HTTP/1.x metadata (`Content-Type`, `Transfer-Encoding`, `payload_incomplete`), observable TLS metadata (SNI, ALPN, versions, unencrypted X.509 certificates).
- **Flow Analysis (`backend/app/detectors/flow_analyzer.py`):** Bidirectional canonical 5-tuple grouping, idle timeout rotation, TCP lifecycle state inference, Welford packet-size and IAT stats, packet-to-flow mapping.
- **Detection Engine (`backend/app/detectors/*.py`, `rule_engine.py`):** 6 heuristic detectors (`DnsTunnellingDetector`, `OutboundExfiltrationDetector`, `HttpUploadDetector`, `BeaconingDetector`, `SuspiciousPortDetector`, `ProtocolAnomalyDetector`) plus Pydantic-validated `YamlRuleEngine` (`detection_rules.yaml`) and audit-safe `AllowlistManager` (`allowlist.yaml`).
- **Correlation, Scoring & MITRE (`alert_manager.py`, `incident_correlator.py`, `mitre_mapper.py`):** Deduplication into `SecurityAlert`, Union-Find grouping into `CorrelatedIncident`, 9-technique evidence-gated MITRE ATT&CK Enterprise catalog, optional non-blocking `ThreatIntelService`.
- **Persistence, Integrity & Reporting (`database.py`, `packet_store.py`, `audit.py`, `reporter.py`):** SQLite WAL tables (`investigations`, `alerts`, `incidents`, `packets`, `audit_logs`, `analysis_runs`), Jinja2 HTML + ReportLab PDF report generation with auto-regeneration.
- **Frontend (`frontend/src/`):** Dark SOC dashboard with Upload & Progress, Overview & 7 Recharts charts, Incidents, Alerts, `@xyflow/react` Network Graph, Timeline, Flows/DNS/HTTP Explorer, Packet Evidence Explorer, and Integrity & Audit modal.

---

## 2. Identified Weaknesses, Gaps & Inconsistencies

### 2.1 Detection Weaknesses
1. **Exfiltration Detector (`outbound_exfiltration.py`):**
   - Lacks **time-window traffic burst analysis** (e.g., sliding-window byte rate bursts), **periodic outbound transfer detection**, and **host-level baseline comparison** (comparing a destination's outbound volume/ratio against the same source host's historical/session peer baseline when `>= 3` external peers exist).
   - Does not explicitly separate **HTTP request frequency**, **HTTP declared body size**, and **actual observed transferred flow bytes** in evidence/explanation.
   - Findings lack an explicit `risk_score` field alongside `confidence`.
2. **DNS Tunnelling (`dns_tunnelling.py`, `protocol_extractors.py`, `models/packet.py`):**
   - `DnsMetadata` does not capture **DNS response size** (`response_bytes` / `answer_count`) or **query-to-response latency/size ratio**, preventing correlation of oversized TXT responses with queries.
   - `DnsTunnellingDetector` does not score **time-window query bursts** (max queries in a 10s/60s window), **unusual record types** beyond TXT/ANY/NULL/CNAME (e.g., `MX`, `SRV`, `DNSKEY`, `HINFO`, unknown `TYPE*`), or **repeated fixed-length subdomain chunk patterns**.
3. **Beaconing (`beaconing.py`):**
   - Lacks explicit **connection frequency** (connections/hour & connections/min), **periodicity score**, **time-span coverage**, and flow **packet-size consistency** (`std_packet_size` alongside `byte_cv`).
4. **HTTP & Protocol Analysis (`http_upload.py`, `protocol_extractors.py`):**
   - Does not track **HTTP response status codes** (`200`/`201` vs `403`/`404`/`500`) alongside request targets, nor **flow-observed transferred bytes vs. declared `Content-Length`** for fragmented/multi-segment HTTP uploads.

### 2.2 Correlation & Scoring Inconsistencies
5. **Incident Status Mismatch (`incident_correlator.py`, `alert_manager.py`, `schemas/analysis.py`, `IncidentsView.tsx`):**
   - Incidents currently reuse alert statuses (`New`, `Investigating`, `Confirmed Suspicious`, `False Positive`, `Closed`) instead of dedicated incident lifecycle statuses (`Open`, `Investigating`, `Resolved`, `Closed`).
6. **Summary Count Ambiguity (`investigation.py`, `OverviewKpis.tsx`):**
   - `summary` lacks explicit separate counters for `total_alerts`, `correlated_incidents`, `active_incidents`, `allowlisted_alerts`, and `allowlisted_incidents`.
7. **Risk Score & Severity Band Calibration (`alert_manager.py`):**
   - Currently `severity` is fed circularly into `priority_score` (`SEVERITY_BASE_WEIGHTS`) rather than computing an objective `0–100` `risk_score` mapped into calibrated bands (`0–20 Low`, `21–40 Medium`, `41–70 High`, `71–100 Critical`) with confidence gating (`CRITICAL` requires `confidence >= 0.65`, duplicate alerts do not boost confidence), and exposing `contributing_indicators`, `evidence_quality`, `confidence_explanation`, `severity_explanation`, and `score_change_reasons`.

### 2.3 Evidence Navigation, Flow & Integrity Gaps
8. **Packet Evidence & 4-Hop Navigation (`packet_store.py`, `api/analysis.py`, `frontend/`):**
   - `packets` table lacks `incident_id` association (`incident_ids_json`) and direct `tcp_flags` field, and `GET /api/analysis/{id}/packets` lacks an `incident_id` filter.
   - Frontend lacks seamless 4-hop navigation (**Incident → Alert → Network Flow → Supporting Packets**).
9. **Flow Analysis (`flow_analyzer.py`, `models/flow.py`):**
   - `NetworkFlow` lacks explicit `connection_frequency_per_min` (for the endpoint pair), `bytes_per_second`, `forward_bytes`/`reverse_bytes` clarity, and `retransmission_reliability` documentation.
10. **Integrity & Audit Trail (`ingestion.py`, `audit.py`, `analyzer.py`):**
    - Missing **investigator identifier** (`investigator_id`) tracking on uploads, analyses, and triage updates.
    - `verify_integrity()` checks SHA-256 hashes but does not explicitly verify **on-disk file size** (`file_size_verified`) or expose a top-level **`evidence_modified`** tamper flag and `analysis_started_at` timestamp.

### 2.4 Frontend, Timeline & Reporting Weaknesses
11. **Incident Timeline (`IncidentTimeline.tsx`):**
    - Lacks **host, protocol, incident, and time-range filters** and **grouping of repeated related events** (while preserving individual event expansion).
12. **Dashboard Pagination, Time Filters & Exports (`FlowsAndDnsView.tsx`, `PacketEvidenceView.tsx`, `AlertManagement.tsx`, `IncidentsView.tsx`):**
    - `FlowsAndDnsView` slices flows at `[:200]` without pagination; `PacketEvidenceView` lacks time-range (`start_time`/`end_time`) UI inputs; tables lack JSON/CSV export options.
13. **HTML/PDF Report Consistency (`report.html.j2`, `reporter.py`):**
    - Missing a dedicated **Beaconing Findings** section/table and a structured **Packet-Level Evidence** table (with packet #, timestamp, endpoints, proto, length, TCP flags/DNS/HTTP summary, flow ID, alert ID) in both HTML and PDF.
    - PDF caps alerts (`[:40]`), incidents (`[:30]`), and timeline (`[:40]`), and executive summary counts must strictly align with summary totals (`total_alerts`, `correlated_incidents`, `active_incidents`, `allowlisted_alerts`, `allowlisted_incidents`).

### 2.5 Duplicate Logic & Performance Bottlenecks
14. **Duplicated `_is_raw_ip` helper** in `detectors/http_upload.py` and `detectors/rule_engine.py` (should be centralized in `app/utils/network.py`).
15. **Bundle & Packet Memory Footprint (`analyzer.py`, `packet_parser.py`):**
    - `PacketParser` keeps all packets in memory during orchestration; `load_bundle()` reads full JSON synchronously on every API call. Adding lightweight bundle caching / streaming metrics and avoiding unnecessary payload duplication improves throughput.

---

## 3. Prioritised Implementation Plan

1. **Phase 1 (Complete):** Audit repository, initialize Git checkpoint, write `docs/IMPROVEMENT_AUDIT.md`.
2. **Phase 2:** Deduplicate `_is_raw_ip`, fix summary/count fields (`total_alerts`, `correlated_incidents`, `active_incidents`, `allowlisted_alerts`, `allowlisted_incidents`), and fix minor report count inconsistencies.
3. **Phase 3:** Upgrade incident management to dedicated statuses (`Open`, `Investigating`, `Resolved`, `Closed`) and verify correlation without discarding raw alerts.
4. **Phase 4:** Upgrade Exfiltration (time-window bursts, periodic transfers, host baseline comparison, HTTP freq vs body vs flow bytes), DNS (response sizes, query-response correlation, unusual types, sliding-window bursts), HTTP (response status correlation, fragmented flow-vs-header bytes), and Beaconing (periodicity, frequency, packet-size consistency).
5. **Phase 5:** Implement transparent calibrated Risk (`0–100`: `0–20 Low`, `21–40 Medium`, `41–70 High`, `71–100 Critical`) separate from Confidence (`0–1`), with `contributing_indicators`, `evidence_quality`, `confidence_explanation`, `severity_explanation`, and `score_change_reasons`.
6. **Phase 6:** Enrich `PacketStore` with `incident_ids`, `tcp_flags`, `incident_id` filter, and full 4-hop evidence traceability.
7. **Phase 7:** Add flow connection frequency, throughput, and retransmission reliability indicators to `FlowAnalyzer`.
8. **Phase 8:** Audit and verify evidence-gated MITRE ATT&CK mappings (no unsupported assignments).
9. **Phase 9:** Add `investigator_id`, file size verification, `analysis_started_at`, and `evidence_modified` tamper detection to Integrity & Audit.
10. **Phase 10:** Upgrade React dashboard (Timeline filters & grouping, Flows pagination, Packet time-range filter & 4-hop navigation, Investigator ID, CSV/JSON exports).
11. **Phase 11:** Upgrade HTML & PDF reports to cover all 17 sections with strict count consistency and zero overflow.
12. **Phase 12:** Performance benchmarks, security & edge-case tests (empty, malformed, truncated, duplicate packets, midstream TCP, large PCAPs), `docs/IMPLEMENTATION_CHANGELOG.md`, `docs/TESTING_AND_VALIDATION.md`, and updated `README.md`.
