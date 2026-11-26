# Phase 1 Project Audit Report — PCAP Exfiltration Analyser

**Audit Date:** 2026-11-26  
**Scope:** Complete inspection of `pcap-exfil-analyser/` backend, frontend, detection rules, database schema, reporting templates, docs, and automated tests.  
**Baseline Verification Results (Pre-Edit):**
- `pytest` (`backend/tests/`): **34 passed, 0 failed** (`2.66s`)
- `ruff check .` (`backend/`): **All checks passed**
- `bandit -r app -c pyproject.toml` (`backend/`): **0 issues identified** (`5,532` lines scanned)
- `npm run build` (`frontend/`): **`tsc && vite build` succeeded** (`dist/assets/index-*.js` 780.92 kB)

---

## 1. Existing Working Features

### 1.1 Ingestion & Persistence (`backend/app/services/ingestion.py`, `backend/app/core/database.py`, `backend/app/api/pcap.py`)
- **Capture Validation:** Validates `.pcap` and `.pcapng` extensions, inspects magic bytes (classic/nanosecond PCAP, PCAPNG SHB + byte-order magic) and DLT link-layer types, and enforces `max_upload_size_bytes` (default 100 MiB) incrementally while streaming to disk.
- **Path Safety & Hashing:** Sanitizes filenames (`sanitize_filename`), confines storage paths (`safe_resolve_within`), and calculates SHA-256 digests (`compute_sha256_file`) prior to dissection.
- **SQLite Persistence:** `DatabaseManager` uses WAL mode, `PRAGMA foreign_keys = ON`, and parameterized queries across `investigations` and `alerts` tables.

### 1.2 Packet Dissection & Bidirectional Flow Reconstruction (`backend/app/parsers/`, `backend/app/detectors/flow_analyzer.py`)
- **Streaming Scapy Dissection:** `PacketParser` uses `PcapReader` / `PcapNgReader`, gracefully handles truncated/malformed captures, enforces optional `max_packets`, and detects TCP retransmissions with a bounded 50k segment cache per flow direction.
- **Protocol Metadata Extraction:** Extracts IPv4/IPv6, TCP flags, UDP, ICMP, ARP, DNS queries/responses with `dns_query_cache` matching, HTTP/1.x request/response headers, and observable TLS handshake metadata (SNI, ALPN, versions, unencrypted X.509 certificate fields).
- **Bidirectional Flow Tracking:** `FlowAnalyzer` groups packets by canonical 5-tuple, applies idle timeout (`120.0s`), splits new TCP `SYN` sessions after graceful close/reset, avoids byte double-counting, and infers TCP states (`SYN_ONLY_UNANSWERED`, `MIDSTREAM_ACTIVE`, `ESTABLISHED`, `HALF_CLOSED`, `CLOSED_GRACEFUL`, `RESET`).

### 1.3 Detection Engine, Rule Engine, Allowlist & MITRE (`backend/app/detectors/`, `backend/app/services/`, `backend/rules/`)
- **6 Independent Heuristic Detectors:** `DnsTunnellingDetector`, `OutboundExfiltrationDetector`, `HttpUploadDetector`, `BeaconingDetector`, `SuspiciousPortDetector`, `ProtocolAnomalyDetector`.
- **YAML Rule Engine:** `YamlRuleEngine` validates `detection_rules.yaml` (`RULE-001`..`RULE-008`) via Pydantic v2 (`DetectionRuleSchema`), supporting `AND`/`OR`/`all`/`any` nested conditions and isolating malformed rules.
- **Audit-Safe Allowlisting:** `AllowlistManager` loads `allowlist.yaml` and marks matching findings as `suppressed=True` with `AllowlistMatch` rather than deleting them.
- **Evidence-Gated MITRE ATT&CK Mapper:** `MitreMapper` validates mappings against an official 9-technique Enterprise catalog (`T1041`, `T1048`, `T1048.002`, `T1048.003`, `T1071.001`, `T1071.004`, `T1095`, `T1567`, `T1571`) with reference URLs and confidence gating.
- **Alert Prioritisation & Timeline:** `AlertManager` deduplicates overlapping findings on `(src, dst, dst_port, protocol, family)`, computes a `0–100` `PriorityBreakdown`, builds `TimelineEvent` records, and supports status updates (`New`, `Investigating`, `Confirmed Suspicious`, `False Positive`, `Closed`).

### 1.4 Reporting & Frontend Dashboard (`backend/app/reporting/`, `frontend/src/`)
- **Standalone Reports:** Generates autoescaped Jinja2 HTML (`report.html.j2` with inline SVG chart) and ReportLab PDF (`reporter.py` with `html.escape` on all cells).
- **Dark SOC Dashboard:** React + TypeScript + Tailwind UI with drag-and-drop upload progress (`UploadPanel`), 10 KPI cards (`OverviewKpis`), 6 Recharts visualizations (`TrafficAnalytics`), alert filtering/sorting/status workbench (`AlertManagement`), `@xyflow/react` topology graph (`NetworkGraph`), `IncidentTimeline`, `FlowsAndDnsView`, and HTML/PDF download links.

---

## 2. Incomplete Features

1. **Incident-Level Alert Correlation:** `AlertManager` only merges identical `(src_ip, dst_ip, dst_port, protocol, family)` detections (e.g., heuristic + YAML rule for the same flow/endpoint). There is no higher-level **Incident** entity grouping related alerts across ports, protocols, rules, time windows, or shared flow IDs (with `incident_id`, `incident_title`, `overall_severity`, `overall_confidence`, `first_seen`, `last_seen`, `incident_status`, and drill-down to alerts/packets).
2. **Packet-Level Forensic Evidence & Inspection:** Dissected `NormalizedPacket` records are discarded after `build_investigation_bundle()`. Alerts lack `packet_indices` references (except `sample_packet_indices[:5]` in packet YAML rules), there is no paginated `/api/analysis/{id}/packets` search/filter endpoint, and there is no frontend Packet Evidence viewer or alert-to-packet navigation.
3. **Separate Risk vs. Confidence Scoring & Configurability:** `AlertManager._compute_priority` computes a single `priority_score` without distinguishing `risk_score` from evidence-quality `confidence` or preventing multiple low-quality indicators from inflating severity to `CRITICAL`. Thresholds are hardcoded inside `AlertManager` and `DetectorConfig` defaults rather than externally configurable.
4. **Threat Intelligence Enrichment:** No modular optional enrichment provider exists for IP/domain reputation, WHOIS/RDAP, or DNS lookups with secure credential loading, caching, timeouts, rate-limit handling, and non-blocking execution.
5. **Forensic Integrity History & Audit Logging:** No `audit_logs` table, no `analysis_runs` history table, no report SHA-256 integrity manifest/verification, and no duplicate-capture awareness.
6. **Async Progress & Cancellation:** `run_async=True` enqueues a FastAPI `BackgroundTask`, but there is no live progress percentage/stage tracking, cancellation flag, or frontend polling for async runs.
7. **Advanced Flow Metrics:** `NetworkFlow` lacks packet-size statistics (`min`, `max`, `std`), inter-arrival-time (IAT) statistics (`mean`, `min`, `max`, `std`), explicit observed-vs-inferred state metadata, and supporting `packet_indices`.
8. **Comprehensive Detection Benchmark:** No automated evaluation suite measuring Precision, Recall, F1-score, False-Positive Rate, processing time, and memory usage across diverse labelled synthetic PCAPs.

---

## 3. Bugs and Weaknesses

1. **`backend/app/services/analyzer.py` (`ensure_report_file`, lines 308–324):** If a generated report file is missing from disk for a `COMPLETED` analysis, `ensure_report_file()` loads the bundle, verifies `status == "COMPLETED"`, and returns `report_path` **without regenerating the file**, causing `FileResponse` to raise a 500 error.
2. **`backend/app/parsers/packet_parser.py` (`_normalize_packet`, line 134):** `datetime.fromtimestamp(timestamp, tz=UTC)` is outside the `try/except` block (lines 128–132). Corrupted packet timestamps (e.g., negative or huge epoch values on Windows) raise `OSError`/`OverflowError` and abort parsing.
3. **`backend/app/parsers/packet_parser.py` (`_normalize_packet`, lines 216–218):** Any TCP packet with `src_port == 443 or dst_port == 443` and empty/non-TLS payload (including raw `SYN` scans or cleartext non-TLS traffic) is unconditionally labeled `protocol = "TLS"`.
4. **`backend/app/detectors/flow_analyzer.py` (`_update_tcp_state`, line 315):** Tracks `saw_ack_after_synack` but never uses it in `_infer_connection_state()` (`SYN_ACK` without final `ACK` is indistinguishable from `ESTABLISHED`).
5. **`backend/app/parsers/protocol_extractors.py` (`extract_http_metadata`, lines 182–266):** Inspects only a single TCP segment's payload; does not extract `Content-Type`, `Transfer-Encoding`, or `Referer`, and cannot distinguish single-segment body length from multi-segment uploads when `Content-Length` is missing/chunked.
6. **`backend/app/services/alert_manager.py` (lines 101–113, 136–138, 287):**
   - `correlated_count = max(len(group_findings), len(pair_families[(src, dst)]))` conflates duplicate heuristic+YAML rules firing on a *single* indicator with independent cross-family detections.
   - `pair_families` and `mitre_summary` include findings that were allowlist-suppressed (`suppressed=True`).
7. **`backend/app/services/allowlist.py` (`check_finding`, lines 200–210):** Comment states *"all candidate domains must be trusted if domains exist"*, but the loop returns on the **first** trusted domain match (`for dom in domains: ... return AllowlistMatch(...)`), risking false suppression when a mixed set of trusted and untrusted domains appears in one finding.
8. **`backend/app/reporting/reporter.py` (lines 235, 283) & `README.md`:** PDF tables silently truncate alerts (`[:20]`) and timeline (`[:25]`) without indicating truncation; README claims 7 charts and 17 report sections while `TrafficAnalytics.tsx` has 6 charts and templates have 9 sections.
9. **`frontend/src/components/NetworkGraph.tsx` (lines 73–76) & `FlowsAndDnsView.tsx` (line 34):** Graph layout places nodes in two fixed vertical columns (`x=40`, `x=440`), overlapping/stretching for larger captures and lacking IP/protocol filter controls; `FlowsAndDnsView` slices flows to `[:150]` silently without search/pagination.
10. **Memory Usage on Large Captures (`analyzer.py`, `packet_parser.py`):** `PacketParser.parse_capture()` materializes every `NormalizedPacket` in a Python list in memory, and `AnalysisOrchestrator._save_bundle_json()` serializes all flows and records into a single monolithic JSON file loaded in full by `/api/analysis/{id}`.

---

## 4. Detection Limitations

- **Data Exfiltration (`outbound_exfiltration.py`):** Misses low-and-slow / staged small outbound transfers (`< 100 KB` per flow, `< 10 KB` single flow) that accumulate significant volume over repeated sessions to uncommon destinations; lacks transfer-frequency and session-duration scoring nuance; lacks packet evidence indices.
- **DNS Tunnelling (`dns_tunnelling.py`):** Does not evaluate average query length, query-timing periodicity/inter-query gap variance, base32/base64/hex encoding heuristics across multiple queries, or abnormal query-type distribution ratios (`TXT`/`NULL`/`CNAME`/`MX` share vs `A`/`AAAA`).
- **Beaconing (`beaconing.py`):** Naive `np.diff(timestamps)` breaks on **missing packets or capture gaps** (a single missed beacon doubles one interval and inflates `CV` above `0.25`, causing false negatives). Does not report supporting timestamps, connection duration stats, or distinguish failed `SYN`-only retries from completed sessions.
- **HTTP Analysis (`http_upload.py`):** Does not inspect suspicious `User-Agent` strings, `Content-Type` anomalies, request/response size ratios, request frequency bursts, or incomplete/truncated TCP-segmented payloads; groups strictly by `(src, dst, dst_port)` and ignores anomalous `GET` patterns (e.g., high-frequency C2 polling or raw-IP GETs when no POST/PUT exists—wait: raw-IP triggers, but not suspicious UA or frequency on GET).
- **Protocol Anomaly (`protocol_anomaly.py`):** Lacks ARP anomaly detection (gratuitous ARP bursts / IP-MAC conflicts), TLS metadata anomaly detection (deprecated `SSLv3`/`TLSv1.0`/`TLSv1.1`, expired cert `not_after`, missing SNI on external 443), and DNS response-without-query / amplification indicators.
- **Fundamental Network Forensics Boundaries (Documented & Preserved):** Encrypted TLS/HTTPS payloads cannot be inspected without keys; NAT/proxies obscure internal source attribution; midstream captures lack initial TCP handshakes; heuristics indicate suspicious patterns rather than proving compromise.

---

## 5. Security Vulnerabilities & Hardening Gaps

1. **No Optional API Authentication / Authorization:** All upload, analysis, alert-mutation, and report endpoints are open without API key or bearer token verification when deployed on non-loopback interfaces.
2. **Verbose 500 Error Detail (`backend/app/api/analysis.py:87`):** Returns raw exception text (`f"Analysis pipeline failed: {exc}"`) to HTTP clients, risking internal path or stack information disclosure.
3. **Permissive CORS Methods/Headers (`backend/app/main.py:45-51`):** Uses `allow_methods=["*"]` and `allow_headers=["*"]` alongside `allow_credentials=True`.
4. **Missing HTTP Security Headers:** Neither FastAPI nor `frontend/nginx.conf` sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, or `Content-Security-Policy` (especially relevant for downloaded/served HTML reports).
5. **Unvalidated Path Parameter Format (`api/analysis.py`):** `analysis_id` path parameters are not validated with a strict regex at the API router boundary before DB/file lookups.
6. **Threat Intel Secret Management Needed:** Upcoming threat-intelligence integrations must use `SecretStr` / environment variables, redact secrets from logs, enforce strict request timeouts, and never send packet payloads externally.

---

## 6. Recommended Changes (Phased Roadmap)

- **Phase 2 (Intelligent Alert Correlation & Incident Management):** Introduce `CorrelatedIncident` model, configurable `CorrelationConfig` (time window, grouping keys, min alerts), deterministic incident IDs (preventing duplicates on re-runs), SQLite `incidents` table + status workflow (`PATCH /api/analysis/{id}/incidents/{incident_id}`), `GET /api/analysis/{id}/incidents`, and drill-down to constituent alerts & packets. Fix `mitre_summary` and `pair_families` to respect suppression status.
- **Phase 3 (Detection Engine Upgrades):** Upgrade all 6 detectors (`outbound_exfiltration`, `dns_tunnelling`, `beaconing` with gap-tolerant interval/GCD analysis, `http_upload` + `Content-Type` / UA / incomplete-payload awareness, `protocol_anomaly` with ARP/TLS/DNS checks, `suspicious_ports`), enrich `protocol_extractors.py`, and make detector thresholds YAML/settings-configurable.
- **Phase 4 (Packet-Level Forensic Evidence):** Persist compact, bounded packet metadata records (without raw payload dumps) in SQLite `packets` table (indexed by `analysis_id`, `src_ip`, `dst_ip`, `dst_port`, `protocol`, `timestamp`), link `packet_indices` and `flow_id` to every `DetectionFinding`, `SecurityAlert`, and `CorrelatedIncident`, add paginated `GET /api/analysis/{id}/packets` + `/packets/{packet_index}`, and build the frontend Packet Evidence explorer + alert/incident/timeline drill-down.
- **Phase 5 (Advanced Risk & Confidence Scoring):** Separate explainable `risk_score` (0–100) and evidence-quality `confidence` (0–1) with configurable weights, capping severity so multiple low-quality indicators cannot fabricate `CRITICAL` severity.
- **Phase 6 (Advanced Flow Analysis):** Add packet-size min/max/std, inter-arrival-time (IAT) mean/min/max/std, `saw_ack_after_synack` state distinction (`ESTABLISHED` vs `SYN_ACK_INCOMPLETE`), explicit `is_midstream` / `observed_vs_inferred` attribution fields, and flow-to-packet references.
- **Phase 7 (MITRE ATT&CK Enrichment & Threat Intelligence):** Expand evidence-gated MITRE mappings (`supporting_indicators`, `evidence_references`, `confidence`, `explanation`) and add modular optional Threat Intelligence enrichment (`ip_reputation`, `domain_reputation`, `whois/rdap`, `dns`) with `SecretStr` config, TTL caching, timeouts, rate limiting, private-IP exclusion, and clear labeling separate from packet-derived evidence.
- **Phase 8 (Forensic Integrity & Audit Logging):** Add `audit_logs` and `analysis_history` SQLite tables, capture duplicate SHA-256 awareness, report SHA-256 integrity manifest/verification (`ensure_report_file` auto-regeneration fix), and `GET /api/analysis/{id}/audit` endpoint.
- **Phase 9 (Frontend Dashboard Improvements):** Add Incidents view + drill-down, dedicated Packet Evidence tab with search/filters/detail drawer, Risk vs Confidence breakdown UI, Threat Intel badge/panel, Network Graph IP/protocol filters & improved multi-tier layout, Flows/DNS/HTTP/Beaconing/Anomaly sub-views, async progress polling + cancellation button, and empty/loading/error states with zero hardcoded metrics.
- **Phase 10 (Professional Forensic Reporting):** Upgrade `report.html.j2` and `reporter.py` to cover all 19 required sections cleanly (executive summary using correlated incidents rather than raw alert floods, full appendices, risk/confidence explanations, packet evidence, report SHA-256 verification block).
- **Phase 11 (Performance & Security Hardening):** Optimize memory during parsing/bundle storage (streaming packet insertion to SQLite in batches, paginated endpoints), add background task progress + cancellation, fix `packet_parser.py` timestamp/443 bugs, add optional API key auth, security headers middleware, strict `analysis_id` validation, sanitized 500 error responses, and CORS tightening.
- **Phase 12 (Complete Testing, Synthetic PCAPs & Documentation):** Build multi-scenario labelled synthetic PCAP suite, measure Precision/Recall/F1/FPR/time/memory, verify all existing 34+ new tests, Ruff, Bandit, and frontend build, and update all documentation (`README.md`, `ARCHITECTURE.md`, `DETECTION_LOGIC.md`, `API_DOCUMENTATION.md`, `MITRE_MAPPING.md`, `SECURITY.md`, `LIMITATIONS.md`, plus example reports).

---

## 7. Files Requiring Modification / Creation

### Backend Modifications
- `backend/app/core/config.py`, `database.py`, `security.py` (new auth/headers helpers)
- `backend/app/models/packet.py`, `flow.py`, `detection.py`, `alert.py`, `incident.py` (new), `mitre.py`, `investigation.py`
- `backend/app/parsers/packet_parser.py`, `protocol_extractors.py`
- `backend/app/detectors/base.py`, `flow_analyzer.py`, `dns_tunnelling.py`, `outbound_exfiltration.py`, `beaconing.py`, `http_upload.py`, `protocol_anomaly.py`, `suspicious_ports.py`, `rule_engine.py`
- `backend/app/services/alert_manager.py`, `allowlist.py`, `mitre_mapper.py`, `analyzer.py`, `ingestion.py`, `threat_intel.py` (new), `audit.py` (new)
- `backend/app/api/pcap.py`, `analysis.py`, `health.py`, `backend/app/main.py`
- `backend/app/schemas/analysis.py`
- `backend/app/reporting/reporter.py`, `templates/report.html.j2`
- `backend/rules/detection_rules.yaml`, `backend/rules/allowlist.yaml`

### Frontend Modifications
- `frontend/src/types/forensics.ts`, `frontend/src/services/api.ts`, `frontend/src/App.tsx`
- `frontend/src/components/OverviewKpis.tsx`, `TrafficAnalytics.tsx`, `AlertManagement.tsx`, `IncidentsView.tsx` (new), `PacketEvidenceView.tsx` (new), `NetworkGraph.tsx`, `IncidentTimeline.tsx`, `FlowsAndDnsView.tsx`, `UploadPanel.tsx`
- `frontend/nginx.conf`

### Tests & Documentation
- `backend/tests/test_phase12_*.py` (detectors, correlation, risk/confidence, packet evidence, MITRE, integrity/audit, threat intel, security, large/truncated captures, precision/recall evaluation)
- `scripts/generate_test_pcap.py` (plus labelled synthetic scenario PCAP generator)
- `README.md` and `docs/*.md`
