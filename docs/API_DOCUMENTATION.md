# REST API Documentation

Base URL (local development): `http://127.0.0.1:8000`  
Interactive OpenAPI docs: `http://127.0.0.1:8000/docs`

**Optional Authentication:** When `PCAP_ANALYSER_API_KEY` is configured, all `/api/pcap/*`, `/api/investigations`, and `/api/analysis/*` endpoints require `X-API-Key: <key>` or `Authorization: Bearer <key>`. `/api/health` remains open for container probes.

## Endpoints

### 1. Health & Readiness
- **`GET /api/health`** — Service status (`healthy` | `degraded`), version, SQLite health, directory checks.

### 2. Capture Ingestion
- **`POST /api/pcap/upload`** — Multipart `.pcap`/`.pcapng` upload. Validates extension, magic bytes, path confinement, and size limit (`400` invalid file, `413` oversized). Records SHA-256, `expected_file_size_bytes`, optional `X-Investigator` attribution, and `PCAP_INGESTED` audit entry (`201 Created`).

### 3. Execution, Progress & Cancellation
- **`POST /api/analysis/start`** — Body `{"analysis_id": "<id>", "run_async": false|true}`. Runs synchronously (`200`) or queues background execution (`PROCESSING`).
- **`GET /api/analysis/{analysis_id}/status`** — Returns `status`, `progress_pct` (`0–100`), `stage`, `cancel_requested`.
- **`POST /api/analysis/{analysis_id}/cancel`** — Cooperative cancellation request for background analyses.
- **`GET /api/investigations?limit=50`** — Lists stored investigations ordered newest first.
- **`GET /api/analysis/{analysis_id}`** — Full investigation bundle JSON.
- **`GET /api/analysis/{analysis_id}/summary`** — KPIs, protocol/time-series/host/port analytics, `network_graph`, `limitations`.

### 4. Correlated Incidents & Alerts
- **`GET /api/analysis/{analysis_id}/incidents`** — Filter by `severity`, `status`, `include_suppressed`, `search`.
- **`GET /api/analysis/{analysis_id}/incidents/{incident_id}`** — Returns correlated incident + constituent alerts.
- **`PATCH /api/analysis/{analysis_id}/incidents/{incident_id}`** — Update dedicated incident workflow status (`Open`, `Investigating`, `Resolved`, `Closed`); supports `X-Investigator` attribution.
- **`GET /api/analysis/{analysis_id}/alerts`** — Filter by `severity`, `protocol`, `status`, `include_suppressed`, `search`.
- **`PATCH /api/analysis/{analysis_id}/alerts/{alert_id}`** — Update alert workflow status (`New`, `Investigating`, `Confirmed Suspicious`, `False Positive`, `Closed`); logged to `audit_logs` with `X-Investigator`.

### 5. Packet-Level Forensic Evidence
- **`GET /api/analysis/{analysis_id}/packets`** — Paginated search (`limit` `1–200`, `offset`) supporting 4-hop correlation and time filtering: `ip`, `src_ip`, `dst_ip`, `port`, `protocol`, `start_time`, `end_time`, `alert_id`, `incident_id`, `flow_id`, `search`. Returns `tcp_flags` and `incident_ids` alongside `alert_ids` and `decoded_fields`.
- **`GET /api/analysis/{analysis_id}/packets/{packet_index}`** — Full decoded metadata, linked flow, and linked alerts for one packet.

### 6. Flows, DNS, MITRE, Threat Intel, Integrity & Reports
- **`GET /api/analysis/{analysis_id}/flows?protocol=&direction=&limit=200&offset=0`** — Bidirectional flows with packet size, IAT stats, throughput (`bytes_per_second`, `packets_per_second`), `connection_frequency_per_min`, and `retransmission_reliability`.
- **`GET /api/analysis/{analysis_id}/dns`** — DNS aggregate stats and sampled records.
- **`GET /api/analysis/{analysis_id}/timeline`** — Chronological timeline events.
- **`GET /api/analysis/{analysis_id}/mitre`** — Evidence-gated MITRE ATT&CK Enterprise mappings.
- **`GET /api/analysis/{analysis_id}/threat-intel`** — Supplemental external threat intelligence (clearly separated from packet evidence).
- **`POST /api/analysis/{analysis_id}/threat-intel/enrich`** — Trigger on-demand non-blocking enrichment.
- **`GET /api/analysis/{analysis_id}/audit`** — Audit trail events, analysis run history, and report integrity metadata.
- **`GET /api/analysis/{analysis_id}/integrity`** — Re-verify on-disk SHA-256 digests and capture file size (`expected_file_size_bytes` vs `actual_file_size_bytes`, `file_size_verified`, `evidence_modified`) of the original PCAP and HTML/PDF reports.
- **`GET /api/analysis/{analysis_id}/report?format=html|pdf`** — Download (or auto-regenerate if missing) standalone HTML/PDF forensic report.
