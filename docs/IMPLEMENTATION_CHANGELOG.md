# Implementation Changelog — PCAP Exfiltration Analyser Upgrades

This changelog records all enhancements made during the structured upgrade across Phases 1–12 while preserving the existing FastAPI + Scapy + SQLite + React/TypeScript architecture.

## 1. Code Audit & Shared Utilities (Phases 1–2)
- Authored [`docs/IMPROVEMENT_AUDIT.md`](IMPROVEMENT_AUDIT.md) identifying duplicate helpers, status alignment gaps, detector improvements, 4-hop evidence linking gaps, and UI/reporting improvements.
- Consolidated duplicate IP-host detection into [`is_raw_ip_host`](../backend/app/utils/network.py) reused by both `HttpUploadDetector` and `YamlRuleEngine`.
- Added explicit summary breakdown counters (`total_alerts`, `allowlisted_alerts`, `correlated_incidents`, `allowlisted_incidents`, alongside `suspicious_events`, `suppressed_events`, `active_incidents`, `total_incidents`) in `InvestigationBundle.summary`.

## 2. Dedicated Incident Workflow Lifecycle (Phase 3)
- Defined dedicated `INCIDENT_STATUSES = ("Open", "Investigating", "Resolved", "Closed")` in [`app/models/incident.py`](../backend/app/models/incident.py), separate from per-alert `INVESTIGATION_STATUSES`.
- Updated `IncidentCorrelator`, Pydantic `IncidentStatusUpdateRequest`, SQLite `incidents` schema default (`'Open'`), `AlertManager.update_incident_status`, and frontend `IncidentsView.tsx` + `types/forensics.ts`.

## 3. Detection Engine Upgrades (Phase 4)
- **Outbound Exfiltration (`outbound_exfiltration.py`):** Added 60-second sliding time-window burst analysis (`max_60s_window_bytes`, `peak_bytes_per_second`), periodic transfer cadence check (`periodic_transfer_detected`), per-host external peer median baseline comparison (`host_baseline_median_bytes`, `baseline_anomaly`), and explicit separation of `http_upload_count` / `http_declared_body_bytes` vs flow-observed `outbound_bytes`.
- **DNS Tunnelling (`dns_tunnelling.py` + `packet.py` + `protocol_extractors.py`):** Populated DNS `answer_count` and `response_size_bytes`; correlated DNS responses (`response_count`, `matched_response_count`, `query_to_response_ratio`, `max_response_bytes`, `avg_response_bytes`), unusual DNS types (`txt_or_any_count`), repeated encoded chunk patterns (`repeated_chunk_pattern`), and 10-second query bursts (`max_10s_burst_queries`).
- **Beaconing (`beaconing.py`):** Added `connections_per_hour`, `active_span_seconds`, `periodicity_score`, `mean_packet_size_std`, and clearer wording distinguishing statistical periodicity from confirmed C2 compromise.
- **HTTP Analysis (`http_upload.py`):** Added HTTP response status correlation (`response_status_codes`) alongside `flow_observed_outbound_bytes` vs HTTP declared body bytes.

## 4. Calibrated Risk Scoring, Flows & 4-Hop Evidence Linking (Phases 5–7)
- **Calibrated Risk & Confidence Scoring (`alert_manager.py`, `alert.py`):** Added `0–100` calibrated risk bands (`0–20` LOW, `21–40` MEDIUM, `41–70` HIGH, `71–100` CRITICAL) gated by evidence confidence (`critical_min_confidence = 0.65`, `high_min_confidence = 0.45`), non-inflating duplicate alert merges, and explainability fields (`contributing_indicators`, `evidence_quality`, `severity_explanation`, `score_change_reasons`).
- **Flow Metrics (`flow.py`, `flow_analyzer.py`):** Added `bytes_per_second`, `packets_per_second`, `connection_frequency_per_min`, and `retransmission_reliability`.
- **4-Hop Traceability (`database.py`, `packet_store.py`, `api/analysis.py`):** Added `tcp_flags` and `incident_ids_json` columns (with safe `_ensure_column` migrations) and `incident_id` filter on `GET /api/analysis/{analysis_id}/packets`, supporting end-to-end navigation across Incidents → Alerts → Flows → Packets.

## 5. Forensic Integrity & Investigator Attribution (Phase 9)
- Added `investigator_id` and `started_at` persistence on `investigations`, populated via optional `X-Investigator` HTTP header across upload, alert status, and incident status endpoints.
- Enhanced `AuditService.verify_integrity()` to check both SHA-256 digests and capture file size (`expected_file_size_bytes`, `actual_file_size_bytes`, `file_size_verified`, `evidence_modified`).

## 6. Interactive Dashboard & Forensic Reports (Phases 10–11)
- **Frontend:** Upgraded `OverviewKpis.tsx`, `IncidentsView.tsx`, `AlertManagement.tsx`, `FlowsAndDnsView.tsx`, `IncidentTimeline.tsx` (filters + grouping toggle), `PacketEvidenceView.tsx` (`incident_id`, `start_time`, `end_time`, `tcp_flags`), `UploadPanel.tsx` (`Investigator ID` input), `App.tsx` (4-hop routing & tamper alert modal), plus CSV/JSON exports.
- **Reports (`reporter.py`, `report.html.j2`):** Added dedicated Beaconing Findings section and structured Packet-Level Evidence Reference Table in both HTML and PDF outputs, separated Risk (`0–100`) from Confidence (`0–100%`), and aligned all executive-summary counts across report sections.
