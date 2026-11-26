# System Architecture — PCAP Exfiltration Analyser

**Tagline:** *From Raw Packets to Actionable Security Intelligence.*

## 1. Processing Pipeline

```text
PCAP / PCAPNG Upload (POST /api/pcap/upload)
    ↓
File Validation, SHA-256 Digest & Audit Log (services/ingestion.py, services/audit.py)
    ↓
Streaming Packet Parsing Engine (parsers/packet_parser.py, protocol_extractors.py)
    ↓
Bidirectional Flow Reconstruction (detectors/flow_analyzer.py — size/IAT stats, state basis, packet map)
    ↓
6 Upgraded Heuristic Detectors + YAML Rule Engine (detectors/*.py, detectors/rule_engine.py)
    ↓
Allowlist Tagging (services/allowlist.py — audit-safe suppression preservation)
    ↓
MITRE ATT&CK Enrichment (services/mitre_mapper.py — evidence-gated Enterprise mappings)
    ↓
Risk/Confidence Scoring & Incident Correlation (services/alert_manager.py, services/incident_correlator.py)
    ↓
SQLite Persistence (investigations, alerts, incidents, packets, audit_logs, analysis_runs)
    ↓
Optional Non-Blocking Threat Intelligence (services/threat_intel.py)
    ↓
Forensic Report Generator (reporting/reporter.py — escaped HTML + ReportLab PDF + SHA-256 digests)
    ↓
FastAPI REST API & React SOC Security Dashboard
```

## 2. Repository Structure

```text
pcap-exfil-analyser/
├── backend/
│   ├── app/
│   │   ├── main.py                       # FastAPI factory, security headers, CORS, job state
│   │   ├── api/                          # health.py, pcap.py, analysis.py
│   │   ├── core/                         # config.py, logging.py, database.py, security.py
│   │   ├── models/                       # packet.py, flow.py, detection.py, mitre.py, alert.py, incident.py, investigation.py
│   │   ├── schemas/                      # health.py, analysis.py
│   │   ├── services/                     # ingestion.py, mitre_mapper.py, allowlist.py, alert_manager.py,
│   │   │                                 # incident_correlator.py, packet_store.py, threat_intel.py, audit.py, analyzer.py
│   │   ├── parsers/                      # packet_parser.py, protocol_extractors.py
│   │   ├── detectors/                    # base.py, flow_analyzer.py, engine.py, rule_engine.py + 6 detectors
│   │   ├── reporting/                    # reporter.py + templates/report.html.j2
│   │   └── utils/                        # security.py, network.py, entropy.py
│   ├── rules/                            # detection_rules.yaml, allowlist.yaml
│   └── tests/                            # Unit, integration, security, and evaluation tests
├── frontend/
│   └── src/
│       ├── components/                   # UploadPanel, OverviewKpis, TrafficAnalytics, IncidentsView,
│       │                                 # AlertManagement, NetworkGraph, IncidentTimeline,
│       │                                 # FlowsAndDnsView, PacketEvidenceView, SeverityBadge
│       ├── services/api.ts
│       ├── types/forensics.ts
│       └── utils/format.ts
├── scripts/
│   ├── generate_test_pcap.py             # Reproducible synthetic sample PCAP generator
│   └── evaluate_detection_suite.py       # 8-scenario labelled evaluation benchmark
└── docs/                                 # Audit, architecture, detection, MITRE, API, security, limitations
```
