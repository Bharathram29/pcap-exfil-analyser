# PCAP Exfiltration Analyser

**From Raw Packets to Actionable Security Intelligence.**

An end-to-end network security and digital forensics platform that transforms raw `.pcap` and `.pcapng` captures into structured packet evidence, bidirectional flow analytics, correlated security incidents, prioritised alerts with separate risk & confidence scoring, validated MITRE ATT&CK mappings, interactive SOC visualisations, chronological incident timelines, and standalone HTML/PDF forensic reports.

---

## Key Capabilities

- **Forensic Ingestion & Integrity:** Extension + magic-byte validation, SHA-256 capture hashing prior to dissection, read-only capture preservation, path-traversal confinement, size caps, and SQLite audit logging + report SHA-256 verification.
- **Streaming Packet Dissection & Packet Evidence Store:** Scapy `PcapReader`/`PcapNgReader` extracts IPv4/IPv6, TCP flags & retransmissions, UDP, ICMP, ARP, DNS query/response pairs, HTTP/1.x metadata (`Content-Type`, `Transfer-Encoding`, incomplete-payload tracking), and observable TLS metadata (SNI, ALPN, versions, unencrypted X.509 certificates). Paginated metadata is persisted in SQLite (`packets`) for fast drill-down without raw payload dumps.
- **Advanced Bidirectional Flow Reconstruction:** Canonical 5-tuple grouping with idle-timeout rotation, packet-size statistics (`min`/`max`/`avg`/`std`), inter-arrival-time (IAT) statistics, observed-vs-inferred TCP connection state basis, and midstream boundary flagging.
- **Upgraded Multi-Indicator Detection Engine + YAML Rules:**
  - **DNS Tunnelling:** Subdomain/query Shannon entropy, avg/max query & subdomain length, unique subdomain fan-out ratio, burst frequency, `TXT`/`ANY`/`CNAME` ratios, encoded-label prevalence, and query-timing cadence (never triggers on entropy alone).
  - **Outbound Data Exfiltration:** Byte volume, outbound-to-inbound ratio, staged small-transfer patterns, transfer frequency, session duration, unusual ports, and HTTP upload corroboration.
  - **HTTP Uploads & Requests:** Large `POST`/`PUT`/`PATCH`, incomplete TCP-segmented body awareness, raw-IP `Host` headers, non-standard ports, suspicious `User-Agent` and `Content-Type` patterns, and request frequency.
  - **Gap-Tolerant Beaconing:** NumPy interval variance with fundamental-period estimation to tolerate missed packets/capture gaps while reducing confidence when gaps exist.
  - **Protocol Anomalies & Suspicious Ports:** Protocol/port mismatches, UDP-on-TCP ports, oversized/high-volume external ICMP, elevated DNS `NXDOMAIN`, deprecated TLS versions, expired TLS certificates, ARP activity bursts, unanswered TCP `SYN` bursts, and excessive retransmissions.
  - **YAML Rule Engine (`backend/rules/detection_rules.yaml`):** Pydantic-validated `AND`/`OR`/`all`/`any` rules + optional `detector_config.yaml` threshold overrides.
- **Intelligent Alert Correlation & Separate Risk/Confidence Scoring:** Groups related alerts across ports, protocols, rules, flow IDs, and configurable time windows into `CorrelatedIncident` records without discarding raw alerts. Computes explainable `risk_score` (`0–100`) separately from `confidence` (`0–1`) with severity calibration guards against low-quality indicator inflation.
- **Evidence-Gated MITRE ATT&CK & Optional Threat Intelligence:** Maps findings to validated Enterprise ATT&CK techniques with supporting indicators and packet/flow references. Supports optional, non-blocking external threat intel (VirusTotal, AbuseIPDB, RDAP/DNS, local IOC YAML) with `SecretStr` credentials, TTL caching, and strict private-IP exclusion.
- **Interactive Dark SOC Dashboard (React + TypeScript + Tailwind):**
  - Upload & live async progress + cooperative cancellation + investigation history
  - Overview KPIs (including Active Incidents & Unique Hosts) & 7 Recharts analytics charts
  - Correlated Incidents workbench + Alerts & Evidence workbench with packet drill-down
  - Interactive `@xyflow/react` Network Graph with IP/protocol filters & node inspector
  - Incident Timeline, Flows/DNS/HTTP/Beaconing Explorer, Packet Evidence Explorer, and Integrity & Audit Trail modal
- **Standalone HTML & PDF Forensic Reports:** Escaped Jinja2 HTML (inline SVG chart, zero external CDNs, CSP header) and ReportLab PDF reports covering capture metadata, executive incident summary, statistics, hosts/flows, correlated incidents, specialized findings, MITRE ATT&CK, timeline, packet references, risk explanations, and technical limitations.

---

## System Architecture

```text
PCAP / PCAPNG Upload (POST /api/pcap/upload)
    ↓
File Validation, SHA-256 Digest & Audit Log (PCAP_INGESTED)
    ↓
Scapy Streaming Packet Parser (IPv4/IPv6, TCP/UDP/ICMP/ARP/DNS/HTTP/TLS)
    ↓
Bidirectional Flow Reconstruction (size/IAT stats, observed vs inferred state, packet->flow map)
    ↓
6 Upgraded Heuristic Detectors + YAML Rule Engine (AND/OR/nested conditions)
    ↓
Allowlist Tagging (audit-safe suppression) → Evidence-Gated MITRE ATT&CK Enrichment
    ↓
Explainable Risk & Confidence Scoring → Intelligent Alert Correlation (CorrelatedIncident)
    ↓
SQLite Persistence (investigations, alerts, incidents, packets, audit_logs, analysis_runs)
    ↓
Optional Non-Blocking Threat Intel → Standalone HTML/PDF Reports (SHA-256 verified)
    ↓
FastAPI REST API (Security Headers + Optional API Key) & React SOC Dashboard
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the complete module map.

---

## Installation & Setup

### Option 1: Windows Setup (PowerShell)

**1. Backend Setup:**

```powershell
cd C:\PYTHON\pcap-exfil-analyser\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements-dev.txt

# Start the FastAPI server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

**2. Frontend Setup (new PowerShell terminal):**

```powershell
cd C:\PYTHON\pcap-exfil-analyser\frontend
npm.cmd install --no-audit --no-fund
npm.cmd run dev
```

Open the dashboard at `http://127.0.0.1:5173` (Swagger UI at `http://127.0.0.1:8000/docs`).

### Option 2: Linux / macOS Setup

```bash
cd pcap-exfil-analyser/backend
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-dev.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 &

cd ../frontend
npm install --no-audit --no-fund
npm run dev
```

### Option 3: Docker Compose Deployment

```powershell
cd C:\PYTHON\pcap-exfil-analyser
docker compose up --build
```

- Frontend SOC Dashboard: `http://localhost:5173`
- Backend REST API & Swagger UI: `http://localhost:8000/docs`
- Reports persist in `./reports`; SQLite database, uploads, and analysis bundles persist in `backend_data`.

---

## Testing, Security Scanning & Evaluation Metrics

```powershell
# Backend tests (52 unit + integration + evaluation tests), Ruff lint, Bandit security scan
cd C:\PYTHON\pcap-exfil-analyser\backend
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\bandit.exe -r app -c pyproject.toml

# Frontend TypeScript check & Vite production bundle
cd C:\PYTHON\pcap-exfil-analyser\frontend
npm.cmd run build

# Run 8-scenario labelled synthetic evaluation benchmark
cd C:\PYTHON\pcap-exfil-analyser
.\backend\.venv\Scripts\python.exe .\scripts\evaluate_detection_suite.py
```

### Measured Detection Evaluation (Labelled Synthetic Benchmark)

Measured by [`scripts/evaluate_detection_suite.py`](scripts/evaluate_detection_suite.py) across 8 labelled synthetic PCAP scenarios (`normal_web_browsing`, `large_outbound_upload`, `dns_tunnelling`, `beaconing` with capture gap, `suspicious_http`, `unusual_port`, `benign_unusual_traffic`, `mixed_normal_and_suspicious`):

| Metric | Measured Result |
| :--- | :--- |
| **Precision** | `1.0` (`TP=7, FP=0`) |
| **Recall** | `1.0` (`TP=7, FN=0`) |
| **F1-Score** | `1.0` |
| **False-Positive Rate** | `0.0` (`FP=0, TN=6`) |
| **Total Pipeline Time (8 PCAPs)** | `~4.45 s` |
| **Peak Traced Python Memory** | `~3.86 MiB` (`3,955.8 KiB`) |

*Note: These metrics reflect controlled synthetic test captures and do not guarantee equivalent accuracy on arbitrary production traffic with NAT, proxies, or encrypted payloads.*

---

## Documentation Index

- [`docs/AUDIT_REPORT.md`](docs/AUDIT_REPORT.md) — Phase 1 audit findings and baseline assessment
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Backend/frontend modules and data flow
- [`docs/DETECTION_LOGIC.md`](docs/DETECTION_LOGIC.md) — Heuristic detectors, YAML rules, correlation & scoring
- [`docs/API_DOCUMENTATION.md`](docs/API_DOCUMENTATION.md) — Complete REST API specification
- [`docs/MITRE_MAPPING.md`](docs/MITRE_MAPPING.md) — Evidence-gated MITRE ATT&CK catalog
- [`docs/SECURITY.md`](docs/SECURITY.md) — Ingestion hardening, auth, CSP, and threat model
- [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) — Forensic boundaries, NAT/TLS/truncation caveats

## License

MIT — see [`LICENSE`](LICENSE).
