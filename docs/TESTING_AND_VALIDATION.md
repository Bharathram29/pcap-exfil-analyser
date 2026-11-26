# Testing and Validation Report

All automated checks below were executed after completing Phases 1–11 code changes against the workspace in `C:\PYTHON\pcap-exfil-analyser`.

## 1. Automated Test Suite (`pytest`)
- **Command:** `c:\PYTHON\.venv\Scripts\pytest.exe -v` (working directory: `backend`)
- **Result:** **58 passed, 0 failed** (1 third-party `StarletteDeprecationWarning` regarding `httpx` in `fastapi.testclient`), duration **16.07 s**.
- **Coverage across suites:**
  - `tests/test_phase1_setup.py` (4 tests): configuration directories, DB schema, JSON logging, `/api/health`.
  - `tests/test_phase2_ingestion_and_parser.py` (6 tests): path sanitization, `.pcap`/`.pcapng` ingestion, invalid/oversized/empty/truncated/unsupported link-layer handling, Scapy protocol extraction (DNS, HTTP, TLS, TCP, IPv6, ARP).
  - `tests/test_phase3_flow_analyzer.py` (4 tests): bidirectional flow accounting, idle timeout splitting, TCP lifecycle/midstream state inference.
  - `tests/test_phase4_detectors.py` (6 tests) & `tests/test_detection_upgrades.py` (5 tests): Shannon entropy, multi-indicator DNS tunnelling, outbound exfil ratios & staged transfers, HTTP uploads, gap-tolerant beaconing, YAML config overrides.
  - `tests/test_phase5_rule_engine.py` (3 tests): default YAML rules + invalid/partial YAML safety.
  - `tests/test_phase6_mitre_mapper.py` (3 tests) & `tests/test_mitre_threat_intel_and_integrity.py` (3 tests): evidence-gated MITRE mapping, threat intel private-IP exclusion, integrity & regeneration.
  - `tests/test_phase7_alert_manager.py` (4 tests), `tests/test_scoring.py` (3 tests), `tests/test_incident_correlation.py` (3 tests): allowlist tagging, confidence guardrails, incident correlation, API status lifecycle.
  - `tests/test_packet_evidence.py` (1 test) & `tests/test_phase8_reporter.py` (4 tests): packet pagination/filters, HTML/PDF generation, XSS escaping.
  - `tests/test_phase11_synthetic_e2e.py` (2 tests), `tests/test_security_and_async.py` (2 tests), `tests/test_evaluation_and_large_pcap.py` (2 tests): async pipeline, API key + CSP headers, 8-scenario evaluation, large-PCAP streaming/pagination.
  - `tests/test_phase4_9_upgrades.py` (6 tests, added in this upgrade):
    - 60s outbound burst, periodic transfer cadence, per-host baseline anomaly, HTTP vs wire volume separation.
    - DNS response-size correlation, unusual DNS record types, 10s query bursts.
    - Beaconing periodicity score & non-C2 proof framing.
    - Calibrated risk bands & duplicate merge non-inflation of confidence.
    - Flow rate metrics (`bytes_per_second`, `packets_per_second`, `connection_frequency_per_min`), duplicate TCP packet, and midstream TCP handling.
    - 4-hop `/packets?incident_id=...` filtering, `tcp_flags` persistence, `X-Investigator` DB tracking, and on-disk PCAP tamper detection (`evidence_modified: true`).

## 2. Labelled Synthetic Evaluation Benchmark
- **Command:** `c:\PYTHON\.venv\Scripts\python.exe scripts/evaluate_detection_suite.py`
- **Measured Results across 8 Scenarios:**
  - **Precision:** `1.0` (`TP=7`, `FP=0`)
  - **Recall:** `1.0` (`TP=7`, `FN=0`)
  - **F1-Score:** `1.0`
  - **False-Positive Rate:** `0.0` (`FP=0`, `TN=6`)
  - **Total Pipeline Time:** `5336.47 ms` (~5.34 s)
  - **Peak Traced Memory:** `4324.1 KiB` (~4.22 MiB)

| Scenario | Packets | Active Alerts | Active Incidents | TP / FP / FN / TN | Time (ms) | Peak Mem (KiB) |
| :--- | ---: | ---: | ---: | :---: | ---: | ---: |
| `normal_web_browsing` | 9 | 0 | 0 | `0 / 0 / 0 / 2` | 512.89 | 3421.2 |
| `large_outbound_upload` | 235 | 3 | 1 | `1 / 0 / 0 / 0` | 940.15 | 3677.8 |
| `dns_tunnelling` | 10 | 1 | 1 | `1 / 0 / 0 / 0` | 665.61 | 3389.7 |
| `beaconing` | 25 | 1 | 1 | `1 / 0 / 0 / 0` | 623.18 | 4324.1 |
| `suspicious_http` | 5 | 2 | 1 | `1 / 0 / 0 / 0` | 549.50 | 3311.1 |
| `unusual_port` | 19 | 2 | 1 | `1 / 0 / 0 / 0` | 654.27 | 3343.0 |
| `benign_unusual_traffic` | 125 | 0 | 0 | `0 / 0 / 0 / 2` | 618.64 | 3494.2 |
| `mixed_normal_and_suspicious` | 24 | 3 | 2 | `2 / 0 / 0 / 2` | 772.23 | 3390.7 |

## 3. Static Analysis & Security Scan
- **Ruff (`c:\PYTHON\.venv\Scripts\ruff.exe check .`):** `All checks passed!` (0 warnings/errors).
- **Bandit (`c:\PYTHON\.venv\Scripts\bandit.exe -r app -c pyproject.toml`):** **0 issues** across **8,769 lines of code**, **0 skipped (`#nosec`)**.
- **Frontend Production Build (`npm.cmd run build`):** `tsc && vite build` exited `0`, `2208 modules transformed`, built in `5.92 s`.
