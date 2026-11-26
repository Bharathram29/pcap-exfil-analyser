# Security Architecture & Threat Model

## 1. Secure File Ingestion & Path Confinement
- **Extension + Magic-Byte Validation:** Uploaded files must end in `.pcap` or `.pcapng` and begin with valid PCAP or PCAPNG SHB magic bytes. Spoofed uploads are rejected (`400`).
- **Upload Size Enforcement:** Streaming uploads enforce `PCAP_ANALYSER_MAX_UPLOAD_SIZE_BYTES` (default 100 MiB) incrementally during write (`413 Content Too Large`).
- **Path Traversal & ID Validation:** `sanitize_filename` strips traversal sequences, `safe_resolve_within` confines all file paths, and `validate_analysis_id` enforces `^[A-Za-z0-9_-]{1,64}$` at API boundaries.
- **Forensic Integrity & Audit Trail:** SHA-256 digests are calculated for uploaded captures (never modified) and generated HTML/PDF reports, recorded alongside `audit_logs` and `analysis_runs` in SQLite.

## 2. Safe Handling of Untrusted Packet Data
- **HTML/PDF XSS & Injection Protection:** Jinja2 HTML reports enable `autoescape`, ReportLab `Paragraph` blocks escape all text via `html.escape(..., quote=True)`, and HTML report downloads include `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:;`.
- **Payload Minimization:** Raw packet payloads are never dumped into the SQLite packet store or executed.
- **Static Parameterized SQL:** All SQLite queries use static bound `?` parameters (`DatabaseManager` + `PacketStore`).

## 3. API Security & Credential Management
- **Optional API Authentication:** Setting `PCAP_ANALYSER_API_KEY` enforces constant-time (`hmac.compare_digest`) `X-API-Key` / `Bearer` token validation across all ingestion, query, mutation, and report routes.
- **Security Headers & CORS:** FastAPI middleware and Nginx set `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and explicit CORS methods/headers.
- **Sanitized Error Responses:** Internal pipeline failures log server-side and return generic `500` messages without leaking paths or stack traces.
- **Threat Intel Secret Management:** External API keys (`virustotal_api_key`, `abuseipdb_api_key`) use Pydantic `SecretStr`, are never logged or serialized, and core PCAP analysis operates 100% offline by default.
