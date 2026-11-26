# Known Limitations & Forensic Boundaries

1. **Encrypted Traffic Opacity (HTTPS / TLS / DoH / DoT):**
   Without TLS session keys (`SSLKEYLOGFILE` or server private keys), encrypted application payloads cannot be inspected. TLS analysis relies strictly on observable handshake metadata (SNI, ALPN, versions, unencrypted X.509 certificates), timing, and byte volumes.

2. **NAT, Proxies & Midstream Capture Boundaries:**
   Captures collected behind NAT gateways or HTTP/SOCKS proxies may obscure true originating internal endpoints. Captures starting mid-TCP-session lack initial `SYN` packets (`connection_state = MIDSTREAM_ACTIVE`, `is_midstream = True`), affecting initiator/responder attribution.

3. **Heuristics Indicate Risk—They Do Not Prove Compromise or Data Theft:**
   High DNS entropy, large HTTP `POST` bodies, periodic beaconing, or asymmetric byte ratios are **suspicious indicators**, not proof of unauthorised exfiltration. Corroborate network findings with host EDR, proxy, and DLP telemetry.

4. **Missing Packets, Capture Truncation & Clock Differences:**
   Packet loss, snaplen truncation (`wirelen > captured_len`), multi-segment HTTP bodies split across TCP segments (`payload_incomplete = True`), or clock drift across capture taps can alter retransmission counts, interval variance, and observed payload sizes.

5. **Integrity Hashing vs. Legal Certification:**
   SHA-256 verification and audit logs confirm local artifact integrity against recorded digests; they do not constitute formal legal certification or guarantee full organizational chain-of-custody compliance without procedural controls.

6. **Scale Bounds:**
   `max_packets_per_capture` and `max_stored_packets_per_analysis` (default `100,000` rows in SQLite) bound memory and disk usage; multi-gigabyte captures should be pre-sliced with `tcpdump` / BPF filters.
