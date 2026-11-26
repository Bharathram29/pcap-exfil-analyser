# MITRE ATT&CK Enterprise Integration

All MITRE ATT&CK mappings are validated against an official Enterprise catalog in [`backend/app/services/mitre_mapper.py`](../backend/app/services/mitre_mapper.py). Unknown or uncatalogued technique IDs are rejected, and every mapping enforces evidence-gating and minimum confidence (`>= 0.45`, non-`INFORMATIONAL`). Each mapping includes `supporting_indicators`, `evidence_references` (`flow_id`, `packet_indices`, `source_detection_ids`), `confidence_level`/`confidence_score`, `reason`, and official ATT&CK URL.

## Validated Technique Catalog

| Technique ID | Name | Tactic | Justification Gate | Official Reference |
| :--- | :--- | :--- | :--- | :--- |
| **T1041** | Exfiltration Over C2 Channel | Exfiltration | Periodic beaconing, external C2 port, or substantial outbound channel upload (`>= 50 KB`) | https://attack.mitre.org/techniques/T1041/ |
| **T1048** | Exfiltration Over Alternative Protocol | Exfiltration | Alternative protocol exfiltration indicator | https://attack.mitre.org/techniques/T1048/ |
| **T1048.002** | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Exfiltration | Encrypted TLS protocol with disproportionate outbound external transfer | https://attack.mitre.org/techniques/T1048/002/ |
| **T1048.003** | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration | Unencrypted DNS/ICMP/HTTP/TCP indicator consistent with non-C2 exfiltration | https://attack.mitre.org/techniques/T1048/003/ |
| **T1071.001** | Application Layer Protocol: Web Protocols | Command and Control | Anomalous HTTP web communication with raw-IP Host, non-standard port, or high-frequency polling (`>= 20 req/min`) — never assigned blindly to generic HTTP traffic | https://attack.mitre.org/techniques/T1071/001/ |
| **T1071.004** | Application Layer Protocol: DNS | Command and Control | Multi-indicator DNS tunnelling or high-ratio NXDOMAIN anomaly | https://attack.mitre.org/techniques/T1071/004/ |
| **T1095** | Non-Application Layer Protocol | Command and Control | Unusual external ICMP payload size or packet volume | https://attack.mitre.org/techniques/T1095/ |
| **T1567** | Exfiltration Over Web Service | Exfiltration | Large or repeated HTTP upload requests (`POST`/`PUT`/`PATCH`) | https://attack.mitre.org/techniques/T1567/ |
| **T1571** | Non-Standard Port | Command and Control | Application protocol observed on mismatched destination port | https://attack.mitre.org/techniques/T1571/ |
