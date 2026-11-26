export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";

export type InvestigationStatus =
  | "New"
  | "Investigating"
  | "Confirmed Suspicious"
  | "False Positive"
  | "Closed";

export type IncidentStatus = "Open" | "Investigating" | "Resolved" | "Closed";

export interface CaptureMetadata {
  analysis_id: string;
  original_filename: string;
  sanitized_filename: string;
  file_size_bytes: number;
  sha256: string;
  capture_format: string;
  ingested_at_utc: string;
  link_layer_type: number | null;
  link_layer_name: string | null;
  supported_link_layer: boolean;
  packet_count: number;
  malformed_packet_count: number;
  is_empty: boolean;
  warnings: string[];
}

export interface PriorityBreakdown {
  severity_score: number;
  confidence_score: number;
  volume_score: number;
  external_destination_score: number;
  repeated_activity_score: number;
  correlation_score: number;
  total_score: number;
  rationale: string;
  risk_score?: number;
  evidence_quality_score?: number;
  confidence_rationale?: string;
  contributing_indicators?: string[];
  evidence_quality?: number;
  severity_explanation?: string;
  score_change_reasons?: string[];
}

export interface AllowlistMatch {
  category: string;
  matched_entry: string;
  reason: string;
}

export interface MitreMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  reason: string;
  supporting_evidence: Record<string, unknown>;
  confidence_level: string;
  confidence_score: number;
  reference_url: string;
  source_detection_ids: string[];
  supporting_indicators?: string[];
  evidence_references?: Record<string, unknown>;
}

export interface SecurityAlert {
  alert_id: string;
  title: string;
  severity: Severity;
  confidence: number;
  priority_score: number;
  risk_score?: number;
  priority_breakdown: PriorityBreakdown;
  status: InvestigationStatus;
  timestamp: string;
  timestamp_epoch: number;
  last_seen?: string | null;
  last_seen_epoch?: number | null;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string;
  explanation: string;
  evidence: Record<string, unknown>;
  recommended_investigation_steps: string[];
  mitre_mappings: MitreMapping[];
  contributing_detection_ids: string[];
  contributing_rule_ids: string[];
  detector_types: string[];
  correlated_indicators_count: number;
  suppressed: boolean;
  allowlist_match: AllowlistMatch | null;
  observation_type: string;
  flow_id: string | null;
  incident_id?: string | null;
  packet_indices?: number[];
}

export interface CorrelatedIncident {
  incident_id: string;
  incident_title: string;
  overall_severity: Severity;
  overall_confidence: number;
  risk_score: number;
  status: IncidentStatus;
  source_hosts: string[];
  destination_hosts: string[];
  source_ports: number[];
  destination_ports: number[];
  protocols: string[];
  detection_categories: string[];
  alert_count: number;
  suppressed: boolean;
  first_seen: string;
  first_seen_epoch: number;
  last_seen: string;
  last_seen_epoch: number;
  alert_ids: string[];
  flow_ids: string[];
  packet_indices: number[];
  rule_ids: string[];
  mitre_mappings: MitreMapping[];
  evidence_references: Record<string, unknown>;
  correlation_reason: string;
  recommended_investigation_steps: string[];
}

export interface NetworkFlow {
  flow_id: string;
  transport_protocol: string;
  application_protocol: string;
  initiator_ip: string;
  initiator_port: number | null;
  responder_ip: string;
  responder_port: number | null;
  direction: string;
  packets_initiator_to_responder: number;
  packets_responder_to_initiator: number;
  bytes_initiator_to_responder: number;
  bytes_responder_to_initiator: number;
  first_seen: number;
  last_seen: number;
  first_seen_utc: string;
  last_seen_utc: string;
  duration_seconds: number;
  total_packets: number;
  total_bytes: number;
  avg_packet_size: number;
  min_packet_size?: number;
  max_packet_size?: number;
  std_packet_size?: number;
  mean_iat_seconds?: number | null;
  min_iat_seconds?: number | null;
  max_iat_seconds?: number | null;
  std_iat_seconds?: number | null;
  outbound_to_inbound_ratio: number | null;
  connection_state: string;
  state_basis?: string;
  handshake_completed?: boolean;
  is_midstream?: boolean;
  retransmission_count: number;
  retransmission_reliability?: string;
  connection_frequency_per_min?: number;
  bytes_per_second?: number;
  packets_per_second?: number;
  observed_dns_queries: string[];
  observed_http_hosts: string[];
  observed_http_methods?: string[];
  observed_tls_snis: string[];
  packet_indices?: number[];
}

export interface PacketEvidenceItem {
  packet_number: number;
  packet_index: number;
  timestamp: number;
  timestamp_utc: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  transport_protocol: string | null;
  length: number;
  ttl: number | null;
  ip_version: number | null;
  flow_id: string | null;
  tcp_flags?: string | null;
  alert_ids: string[];
  incident_ids?: string[];
  decoded_fields: Record<string, unknown>;
  raw_summary: string;
}

export interface TimelineEvent {
  event_id: string;
  timestamp: string;
  timestamp_epoch: number;
  source_ip: string | null;
  destination_ip: string | null;
  protocol: string;
  detection_rule: string;
  severity: Severity;
  mitre_techniques: string[];
  evidence_summary: string;
  suppressed: boolean;
  alert_id: string | null;
  incident_id?: string | null;
  packet_indices?: number[];
}

export interface GraphNodeData {
  id: string;
  ip: string;
  is_external: boolean;
  is_suspicious: boolean;
  alert_count: number;
  highest_severity: Severity | null;
  bytes_sent: number;
  bytes_received: number;
  flow_count: number;
}

export interface GraphEdgeData {
  id: string;
  source: string;
  target: string;
  total_bytes: number;
  total_packets: number;
  flow_count: number;
  protocols: string[];
  ports: number[];
  is_suspicious: boolean;
}

export interface InvestigationSummaryStats {
  total_packets: number;
  total_bytes: number;
  total_flows: number;
  unique_source_ips: number;
  unique_destination_ips: number;
  dns_queries: number;
  http_requests: number;
  tls_handshakes: number;
  suspicious_events: number;
  suppressed_events: number;
  total_alerts?: number;
  allowlisted_alerts?: number;
  correlated_incidents?: number;
  active_incidents?: number;
  allowlisted_incidents?: number;
  total_incidents?: number;
  critical_alerts: number;
  high_alerts: number;
  medium_alerts: number;
  low_alerts: number;
  informational_alerts: number;
  severity_distribution: Record<string, number>;
  outbound_bytes: number;
  inbound_bytes: number;
  processing_duration_ms: number;
}

export interface DnsRecordItem {
  packet_index: number;
  timestamp: string;
  src_ip: string | null;
  dst_ip: string | null;
  is_response: boolean;
  query_name: string | null;
  query_type: string | null;
  response_code: string | null;
  response_ips: string[];
  query_length: number;
  subdomain_length: number;
  parent_domain: string | null;
}

export interface ThreatIntelResultItem {
  indicator: string;
  indicator_type: string;
  provider: string;
  reputation: string;
  confidence: number;
  summary: string;
  details: Record<string, unknown>;
  source_type: string;
  cached: boolean;
}

export interface ThreatIntelBundle {
  enabled?: boolean;
  providers_configured?: string[];
  source_label?: string;
  disclaimer?: string;
  skipped_private_ips?: string[];
  results?: ThreatIntelResultItem[];
}

export interface InvestigationBundle {
  analysis_id: string;
  status: string;
  generated_at_utc: string;
  processing_duration_ms: number;
  capture_metadata: CaptureMetadata;
  summary: InvestigationSummaryStats;
  protocol_distribution: Array<{ protocol: string; packet_count: number; byte_count: number }>;
  traffic_over_time: Array<{
    timestamp: string;
    timestamp_epoch: number;
    bytes: number;
    packets: number;
    dns_queries: number;
    suspicious_events: number;
  }>;
  top_hosts: Array<{
    ip: string;
    bytes_sent: number;
    bytes_received: number;
    total_bytes: number;
    alert_count: number;
    is_external: boolean;
  }>;
  top_ports: Array<{ port: number; flow_count: number; total_bytes: number }>;
  dns_analysis: {
    total_queries: number;
    total_responses: number;
    unique_domains: number;
    nxdomain_count: number;
    query_types: Record<string, number>;
    top_queried_domains: Array<{ domain: string; count: number }>;
    records?: DnsRecordItem[];
  };
  http_analysis: {
    total_requests: number;
    total_responses: number;
    methods: Record<string, number>;
    total_upload_payload_bytes: number;
    top_hosts: Array<{ host: string; count: number }>;
    sample_requests: Array<{
      timestamp: string;
      src_ip: string | null;
      dst_ip: string | null;
      method: string | null;
      host: string | null;
      uri: string | null;
      user_agent: string | null;
      payload_size: number;
      direction: string;
    }>;
  };
  tls_analysis: {
    total_handshakes: number;
    observed_snis: Array<{ sni: string; count: number }>;
    versions: Record<string, number>;
    note: string;
  };
  flows: NetworkFlow[];
  alerts: SecurityAlert[];
  active_alerts: SecurityAlert[];
  suppressed_alerts: SecurityAlert[];
  incidents?: CorrelatedIncident[];
  active_incidents?: CorrelatedIncident[];
  suppressed_incidents?: CorrelatedIncident[];
  mitre_mappings: MitreMapping[];
  timeline: TimelineEvent[];
  network_graph: { nodes: GraphNodeData[]; edges: GraphEdgeData[] };
  limitations: string[];
  threat_intelligence?: ThreatIntelBundle;
  integrity?: {
    capture_sha256?: string;
    html_report_sha256?: string;
    pdf_report_sha256?: string;
    original_capture_preserved?: boolean;
  };
}

export interface InvestigationListItem {
  analysis_id: string;
  filename: string;
  file_size_bytes: number;
  sha256: string;
  status: string;
  created_at: string;
  completed_at: string | null;
  processing_duration_ms: number | null;
  summary: InvestigationSummaryStats | null;
}

export interface PcapUploadResponse {
  analysis_id: string;
  filename: string;
  file_size_bytes: number;
  sha256: string;
  capture_format: string;
  status: string;
  warnings: string[];
}

export interface AnalysisJobStatus {
  analysis_id: string;
  status: string;
  progress_pct: number;
  stage: string;
  cancel_requested: boolean;
}

export interface AuditLogEntry {
  id: number;
  analysis_id: string;
  action: string;
  actor: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface IntegrityVerification {
  analysis_id: string;
  capture_present: boolean;
  capture_integrity_verified: boolean;
  expected_file_size_bytes?: number | null;
  actual_file_size_bytes?: number | null;
  file_size_verified?: boolean;
  html_report_present: boolean;
  html_report_verified: boolean;
  pdf_report_present: boolean;
  pdf_report_verified: boolean;
  capture_expected_sha256: string;
  capture_actual_sha256?: string | null;
  evidence_modified?: boolean;
  disclaimer: string;
}
