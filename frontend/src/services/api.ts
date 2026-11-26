import type {
  AnalysisJobStatus,
  AuditLogEntry,
  IntegrityVerification,
  InvestigationBundle,
  InvestigationListItem,
  InvestigationStatus,
  PacketEvidenceItem,
  PcapUploadResponse,
  ThreatIntelBundle,
} from "../types/forensics";

const API_BASE = import.meta.env.VITE_API_BASE ?? "";

export function uploadPcapWithProgress(
  file: File,
  onProgress: (percent: number) => void,
): Promise<PcapUploadResponse> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_BASE}/api/pcap/upload`);

    xhr.upload.onprogress = (evt) => {
      if (evt.lengthComputable && evt.total > 0) {
        onProgress(Math.round((evt.loaded / evt.total) * 100));
      }
    };

    xhr.onload = () => {
      try {
        const body = JSON.parse(xhr.responseText || "{}");
        if (xhr.status >= 200 && xhr.status < 300) {
          onProgress(100);
          resolve(body as PcapUploadResponse);
        } else {
          reject(new Error(body.detail || `Upload failed with status ${xhr.status}`));
        }
      } catch {
        reject(new Error(`Upload failed with status ${xhr.status}`));
      }
    };

    xhr.onerror = () => reject(new Error("Network error while uploading PCAP file."));

    const formData = new FormData();
    formData.append("file", file);
    xhr.send(formData);
  });
}

export async function startAnalysis(
  analysisId: string,
  runAsync = false,
): Promise<{ analysis_id: string; status: string; processing_duration_ms: number | null }> {
  const res = await fetch(`${API_BASE}/api/analysis/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ analysis_id: analysisId, run_async: runAsync }),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || "Failed to execute analysis pipeline.");
  }
  return data;
}

export async function fetchAnalysisStatus(analysisId: string): Promise<AnalysisJobStatus> {
  const res = await fetch(`${API_BASE}/api/analysis/${encodeURIComponent(analysisId)}/status`);
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || "Failed to check analysis status.");
  }
  return data as AnalysisJobStatus;
}

export async function cancelAnalysis(analysisId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/api/analysis/${encodeURIComponent(analysisId)}/cancel`, {
    method: "POST",
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || "Failed to cancel analysis.");
  }
}

export async function fetchInvestigationBundle(analysisId: string): Promise<InvestigationBundle> {
  const res = await fetch(`${API_BASE}/api/analysis/${encodeURIComponent(analysisId)}`);
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || "Failed to load investigation details.");
  }
  return data as InvestigationBundle;
}

export async function listInvestigations(): Promise<InvestigationListItem[]> {
  const res = await fetch(`${API_BASE}/api/investigations?limit=25`);
  if (!res.ok) {
    return [];
  }
  return (await res.json()) as InvestigationListItem[];
}

export async function updateAlertStatus(
  analysisId: string,
  alertId: string,
  status: InvestigationStatus,
): Promise<void> {
  const res = await fetch(
    `${API_BASE}/api/analysis/${encodeURIComponent(analysisId)}/alerts/${encodeURIComponent(alertId)}`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    },
  );
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || "Failed to update alert status.");
  }
}

export async function updateIncidentStatus(
  analysisId: string,
  incidentId: string,
  status: InvestigationStatus,
): Promise<void> {
  const res = await fetch(
    `${API_BASE}/api/analysis/${encodeURIComponent(analysisId)}/incidents/${encodeURIComponent(incidentId)}`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    },
  );
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || "Failed to update incident status.");
  }
}

export interface PacketQueryParams {
  ip?: string;
  port?: string;
  protocol?: string;
  alert_id?: string;
  flow_id?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export async function queryPackets(
  analysisId: string,
  params: PacketQueryParams,
): Promise<{ total: number; packets: PacketEvidenceItem[] }> {
  const qs = new URLSearchParams();
  if (params.ip) qs.set("ip", params.ip);
  if (params.port) qs.set("port", params.port);
  if (params.protocol && params.protocol !== "ALL") qs.set("protocol", params.protocol);
  if (params.alert_id) qs.set("alert_id", params.alert_id);
  if (params.flow_id) qs.set("flow_id", params.flow_id);
  if (params.search) qs.set("search", params.search);
  qs.set("limit", String(params.limit ?? 50));
  qs.set("offset", String(params.offset ?? 0));

  const res = await fetch(
    `${API_BASE}/api/analysis/${encodeURIComponent(analysisId)}/packets?${qs.toString()}`,
  );
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || "Failed to load packet evidence.");
  }
  return data as { total: number; packets: PacketEvidenceItem[] };
}

export async function fetchPacketDetail(
  analysisId: string,
  packetIndex: number,
): Promise<{
  packet: PacketEvidenceItem;
  flow: Record<string, unknown> | null;
  alerts: Array<{ alert_id: string; title: string; severity: string }>;
}> {
  const res = await fetch(
    `${API_BASE}/api/analysis/${encodeURIComponent(analysisId)}/packets/${packetIndex}`,
  );
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || "Failed to load packet detail.");
  }
  return data;
}

export async function fetchAuditAndIntegrity(analysisId: string): Promise<{
  audit_logs: AuditLogEntry[];
  integrity: IntegrityVerification;
}> {
  const [auditRes, integRes] = await Promise.all([
    fetch(`${API_BASE}/api/analysis/${encodeURIComponent(analysisId)}/audit`),
    fetch(`${API_BASE}/api/analysis/${encodeURIComponent(analysisId)}/integrity`),
  ]);
  const auditJson = await auditRes.json();
  const integJson = await integRes.json();
  if (!auditRes.ok || !integRes.ok) {
    throw new Error("Failed to fetch forensic audit & integrity verification.");
  }
  return {
    audit_logs: auditJson.audit_logs ?? [],
    integrity: integJson as IntegrityVerification,
  };
}

export async function enrichThreatIntel(analysisId: string): Promise<ThreatIntelBundle> {
  const res = await fetch(
    `${API_BASE}/api/analysis/${encodeURIComponent(analysisId)}/threat-intel/enrich`,
    { method: "POST" },
  );
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || "Threat intelligence enrichment failed.");
  }
  return data.threat_intelligence as ThreatIntelBundle;
}

export function getReportDownloadUrl(analysisId: string, format: "html" | "pdf"): string {
  return `${API_BASE}/api/analysis/${encodeURIComponent(analysisId)}/report?format=${format}`;
}
