import React from "react";
import {
  Activity,
  AlertTriangle,
  Clock,
  FileText,
  Globe,
  Info,
  Layers,
  Network,
  Server,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { InvestigationBundle } from "../types/forensics";
import { formatBytes } from "../utils/format";

interface OverviewKpisProps {
  bundle: InvestigationBundle;
}

export const OverviewKpis: React.FC<OverviewKpisProps> = ({ bundle }) => {
  const { summary, capture_metadata: meta } = bundle;
  const totalAlertsCount = summary.total_alerts ?? bundle.alerts.length;
  const allowlistedAlertsCount = summary.allowlisted_alerts ?? summary.suppressed_events ?? 0;
  const correlatedIncidentsCount =
    summary.correlated_incidents ?? summary.total_incidents ?? bundle.incidents?.length ?? 0;
  const activeIncidentsCount = summary.active_incidents ?? bundle.active_incidents?.length ?? 0;
  const allowlistedIncidentsCount =
    summary.allowlisted_incidents ?? bundle.suppressed_incidents?.length ?? 0;

  const cards = [
    { label: "Total Packets", value: summary.total_packets.toLocaleString(), icon: Activity, tone: "text-sky-400" },
    { label: "Network Flows", value: summary.total_flows.toLocaleString(), icon: Network, tone: "text-cyan-400" },
    { label: "Unique Hosts", value: (summary.unique_source_ips + summary.unique_destination_ips).toLocaleString(), icon: Server, tone: "text-indigo-400" },
    { label: "Active Incidents", value: `${activeIncidentsCount} / ${correlatedIncidentsCount}`, icon: Layers, tone: "text-rose-400" },
    { label: "Active Alerts", value: `${summary.suspicious_events} / ${totalAlertsCount}`, icon: AlertTriangle, tone: "text-amber-400" },
    { label: "Critical Alerts", value: summary.critical_alerts.toLocaleString(), icon: ShieldAlert, tone: "text-red-400" },
    { label: "High Alerts", value: summary.high_alerts.toLocaleString(), icon: ShieldAlert, tone: "text-orange-400" },
    { label: "DNS Queries", value: summary.dns_queries.toLocaleString(), icon: ShieldCheck, tone: "text-emerald-400" },
    { label: "HTTP Requests", value: summary.http_requests.toLocaleString(), icon: FileText, tone: "text-teal-400" },
    { label: "Processing Time", value: `${summary.processing_duration_ms.toFixed(1)} ms`, icon: Clock, tone: "text-slate-300" },
  ];

  const tiResults = bundle.threat_intelligence?.results ?? [];

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-semibold text-slate-200">{meta.original_filename}</span>
              <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-sky-300">
                {meta.capture_format.toUpperCase()}
              </span>
              <span className="text-slate-400">{formatBytes(meta.file_size_bytes)}</span>
              <span className="text-slate-400">• {meta.link_layer_name || "Unknown Link Layer"}</span>
            </div>
            <div className="font-mono text-[11px] text-slate-400">
              Capture SHA-256: <span className="text-slate-200">{meta.sha256}</span>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-3 text-slate-400">
            <span>Outbound: <strong className="text-slate-200">{formatBytes(summary.outbound_bytes)}</strong></span>
            <span>Inbound: <strong className="text-slate-200">{formatBytes(summary.inbound_bytes)}</strong></span>
            <span className="rounded-full bg-slate-800 px-2.5 py-0.5 text-slate-300">
              {allowlistedAlertsCount} Allowlisted Alerts
            </span>
            <span className="rounded-full bg-slate-800 px-2.5 py-0.5 text-slate-300">
              {allowlistedIncidentsCount} Allowlisted Incidents
            </span>
          </div>
        </div>

        {meta.warnings.length > 0 && (
          <div className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-2.5 text-xs text-amber-200">
            <strong>Dissection Warnings:</strong> {meta.warnings.join(" | ")}
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {cards.map((card) => {
          const Icon = card.icon;
          return (
            <div
              key={card.label}
              className="rounded-xl border border-slate-800 bg-slate-900/70 p-3.5 shadow-sm"
            >
              <div className="flex items-center justify-between text-[11px] font-medium uppercase tracking-wider text-slate-400">
                <span>{card.label}</span>
                <Icon className={`h-4 w-4 ${card.tone}`} />
              </div>
              <div className="mt-2 text-2xl font-bold text-slate-100">{card.value}</div>
            </div>
          );
        })}
      </div>

      {tiResults.length > 0 && (
        <div className="rounded-xl border border-indigo-500/30 bg-indigo-950/20 p-3.5 text-xs">
          <div className="mb-1.5 flex items-center gap-2 font-semibold text-indigo-300">
            <Globe className="h-4 w-4" />
            Supplemental External Threat Intelligence (Non-Packet Context)
          </div>
          <div className="flex flex-wrap gap-2">
            {tiResults.slice(0, 8).map((ti, idx) => (
              <span
                key={`${ti.indicator}-${idx}`}
                className="rounded border border-slate-700 bg-slate-900/80 px-2 py-1 font-mono text-[11px] text-slate-200"
              >
                {ti.indicator}: <strong>{ti.reputation}</strong> ({ti.provider})
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="flex items-start gap-2.5 rounded-xl border border-sky-500/20 bg-sky-950/20 px-4 py-3 text-xs text-slate-300">
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" />
        <div>
          <strong className="text-sky-300">Forensic Methodology Note:</strong> Packet/flow metrics are{" "}
          <em>confirmed observations</em>; heuristics &amp; YAML triggers are <em>suspicious indicators</em>;
          correlated incidents &amp; MITRE ATT&amp;CK mappings are <em>inferred conclusions</em>. Encrypted TLS
          payloads are analysed via observable metadata only and are never fabricated as decrypted.
        </div>
      </div>
    </div>
  );
};
