import React, { useMemo, useState } from "react";
import { ArrowUpDown, ExternalLink, Filter, Layers, Network, Search, ShieldAlert, ShieldCheck } from "lucide-react";
import type { CorrelatedIncident, IncidentStatus, SecurityAlert } from "../types/forensics";
import { shortTimestamp } from "../utils/format";
import { SeverityBadge } from "./SeverityBadge";

interface IncidentsViewProps {
  incidents: CorrelatedIncident[];
  alerts: SecurityAlert[];
  onIncidentStatusChange: (incidentId: string, status: IncidentStatus) => Promise<void>;
  onInspectPackets: (opts: { alertId?: string; flowId?: string; incidentId?: string }) => void;
  onInspectAlert?: (alertId: string) => void;
  onInspectFlow?: (flowId: string) => void;
}

const STATUS_OPTIONS: IncidentStatus[] = [
  "Open",
  "Investigating",
  "Resolved",
  "Closed",
];

const SEV_ORDER: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFORMATIONAL: 1,
};

export const IncidentsView: React.FC<IncidentsViewProps> = ({
  incidents,
  alerts,
  onIncidentStatusChange,
  onInspectPackets,
  onInspectAlert,
  onInspectFlow,
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [includeSuppressed, setIncludeSuppressed] = useState<boolean>(true);
  const [search, setSearch] = useState<string>("");
  const [sortBy, setSortBy] = useState<"risk" | "severity" | "alerts" | "time">("risk");
  const [sortAsc, setSortAsc] = useState<boolean>(false);
  const [selectedId, setSelectedId] = useState<string | null>(incidents[0]?.incident_id ?? null);
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const list = incidents.filter((inc) => {
      if (!includeSuppressed && inc.suppressed) return false;
      if (severityFilter !== "ALL" && inc.overall_severity !== severityFilter) return false;
      if (q) {
        const hay = `${inc.incident_id} ${inc.incident_title} ${inc.source_hosts.join(" ")} ${inc.destination_hosts.join(" ")} ${inc.detection_categories.join(" ")}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    list.sort((a, b) => {
      let cmp = 0;
      if (sortBy === "risk") cmp = a.risk_score - b.risk_score;
      else if (sortBy === "severity")
        cmp = (SEV_ORDER[a.overall_severity] ?? 0) - (SEV_ORDER[b.overall_severity] ?? 0);
      else if (sortBy === "alerts") cmp = a.alert_count - b.alert_count;
      else cmp = a.first_seen_epoch - b.first_seen_epoch;
      return sortAsc ? cmp : -cmp;
    });
    return list;
  }, [incidents, severityFilter, includeSuppressed, search, sortBy, sortAsc]);

  const selected = useMemo(
    () => filtered.find((i) => i.incident_id === selectedId) ?? filtered[0] ?? null,
    [filtered, selectedId],
  );

  const constituentAlerts = useMemo(() => {
    if (!selected) return [];
    const idSet = new Set(selected.alert_ids);
    return alerts.filter((a) => idSet.has(a.alert_id));
  }, [selected, alerts]);

  const toggleSort = (col: "risk" | "severity" | "alerts" | "time") => {
    if (sortBy === col) setSortAsc(!sortAsc);
    else {
      setSortBy(col);
      setSortAsc(false);
    }
  };

  const handleStatus = async (incidentId: string, status: IncidentStatus) => {
    setUpdatingId(incidentId);
    try {
      await onIncidentStatusChange(incidentId, status);
    } finally {
      setUpdatingId(null);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-slate-800 bg-slate-900/70 p-3.5 text-xs">
        <div className="relative min-w-[220px] flex-1">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search correlated incidents, hosts, or categories..."
            className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-8 pr-3 text-xs text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-1.5">
          <Filter className="h-3.5 w-3.5 text-slate-400" />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2 text-xs text-slate-200"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>

        <label className="flex cursor-pointer items-center gap-2 text-slate-300">
          <input
            type="checkbox"
            checked={includeSuppressed}
            onChange={(e) => setIncludeSuppressed(e.target.checked)}
            className="rounded border-slate-600 bg-slate-950 text-sky-500"
          />
          Show Allowlisted Incidents
        </label>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <div className="xl:col-span-3 overflow-hidden rounded-xl border border-slate-800 bg-slate-900/70">
          <div className="max-h-[540px] overflow-auto">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-slate-950 text-[11px] uppercase text-slate-400">
                <tr>
                  <th className="px-3 py-2.5">
                    <button type="button" onClick={() => toggleSort("severity")} className="inline-flex items-center gap-1 hover:text-slate-200">
                      Severity <ArrowUpDown className="h-3 w-3" />
                    </button>
                  </th>
                  <th className="px-3 py-2.5">
                    <button type="button" onClick={() => toggleSort("risk")} className="inline-flex items-center gap-1 hover:text-slate-200">
                      Risk <ArrowUpDown className="h-3 w-3" />
                    </button>
                  </th>
                  <th className="px-3 py-2.5">Correlated Incident</th>
                  <th className="px-3 py-2.5">
                    <button type="button" onClick={() => toggleSort("alerts")} className="inline-flex items-center gap-1 hover:text-slate-200">
                      Alerts <ArrowUpDown className="h-3 w-3" />
                    </button>
                  </th>
                  <th className="px-3 py-2.5">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                      No correlated incidents match the current filters.
                    </td>
                  </tr>
                ) : (
                  filtered.map((inc) => {
                    const active = selected?.incident_id === inc.incident_id;
                    return (
                      <tr
                        key={inc.incident_id}
                        onClick={() => setSelectedId(inc.incident_id)}
                        className={`cursor-pointer transition ${
                          active ? "bg-sky-500/10" : "hover:bg-slate-800/40"
                        } ${inc.suppressed ? "opacity-75" : ""}`}
                      >
                        <td className="px-3 py-2.5">
                          <SeverityBadge severity={inc.overall_severity} />
                        </td>
                        <td className="px-3 py-2.5 font-mono font-semibold text-slate-200">
                          {inc.risk_score.toFixed(1)}
                        </td>
                        <td className="px-3 py-2.5">
                          <div className="font-medium text-slate-100">{inc.incident_title}</div>
                          <div className="mt-0.5 font-mono text-[11px] text-slate-400">
                            {inc.source_hosts.join(", ")} → {inc.destination_hosts.join(", ")}
                          </div>
                        </td>
                        <td className="px-3 py-2.5 font-mono text-slate-200">
                          {inc.alert_count}
                        </td>
                        <td className="px-3 py-2.5">
                          <span className="rounded border border-slate-700 bg-slate-950 px-2 py-0.5 text-[11px] text-slate-200">
                            {inc.status}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="xl:col-span-2 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          {!selected ? (
            <div className="py-12 text-center text-xs text-slate-500">
              Select an incident to drill down into correlated alerts and supporting packets.
            </div>
          ) : (
            <div className="space-y-4 text-xs">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={selected.overall_severity} />
                    <span className="font-mono text-[11px] text-sky-400">{selected.incident_id}</span>
                  </div>
                  <h3 className="mt-1.5 text-sm font-semibold text-slate-100">
                    {selected.incident_title}
                  </h3>
                </div>
                <select
                  value={selected.status}
                  disabled={updatingId === selected.incident_id}
                  onChange={(e) =>
                    void handleStatus(selected.incident_id, e.target.value as IncidentStatus)
                  }
                  className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs font-medium text-slate-100"
                >
                  {STATUS_OPTIONS.map((st) => (
                    <option key={st} value={st}>
                      {st}
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-2 rounded-lg border border-slate-800 bg-slate-950/70 p-3 text-[11px]">
                <div>Risk Score: <strong className="text-sky-400">{selected.risk_score} / 100</strong></div>
                <div>Confidence: <strong className="text-emerald-400">{Math.round(selected.overall_confidence * 100)}%</strong></div>
                <div>First Seen: <strong className="text-slate-200">{shortTimestamp(selected.first_seen)}</strong></div>
                <div>Last Seen: <strong className="text-slate-200">{shortTimestamp(selected.last_seen)}</strong></div>
              </div>

              {selected.suppressed && (
                <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2 text-emerald-200">
                  <ShieldCheck className="h-4 w-4 shrink-0" />
                  All constituent alerts in this incident matched allowlist rules.
                </div>
              )}

              <p className="text-slate-300">{selected.correlation_reason}</p>

              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => onInspectPackets({ incidentId: selected.incident_id })}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/10 px-3 py-1.5 text-xs font-medium text-sky-300 hover:bg-sky-500/20"
                >
                  <Layers className="h-3.5 w-3.5" />
                  Inspect Incident Packets ({selected.packet_indices.length} refs)
                </button>
                {selected.flow_ids.length > 0 && onInspectFlow && (
                  <button
                    type="button"
                    onClick={() => onInspectFlow(selected.flow_ids[0])}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-xs font-medium text-cyan-300 hover:bg-cyan-500/20"
                  >
                    <Network className="h-3.5 w-3.5" />
                    Inspect Flow ({selected.flow_ids[0]})
                  </button>
                )}
              </div>

              <div>
                <h4 className="mb-1.5 font-semibold text-slate-200">
                  Constituent Alerts ({constituentAlerts.length})
                </h4>
                <div className="max-h-48 space-y-1.5 overflow-y-auto">
                  {constituentAlerts.map((a) => (
                    <div
                      key={a.alert_id}
                      className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <SeverityBadge severity={a.severity} />
                        <div className="flex items-center gap-2">
                          {onInspectAlert && (
                            <button
                              type="button"
                              onClick={() => onInspectAlert(a.alert_id)}
                              className="inline-flex items-center gap-1 text-[11px] text-amber-300 hover:underline"
                            >
                              <ShieldAlert className="h-3 w-3" />
                              Alert
                            </button>
                          )}
                          {a.flow_id && onInspectFlow && (
                            <button
                              type="button"
                              onClick={() => onInspectFlow(a.flow_id!)}
                              className="text-[11px] text-cyan-300 hover:underline"
                            >
                              Flow
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => onInspectPackets({ alertId: a.alert_id })}
                            className="text-[11px] text-sky-400 hover:underline"
                          >
                            Packets ({a.packet_indices?.length ?? 0})
                          </button>
                        </div>
                      </div>
                      <div className="mt-1 font-medium text-slate-100">{a.title}</div>
                      <div className="mt-0.5 text-[11px] text-slate-400">
                        Risk {a.priority_score} • Conf {Math.round(a.confidence * 100)}% • {a.protocol}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {selected.mitre_mappings.length > 0 && (
                <div>
                  <h4 className="mb-1.5 font-semibold text-slate-200">MITRE ATT&amp;CK Techniques</h4>
                  <div className="space-y-1">
                    {selected.mitre_mappings.map((m) => (
                      <div key={m.technique_id} className="flex items-center justify-between rounded border border-slate-800 bg-slate-950/60 px-2.5 py-1.5">
                        <span className="font-mono text-indigo-300">{m.technique_id} — {m.technique_name}</span>
                        <a href={m.reference_url} target="_blank" rel="noopener noreferrer" className="text-sky-400">
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
