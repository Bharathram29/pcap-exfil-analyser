import React, { useEffect, useMemo, useState } from "react";
import { ArrowUpDown, ExternalLink, Filter, Layers, Search, ShieldCheck } from "lucide-react";
import type { InvestigationStatus, SecurityAlert } from "../types/forensics";
import { shortTimestamp } from "../utils/format";
import { SeverityBadge } from "./SeverityBadge";

interface AlertManagementProps {
  alerts: SecurityAlert[];
  onStatusChange: (alertId: string, status: InvestigationStatus) => Promise<void>;
  onInspectPackets: (opts: { alertId?: string; flowId?: string }) => void;
}

const STATUS_OPTIONS: InvestigationStatus[] = [
  "New",
  "Investigating",
  "Confirmed Suspicious",
  "False Positive",
  "Closed",
];

const SEV_ORDER: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFORMATIONAL: 1,
};

export const AlertManagement: React.FC<AlertManagementProps> = ({
  alerts,
  onStatusChange,
  onInspectPackets,
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [protocolFilter, setProtocolFilter] = useState<string>("ALL");
  const [includeSuppressed, setIncludeSuppressed] = useState<boolean>(true);
  const [search, setSearch] = useState<string>("");
  const [sortBy, setSortBy] = useState<"priority" | "severity" | "timestamp" | "confidence">("priority");
  const [sortAsc, setSortAsc] = useState<boolean>(false);
  const [selectedId, setSelectedId] = useState<string | null>(alerts[0]?.alert_id ?? null);
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  useEffect(() => {
    setSelectedId(alerts[0]?.alert_id ?? null);
  }, [alerts]);

  const protocols = useMemo(
    () => Array.from(new Set(alerts.map((a) => a.protocol))).sort(),
    [alerts],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const list = alerts.filter((a) => {
      if (!includeSuppressed && a.suppressed) return false;
      if (severityFilter !== "ALL" && a.severity !== severityFilter) return false;
      if (protocolFilter !== "ALL" && a.protocol !== protocolFilter) return false;
      if (q) {
        const hay = `${a.title} ${a.source_ip ?? ""} ${a.destination_ip ?? ""} ${a.explanation}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    list.sort((a, b) => {
      let cmp = 0;
      if (sortBy === "priority") cmp = a.priority_score - b.priority_score;
      else if (sortBy === "severity") cmp = (SEV_ORDER[a.severity] ?? 0) - (SEV_ORDER[b.severity] ?? 0);
      else if (sortBy === "confidence") cmp = a.confidence - b.confidence;
      else cmp = a.timestamp_epoch - b.timestamp_epoch;
      return sortAsc ? cmp : -cmp;
    });
    return list;
  }, [alerts, severityFilter, protocolFilter, includeSuppressed, search, sortBy, sortAsc]);

  const selectedAlert = useMemo(
    () => filtered.find((a) => a.alert_id === selectedId) ?? filtered[0] ?? null,
    [filtered, selectedId],
  );

  const toggleSort = (col: "priority" | "severity" | "timestamp" | "confidence") => {
    if (sortBy === col) setSortAsc(!sortAsc);
    else {
      setSortBy(col);
      setSortAsc(false);
    }
  };

  const handleStatus = async (alertId: string, newStatus: InvestigationStatus) => {
    setUpdatingId(alertId);
    try {
      await onStatusChange(alertId, newStatus);
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
            placeholder="Search alerts, IP addresses, or evidence..."
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
            <option value="INFORMATIONAL">INFORMATIONAL</option>
          </select>

          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2 text-xs text-slate-200"
          >
            <option value="ALL">All Protocols</option>
            {protocols.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </div>

        <label className="flex cursor-pointer items-center gap-2 text-slate-300">
          <input
            type="checkbox"
            checked={includeSuppressed}
            onChange={(e) => setIncludeSuppressed(e.target.checked)}
            className="rounded border-slate-600 bg-slate-950 text-sky-500"
          />
          Show Allowlisted / Suppressed
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
                    <button type="button" onClick={() => toggleSort("priority")} className="inline-flex items-center gap-1 hover:text-slate-200">
                      Risk <ArrowUpDown className="h-3 w-3" />
                    </button>
                  </th>
                  <th className="px-3 py-2.5">Alert</th>
                  <th className="px-3 py-2.5">Endpoints</th>
                  <th className="px-3 py-2.5">
                    <button type="button" onClick={() => toggleSort("confidence")} className="inline-flex items-center gap-1 hover:text-slate-200">
                      Conf <ArrowUpDown className="h-3 w-3" />
                    </button>
                  </th>
                  <th className="px-3 py-2.5">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                      No alerts match the current filters.
                    </td>
                  </tr>
                ) : (
                  filtered.map((alert) => {
                    const active = selectedAlert?.alert_id === alert.alert_id;
                    return (
                      <tr
                        key={alert.alert_id}
                        onClick={() => setSelectedId(alert.alert_id)}
                        className={`cursor-pointer transition ${
                          active ? "bg-sky-500/10" : "hover:bg-slate-800/40"
                        } ${alert.suppressed ? "opacity-75" : ""}`}
                      >
                        <td className="px-3 py-2.5">
                          <SeverityBadge severity={alert.severity} />
                        </td>
                        <td className="px-3 py-2.5 font-mono font-semibold text-slate-200">
                          {alert.priority_score.toFixed(1)}
                        </td>
                        <td className="px-3 py-2.5">
                          <div className="font-medium text-slate-100">{alert.title}</div>
                          <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-slate-400">
                            <span>{alert.protocol}</span>
                            {alert.incident_id && (
                              <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-sky-300">
                                {alert.incident_id}
                              </span>
                            )}
                            {alert.suppressed && (
                              <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">
                                Allowlisted
                              </span>
                            )}
                            {alert.mitre_mappings.map((m) => (
                              <span key={m.technique_id} className="rounded bg-indigo-500/20 px-1.5 py-0.5 font-mono text-[10px] text-indigo-300">
                                {m.technique_id}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="px-3 py-2.5 font-mono text-[11px] text-slate-300">
                          {alert.source_ip || "-"} → {alert.destination_ip || "-"}
                          {alert.destination_port ? `:${alert.destination_port}` : ""}
                        </td>
                        <td className="px-3 py-2.5 text-slate-300">
                          {Math.round(alert.confidence * 100)}%
                        </td>
                        <td className="px-3 py-2.5">
                          <span className="rounded border border-slate-700 bg-slate-950 px-2 py-0.5 text-[11px] text-slate-200">
                            {alert.status}
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
          {!selectedAlert ? (
            <div className="py-12 text-center text-xs text-slate-500">
              Select an alert from the table to inspect evidence and MITRE ATT&amp;CK details.
            </div>
          ) : (
            <div className="space-y-4 text-xs">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={selectedAlert.severity} />
                    <span className="font-mono text-[11px] text-slate-400">
                      {shortTimestamp(selectedAlert.timestamp)}
                    </span>
                  </div>
                  <h3 className="mt-2 text-sm font-semibold text-slate-100">
                    {selectedAlert.title}
                  </h3>
                </div>

                <select
                  value={selectedAlert.status}
                  disabled={updatingId === selectedAlert.alert_id}
                  onChange={(e) =>
                    void handleStatus(
                      selectedAlert.alert_id,
                      e.target.value as InvestigationStatus,
                    )
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

              {selectedAlert.allowlist_match && (
                <div className="flex items-start gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-emerald-200">
                  <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
                  <div>
                    <strong>Allowlist Match ({selectedAlert.allowlist_match.category}):</strong>{" "}
                    {selectedAlert.allowlist_match.matched_entry} —{" "}
                    {selectedAlert.allowlist_match.reason}
                  </div>
                </div>
              )}

              <p className="leading-relaxed text-slate-300">{selectedAlert.explanation}</p>

              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() =>
                    onInspectPackets({
                      alertId: selectedAlert.alert_id,
                      flowId: selectedAlert.flow_id ?? undefined,
                    })
                  }
                  className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/10 px-3 py-1.5 text-xs font-medium text-sky-300 hover:bg-sky-500/20"
                >
                  <Layers className="h-3.5 w-3.5" />
                  Inspect Supporting Packets ({selectedAlert.packet_indices?.length ?? 0} refs)
                </button>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
                <div className="mb-1.5 flex items-center justify-between font-semibold text-slate-200">
                  <span>Explainable Risk &amp; Confidence Score</span>
                  <span className="font-mono text-sky-400">
                    Risk {selectedAlert.priority_score} / 100 • Conf {Math.round(selectedAlert.confidence * 100)}%
                  </span>
                </div>
                <p className="font-mono text-[11px] text-slate-400">
                  {selectedAlert.priority_breakdown.rationale}
                </p>
                {selectedAlert.priority_breakdown.confidence_rationale && (
                  <p className="mt-1 font-mono text-[11px] text-emerald-400/90">
                    {selectedAlert.priority_breakdown.confidence_rationale}
                  </p>
                )}
              </div>

              {selectedAlert.mitre_mappings.length > 0 && (
                <div>
                  <h4 className="mb-1.5 font-semibold text-slate-200">MITRE ATT&amp;CK Techniques</h4>
                  <div className="space-y-1.5">
                    {selectedAlert.mitre_mappings.map((m) => (
                      <div
                        key={m.technique_id}
                        className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-indigo-300">
                            {m.technique_id} — {m.technique_name}
                          </span>
                          <a
                            href={m.reference_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-sky-400 hover:underline"
                          >
                            MITRE <ExternalLink className="h-3 w-3" />
                          </a>
                        </div>
                        <div className="mt-1 text-[11px] text-slate-400">
                          Tactic: {m.tactic} | Confidence: {m.confidence_level} — {m.reason}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <h4 className="mb-1.5 font-semibold text-slate-200">Recommended Investigation Steps</h4>
                <ul className="list-disc space-y-1 pl-4 text-slate-300">
                  {selectedAlert.recommended_investigation_steps.map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ul>
              </div>

              <div>
                <h4 className="mb-1.5 font-semibold text-slate-200">Supporting Forensic Evidence</h4>
                <pre className="max-h-48 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-2.5 font-mono text-[11px] text-slate-300">
                  {JSON.stringify(selectedAlert.evidence, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
