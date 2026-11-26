import React, { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Clock, Layers, Search } from "lucide-react";
import type { TimelineEvent } from "../types/forensics";
import { shortTimestamp } from "../utils/format";
import { SeverityBadge } from "./SeverityBadge";

interface IncidentTimelineProps {
  events: TimelineEvent[];
  onInspectPackets: (opts: { alertId?: string; incidentId?: string }) => void;
}

export const IncidentTimeline: React.FC<IncidentTimelineProps> = ({
  events,
  onInspectPackets,
}) => {
  const [hostFilter, setHostFilter] = useState("");
  const [protoFilter, setProtoFilter] = useState("ALL");
  const [incidentFilter, setIncidentFilter] = useState("ALL");
  const [timeStart, setTimeStart] = useState("");
  const [timeEnd, setTimeEnd] = useState("");
  const [groupSimilar, setGroupSimilar] = useState(true);
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({});

  const protocols = useMemo(
    () => Array.from(new Set(events.map((e) => e.protocol))).sort(),
    [events],
  );
  const incidentIds = useMemo(
    () => Array.from(new Set(events.map((e) => e.incident_id).filter(Boolean) as string[])).sort(),
    [events],
  );

  const filtered = useMemo(() => {
    const q = hostFilter.trim().toLowerCase();
    const startTs = timeStart ? Date.parse(timeStart) / 1000 : null;
    const endTs = timeEnd ? Date.parse(timeEnd) / 1000 : null;
    return events.filter((ev) => {
      if (protoFilter !== "ALL" && ev.protocol !== protoFilter) return false;
      if (incidentFilter !== "ALL" && ev.incident_id !== incidentFilter) return false;
      if (startTs !== null && !Number.isNaN(startTs) && ev.timestamp_epoch < startTs) return false;
      if (endTs !== null && !Number.isNaN(endTs) && ev.timestamp_epoch > endTs) return false;
      if (q) {
        const hay = `${ev.source_ip ?? ""} ${ev.destination_ip ?? ""} ${ev.detection_rule} ${ev.evidence_summary}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [events, hostFilter, protoFilter, incidentFilter, timeStart, timeEnd]);

  const groupedItems = useMemo(() => {
    if (!groupSimilar) {
      return filtered.map((ev) => ({ key: ev.event_id, events: [ev] }));
    }
    const groups: Array<{ key: string; events: TimelineEvent[] }> = [];
    for (const ev of filtered) {
      const sig = `${ev.source_ip ?? ""}|${ev.destination_ip ?? ""}|${ev.protocol}|${ev.detection_rule}`;
      const last = groups[groups.length - 1];
      if (
        last &&
        `${last.events[0].source_ip ?? ""}|${last.events[0].destination_ip ?? ""}|${last.events[0].protocol}|${last.events[0].detection_rule}` ===
          sig
      ) {
        last.events.push(ev);
      } else {
        groups.push({ key: `${sig}:${ev.event_id}`, events: [ev] });
      }
    }
    return groups;
  }, [filtered, groupSimilar]);

  if (events.length === 0) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-8 text-center text-xs text-slate-500">
        No suspicious timeline events were recorded for this capture.
      </div>
    );
  }

  return (
    <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2 text-sm font-semibold text-slate-200">
        <span className="inline-flex items-center gap-2">
          <Clock className="h-4 w-4 text-sky-400" />
          Chronological Incident Timeline ({filtered.length} / {events.length} Events)
        </span>
        <label className="flex cursor-pointer items-center gap-1.5 text-xs font-normal text-slate-300">
          <input
            type="checkbox"
            checked={groupSimilar}
            onChange={(e) => setGroupSimilar(e.target.checked)}
            className="rounded border-slate-600 bg-slate-950 text-sky-500"
          />
          Group Repeated Related Events
        </label>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        <div className="relative min-w-[180px] flex-1">
          <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-400" />
          <input
            type="text"
            value={hostFilter}
            onChange={(e) => setHostFilter(e.target.value)}
            placeholder="Filter host IP, detector, summary..."
            className="w-full rounded-lg border border-slate-700 bg-slate-950 py-1.5 pl-8 pr-3 text-xs text-slate-100 placeholder-slate-500"
          />
        </div>
        <select
          value={protoFilter}
          onChange={(e) => setProtoFilter(e.target.value)}
          className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-200"
        >
          <option value="ALL">All Protocols</option>
          {protocols.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <select
          value={incidentFilter}
          onChange={(e) => setIncidentFilter(e.target.value)}
          className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-200"
        >
          <option value="ALL">All Incidents</option>
          {incidentIds.map((id) => (
            <option key={id} value={id}>
              {id}
            </option>
          ))}
        </select>
        <input
          type="text"
          value={timeStart}
          onChange={(e) => setTimeStart(e.target.value)}
          placeholder="Start ISO UTC"
          className="w-40 rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500"
        />
        <input
          type="text"
          value={timeEnd}
          onChange={(e) => setTimeEnd(e.target.value)}
          placeholder="End ISO UTC"
          className="w-40 rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500"
        />
      </div>

      <div className="space-y-3">
        {groupedItems.map((group) => {
          const ev = group.events[0];
          const isMulti = group.events.length > 1;
          const expanded = Boolean(expandedGroups[group.key]);
          return (
            <div
              key={group.key}
              className={`rounded-xl border border-slate-800 bg-slate-950/70 p-3.5 text-xs ${
                ev.suppressed ? "opacity-75" : ""
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={ev.severity} />
                  <span className="font-mono text-[11px] text-sky-300">
                    {shortTimestamp(ev.timestamp)}
                    {isMulti ? ` → ${shortTimestamp(group.events[group.events.length - 1].timestamp)}` : ""}
                  </span>
                  <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-slate-200">
                    {ev.protocol}
                  </span>
                  <span className="text-slate-400">
                    Rule/Detector: <strong className="text-slate-200">{ev.detection_rule}</strong>
                  </span>
                  {isMulti && (
                    <button
                      type="button"
                      onClick={() =>
                        setExpandedGroups((prev) => ({ ...prev, [group.key]: !prev[group.key] }))
                      }
                      className="inline-flex items-center gap-1 rounded bg-amber-500/15 px-2 py-0.5 text-[10px] font-semibold text-amber-300"
                    >
                      {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                      {group.events.length} Grouped Events
                    </button>
                  )}
                  {ev.incident_id && (
                    <button
                      type="button"
                      onClick={() => onInspectPackets({ incidentId: ev.incident_id ?? undefined })}
                      className="rounded bg-sky-500/15 px-2 py-0.5 font-mono text-[10px] text-sky-300 hover:bg-sky-500/25"
                    >
                      {ev.incident_id}
                    </button>
                  )}
                  {ev.suppressed && (
                    <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-slate-300">
                      Allowlisted
                    </span>
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-1.5">
                  {ev.mitre_techniques.map((tid) => (
                    <span key={tid} className="rounded bg-indigo-500/20 px-2 py-0.5 font-mono text-[10px] text-indigo-300">
                      {tid}
                    </span>
                  ))}
                  {ev.alert_id && (
                    <button
                      type="button"
                      onClick={() => onInspectPackets({ alertId: ev.alert_id ?? undefined })}
                      className="inline-flex items-center gap-1 rounded border border-sky-500/40 bg-sky-500/10 px-2 py-0.5 text-[10px] text-sky-300 hover:bg-sky-500/20"
                    >
                      <Layers className="h-3 w-3" />
                      Packets ({ev.packet_indices?.length ?? 0})
                    </button>
                  )}
                </div>
              </div>
              <div className="mt-2 font-mono text-[11px] text-slate-300">
                {ev.source_ip || "-"} → {ev.destination_ip || "-"}
              </div>
              <p className="mt-1.5 text-slate-300">{ev.evidence_summary}</p>
              {isMulti && expanded && (
                <div className="mt-2 space-y-1.5 border-l-2 border-slate-700 pl-3">
                  {group.events.map((sub) => (
                    <div key={sub.event_id} className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>
                        {shortTimestamp(sub.timestamp)} — {sub.evidence_summary}
                      </span>
                      {sub.alert_id && (
                        <button
                          type="button"
                          onClick={() => onInspectPackets({ alertId: sub.alert_id ?? undefined })}
                          className="shrink-0 pl-2 text-sky-400 hover:underline"
                        >
                          Packets ({sub.packet_indices?.length ?? 0})
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
