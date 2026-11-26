import React from "react";
import { Clock, Layers } from "lucide-react";
import type { TimelineEvent } from "../types/forensics";
import { shortTimestamp } from "../utils/format";
import { SeverityBadge } from "./SeverityBadge";

interface IncidentTimelineProps {
  events: TimelineEvent[];
  onInspectPackets: (opts: { alertId?: string }) => void;
}

export const IncidentTimeline: React.FC<IncidentTimelineProps> = ({
  events,
  onInspectPackets,
}) => {
  if (events.length === 0) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-8 text-center text-xs text-slate-500">
        No suspicious timeline events were recorded for this capture.
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
      <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-slate-200">
        <Clock className="h-4 w-4 text-sky-400" />
        Chronological Incident Timeline ({events.length} Events)
      </div>
      <div className="space-y-3">
        {events.map((ev) => (
          <div
            key={ev.event_id}
            className={`rounded-xl border border-slate-800 bg-slate-950/70 p-3.5 text-xs ${
              ev.suppressed ? "opacity-75" : ""
            }`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={ev.severity} />
                <span className="font-mono text-[11px] text-sky-300">
                  {shortTimestamp(ev.timestamp)}
                </span>
                <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-slate-200">
                  {ev.protocol}
                </span>
                <span className="text-slate-400">
                  Rule/Detector: <strong className="text-slate-200">{ev.detection_rule}</strong>
                </span>
                {ev.incident_id && (
                  <span className="rounded bg-sky-500/15 px-2 py-0.5 font-mono text-[10px] text-sky-300">
                    {ev.incident_id}
                  </span>
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
          </div>
        ))}
      </div>
    </div>
  );
};
