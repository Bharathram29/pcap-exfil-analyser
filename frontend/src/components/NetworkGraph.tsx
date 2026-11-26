import React, { useMemo, useState } from "react";
import {
  Background,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Filter, Layers, Search } from "lucide-react";
import type {
  GraphEdgeData,
  GraphNodeData,
  NetworkFlow,
  SecurityAlert,
} from "../types/forensics";
import { formatBytes } from "../utils/format";
import { SeverityBadge } from "./SeverityBadge";

interface NetworkGraphProps {
  nodes: GraphNodeData[];
  edges: GraphEdgeData[];
  flows: NetworkFlow[];
  alerts: SecurityAlert[];
  onInspectPackets: (opts: { ip?: string; flowId?: string }) => void;
}

export const NetworkGraph: React.FC<NetworkGraphProps> = ({
  nodes: rawNodes,
  edges: rawEdges,
  flows,
  alerts,
  onInspectPackets,
}) => {
  const [ipFilter, setIpFilter] = useState("");
  const [protoFilter, setProtoFilter] = useState("ALL");
  const [selectedIp, setSelectedIp] = useState<string | null>(
    rawNodes.find((n) => n.is_suspicious)?.ip ?? rawNodes[0]?.ip ?? null,
  );

  const protocols = useMemo(
    () => Array.from(new Set(rawEdges.flatMap((e) => e.protocols))).sort(),
    [rawEdges],
  );

  const filteredEdges = useMemo(() => {
    const q = ipFilter.trim().toLowerCase();
    return rawEdges.filter((e) => {
      if (protoFilter !== "ALL" && !e.protocols.includes(protoFilter)) return false;
      if (q && !e.source.toLowerCase().includes(q) && !e.target.toLowerCase().includes(q)) {
        return false;
      }
      return true;
    });
  }, [rawEdges, ipFilter, protoFilter]);

  const filteredNodes = useMemo(() => {
    const q = ipFilter.trim().toLowerCase();
    if (!q && protoFilter === "ALL") return rawNodes;
    const edgeHosts = new Set<string>();
    for (const e of filteredEdges) {
      edgeHosts.add(e.source);
      edgeHosts.add(e.target);
    }
    return rawNodes.filter(
      (n) => edgeHosts.has(n.ip) || (q && n.ip.toLowerCase().includes(q)),
    );
  }, [rawNodes, filteredEdges, ipFilter, protoFilter]);

  const flowNodes: Node[] = useMemo(() => {
    const internals = filteredNodes.filter((n) => !n.is_external);
    const externals = filteredNodes.filter((n) => n.is_external);

    const buildNode = (n: GraphNodeData, x: number, y: number): Node => {
      const borderColor = n.is_suspicious
        ? "#ef4444"
        : n.is_external
          ? "#f59e0b"
          : "#38bdf8";
      return {
        id: n.id,
        position: { x, y },
        data: {
          label: (
            <div className="text-left">
              <div className="font-mono text-xs font-semibold text-slate-100">{n.ip}</div>
              <div className="mt-0.5 text-[10px] text-slate-400">
                {n.is_external ? "External" : "Internal"} • {formatBytes(n.bytes_sent + n.bytes_received)}
                {n.alert_count > 0 ? ` • ${n.alert_count} alert(s)` : ""}
              </div>
            </div>
          ),
        },
        style: {
          background: n.is_suspicious ? "#2a0f14" : "#0f172a",
          border: `2px solid ${borderColor}`,
          borderRadius: 10,
          padding: "8px 12px",
          width: 210,
          color: "#f8fafc",
        },
      };
    };

    return [
      ...internals.map((n, i) => buildNode(n, 40 + (i % 2) * 240, 40 + Math.floor(i / 2) * 95)),
      ...externals.map((n, i) => buildNode(n, 560 + (i % 2) * 240, 40 + Math.floor(i / 2) * 95)),
    ];
  }, [filteredNodes]);

  const flowEdges: Edge[] = useMemo(
    () =>
      filteredEdges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        animated: e.is_suspicious,
        label: `${e.protocols.join("/")} (${formatBytes(e.total_bytes)})`,
        labelStyle: { fill: "#cbd5e1", fontSize: 10 },
        labelBgStyle: { fill: "#0f172a", fillOpacity: 0.85 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: e.is_suspicious ? "#ef4444" : "#38bdf8",
        },
        style: {
          stroke: e.is_suspicious ? "#ef4444" : e.total_bytes > 100_000 ? "#f97316" : "#38bdf8",
          strokeWidth: e.total_bytes > 100_000 || e.is_suspicious ? 2.5 : 1.5,
        },
      })),
    [filteredEdges],
  );

  const selectedNode = rawNodes.find((n) => n.ip === selectedIp) ?? null;
  const relatedFlows = useMemo(
    () =>
      selectedIp
        ? flows.filter((f) => f.initiator_ip === selectedIp || f.responder_ip === selectedIp)
        : [],
    [flows, selectedIp],
  );
  const relatedAlerts = useMemo(
    () =>
      selectedIp
        ? alerts.filter((a) => a.source_ip === selectedIp || a.destination_ip === selectedIp)
        : [],
    [alerts, selectedIp],
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-xs">
        <div className="relative min-w-[200px] flex-1">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
          <input
            type="text"
            value={ipFilter}
            onChange={(e) => setIpFilter(e.target.value)}
            placeholder="Filter graph by IP address..."
            className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-8 pr-3 text-xs text-slate-100 placeholder-slate-500"
          />
        </div>
        <div className="flex items-center gap-1.5">
          <Filter className="h-3.5 w-3.5 text-slate-400" />
          <select
            value={protoFilter}
            onChange={(e) => setProtoFilter(e.target.value)}
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
        <span className="text-slate-400">
          {flowNodes.length} host(s) • {flowEdges.length} link(s)
        </span>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2 h-[540px] overflow-hidden rounded-xl border border-slate-800 bg-slate-950">
          {flowNodes.length === 0 ? (
            <div className="flex h-full items-center justify-center text-xs text-slate-500">
              No IP communication relationships match the current filter.
            </div>
          ) : (
            <ReactFlow
              nodes={flowNodes}
              edges={flowEdges}
              fitView
              onNodeClick={(_evt, node) => setSelectedIp(node.id)}
            >
              <Background color="#1e293b" gap={20} />
              <Controls />
              <MiniMap
                nodeColor={(n) => (String(n.style?.border || "").includes("#ef4444") ? "#ef4444" : "#38bdf8")}
                maskColor="rgba(7, 11, 20, 0.75)"
                style={{ backgroundColor: "#0f172a" }}
              />
            </ReactFlow>
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
          <h3 className="text-sm font-semibold text-slate-100">Node Forensic Inspector</h3>
          <p className="mt-1 text-[11px] text-slate-400">
            Click any host node in the graph to inspect associated conversations, alerts, and packets.
          </p>

          {!selectedNode ? (
            <p className="mt-8 text-slate-500">No host selected.</p>
          ) : (
            <div className="mt-4 space-y-4">
              <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm font-bold text-sky-300">{selectedNode.ip}</span>
                  <span
                    className={`rounded px-2 py-0.5 text-[10px] font-semibold ${
                      selectedNode.is_external
                        ? "bg-amber-500/20 text-amber-300"
                        : "bg-sky-500/20 text-sky-300"
                    }`}
                  >
                    {selectedNode.is_external ? "External" : "Internal"}
                  </span>
                </div>
                <div className="mt-2 grid grid-cols-2 gap-2 text-[11px] text-slate-400">
                  <div>Sent: <strong className="text-slate-200">{formatBytes(selectedNode.bytes_sent)}</strong></div>
                  <div>Received: <strong className="text-slate-200">{formatBytes(selectedNode.bytes_received)}</strong></div>
                  <div>Flows: <strong className="text-slate-200">{selectedNode.flow_count}</strong></div>
                  <div>Alerts: <strong className="text-slate-200">{relatedAlerts.length}</strong></div>
                </div>
                <button
                  type="button"
                  onClick={() => onInspectPackets({ ip: selectedNode.ip })}
                  className="mt-3 inline-flex items-center gap-1.5 rounded border border-sky-500/40 bg-sky-500/10 px-2.5 py-1 text-[11px] text-sky-300 hover:bg-sky-500/20"
                >
                  <Layers className="h-3 w-3" />
                  View Host Packets
                </button>
              </div>

              <div>
                <h4 className="mb-1.5 font-semibold text-slate-200">Related Alerts ({relatedAlerts.length})</h4>
                <div className="max-h-36 space-y-1.5 overflow-y-auto">
                  {relatedAlerts.length === 0 ? (
                    <p className="text-slate-500">No alerts associated with this IP.</p>
                  ) : (
                    relatedAlerts.map((a) => (
                      <div key={a.alert_id} className="rounded border border-slate-800 bg-slate-950/60 p-2">
                        <div className="flex items-center justify-between gap-2">
                          <SeverityBadge severity={a.severity} />
                          <span className="font-mono text-[10px] text-slate-400">{a.protocol}</span>
                        </div>
                        <div className="mt-1 font-medium text-slate-200">{a.title}</div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div>
                <h4 className="mb-1.5 font-semibold text-slate-200">Related Flows ({relatedFlows.length})</h4>
                <div className="max-h-40 space-y-1.5 overflow-y-auto">
                  {relatedFlows.slice(0, 12).map((f) => (
                    <div
                      key={f.flow_id}
                      onClick={() => onInspectPackets({ flowId: f.flow_id })}
                      className="cursor-pointer rounded border border-slate-800 bg-slate-950/60 p-2 font-mono text-[11px] hover:border-sky-500/50"
                    >
                      <div className="text-slate-200">
                        {f.initiator_ip}:{f.initiator_port ?? "-"} → {f.responder_ip}:{f.responder_port ?? "-"}
                      </div>
                      <div className="mt-0.5 text-[10px] text-slate-400">
                        {f.application_protocol} • {formatBytes(f.total_bytes)} • {f.connection_state}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
