import React, { useCallback, useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, FileSearch, Filter, Loader2, Search, X } from "lucide-react";
import { fetchPacketDetail, queryPackets } from "../services/api";
import type { PacketEvidenceItem } from "../types/forensics";
import { shortTimestamp } from "../utils/format";

interface PacketEvidenceViewProps {
  analysisId: string;
  initialFilter?: { alertId?: string; flowId?: string; ip?: string };
  onClearFilter?: () => void;
}

export const PacketEvidenceView: React.FC<PacketEvidenceViewProps> = ({
  analysisId,
  initialFilter,
  onClearFilter,
}) => {
  const [ipFilter, setIpFilter] = useState(initialFilter?.ip ?? "");
  const [portFilter, setPortFilter] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("ALL");
  const [alertIdFilter, setAlertIdFilter] = useState(initialFilter?.alertId ?? "");
  const [flowIdFilter, setFlowIdFilter] = useState(initialFilter?.flowId ?? "");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const limit = 50;

  const [packets, setPackets] = useState<PacketEvidenceItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<{
    packet: PacketEvidenceItem;
    flow: Record<string, unknown> | null;
    alerts: Array<{ alert_id: string; title: string; severity: string }>;
  } | null>(null);

  useEffect(() => {
    setIpFilter(initialFilter?.ip ?? "");
    setAlertIdFilter(initialFilter?.alertId ?? "");
    setFlowIdFilter(initialFilter?.flowId ?? "");
    setOffset(0);
  }, [initialFilter]);

  const loadPackets = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await queryPackets(analysisId, {
        ip: ipFilter || undefined,
        port: portFilter || undefined,
        protocol: protocolFilter,
        alert_id: alertIdFilter || undefined,
        flow_id: flowIdFilter || undefined,
        search: search || undefined,
        limit,
        offset,
      });
      setPackets(res.packets);
      setTotal(res.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load packets.");
    } finally {
      setLoading(false);
    }
  }, [analysisId, ipFilter, portFilter, protocolFilter, alertIdFilter, flowIdFilter, search, offset]);

  useEffect(() => {
    void loadPackets();
  }, [loadPackets]);

  const openDetail = async (packetIndex: number) => {
    try {
      const detail = await fetchPacketDetail(analysisId, packetIndex);
      setSelectedDetail(detail);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to inspect packet.");
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2.5 rounded-xl border border-slate-800 bg-slate-900/70 p-3.5 text-xs">
        <div className="relative min-w-[180px] flex-1">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setOffset(0);
            }}
            placeholder="Search decoded fields, summary, domains..."
            className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-8 pr-3 text-xs text-slate-100 placeholder-slate-500"
          />
        </div>

        <input
          type="text"
          value={ipFilter}
          onChange={(e) => {
            setIpFilter(e.target.value);
            setOffset(0);
          }}
          placeholder="Filter IP"
          className="w-36 rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2 text-xs text-slate-100 placeholder-slate-500"
        />

        <input
          type="text"
          value={portFilter}
          onChange={(e) => {
            setPortFilter(e.target.value.replace(/[^0-9]/g, ""));
            setOffset(0);
          }}
          placeholder="Port"
          className="w-24 rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2 text-xs text-slate-100 placeholder-slate-500"
        />

        <div className="flex items-center gap-1.5">
          <Filter className="h-3.5 w-3.5 text-slate-400" />
          <select
            value={protocolFilter}
            onChange={(e) => {
              setProtocolFilter(e.target.value);
              setOffset(0);
            }}
            className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2 text-xs text-slate-200"
          >
            <option value="ALL">All Protocols</option>
            <option value="DNS">DNS</option>
            <option value="HTTP">HTTP</option>
            <option value="TLS">TLS</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
            <option value="ARP">ARP</option>
          </select>
        </div>

        {(alertIdFilter || flowIdFilter || ipFilter) && (
          <button
            type="button"
            onClick={() => {
              setAlertIdFilter("");
              setFlowIdFilter("");
              setIpFilter("");
              setPortFilter("");
              setSearch("");
              setOffset(0);
              onClearFilter?.();
            }}
            className="inline-flex items-center gap-1 rounded-lg border border-amber-500/40 bg-amber-500/10 px-2.5 py-1.5 text-[11px] text-amber-300 hover:bg-amber-500/20"
          >
            <X className="h-3 w-3" />
            Clear Active Drill-Down
          </button>
        )}
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-300">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <div className="xl:col-span-3 overflow-hidden rounded-xl border border-slate-800 bg-slate-900/70">
          <div className="flex items-center justify-between border-b border-slate-800 px-3.5 py-2.5 text-xs text-slate-400">
            <span>
              {loading ? (
                <span className="inline-flex items-center gap-1.5 text-sky-400">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading packet evidence...
                </span>
              ) : (
                `Showing ${packets.length} of ${total.toLocaleString()} packets`
              )}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - limit))}
                className="rounded border border-slate-700 p-1 hover:bg-slate-800 disabled:opacity-40"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
              </button>
              <span className="font-mono text-[11px]">
                {total === 0 ? 0 : offset + 1}-{Math.min(offset + limit, total)}
              </span>
              <button
                type="button"
                disabled={offset + limit >= total}
                onClick={() => setOffset(offset + limit)}
                className="rounded border border-slate-700 p-1 hover:bg-slate-800 disabled:opacity-40"
              >
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          <div className="max-h-[520px] overflow-auto">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-slate-950 text-[11px] uppercase text-slate-400">
                <tr>
                  <th className="px-3 py-2">#</th>
                  <th className="px-3 py-2">Time</th>
                  <th className="px-3 py-2">Source → Destination</th>
                  <th className="px-3 py-2">Proto</th>
                  <th className="px-3 py-2">Len</th>
                  <th className="px-3 py-2">Alerts</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {packets.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                      No packets match the current filters.
                    </td>
                  </tr>
                ) : (
                  packets.map((p) => {
                    const active = selectedDetail?.packet.packet_index === p.packet_index;
                    return (
                      <tr
                        key={p.packet_index}
                        onClick={() => void openDetail(p.packet_index)}
                        className={`cursor-pointer transition ${
                          active ? "bg-sky-500/10" : "hover:bg-slate-800/40"
                        }`}
                      >
                        <td className="px-3 py-2 font-mono text-sky-400">{p.packet_index}</td>
                        <td className="px-3 py-2 font-mono text-[11px] text-slate-400">
                          {shortTimestamp(p.timestamp_utc)}
                        </td>
                        <td className="px-3 py-2 font-mono text-[11px] text-slate-200">
                          {p.src_ip ?? "-"}:{p.src_port ?? "-"} → {p.dst_ip ?? "-"}:{p.dst_port ?? "-"}
                        </td>
                        <td className="px-3 py-2">{p.protocol}</td>
                        <td className="px-3 py-2 font-mono">{p.length}</td>
                        <td className="px-3 py-2">
                          {p.alert_ids.length > 0 ? (
                            <span className="rounded bg-red-500/20 px-1.5 py-0.5 font-mono text-[10px] text-red-300">
                              {p.alert_ids.length}
                            </span>
                          ) : (
                            <span className="text-slate-600">-</span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="xl:col-span-2 rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-100">
            <FileSearch className="h-4 w-4 text-sky-400" />
            Packet Forensic Inspector
          </div>

          {!selectedDetail ? (
            <p className="py-12 text-center text-slate-500">
              Select a packet row to inspect decoded headers, flow association, and linked alerts.
            </p>
          ) : (
            <div className="space-y-3">
              <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 font-mono text-[11px]">
                <div className="text-sky-300">
                  Packet #{selectedDetail.packet.packet_index} • {selectedDetail.packet.protocol} •{" "}
                  {selectedDetail.packet.length} bytes
                </div>
                <div className="mt-1 text-slate-300">
                  {selectedDetail.packet.src_ip ?? "-"}:{selectedDetail.packet.src_port ?? "-"} →{" "}
                  {selectedDetail.packet.dst_ip ?? "-"}:{selectedDetail.packet.dst_port ?? "-"}
                </div>
                <div className="mt-1 text-slate-400">
                  Flow ID: {selectedDetail.packet.flow_id ?? "None"} • TTL:{" "}
                  {selectedDetail.packet.ttl ?? "-"}
                </div>
              </div>

              {selectedDetail.alerts.length > 0 && (
                <div>
                  <h4 className="mb-1 font-semibold text-slate-200">Linked Alerts</h4>
                  <div className="space-y-1">
                    {selectedDetail.alerts.map((a) => (
                      <div
                        key={a.alert_id}
                        className="rounded border border-slate-800 bg-slate-950/60 px-2.5 py-1.5 text-[11px]"
                      >
                        <strong className="text-amber-300">[{a.severity}]</strong> {a.title}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <h4 className="mb-1 font-semibold text-slate-200">Decoded Protocol Metadata</h4>
                <pre className="max-h-72 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-2.5 font-mono text-[11px] text-slate-300">
                  {JSON.stringify(selectedDetail.packet.decoded_fields, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
