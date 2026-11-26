import React, { useEffect, useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, Download, Search } from "lucide-react";
import type { InvestigationBundle } from "../types/forensics";
import { downloadTextFile, formatBytes, toCsv } from "../utils/format";

interface FlowsAndDnsViewProps {
  bundle: InvestigationBundle;
  focusedFlowId?: string;
  onInspectPackets: (opts: { flowId?: string; ip?: string }) => void;
}

export const FlowsAndDnsView: React.FC<FlowsAndDnsViewProps> = ({
  bundle,
  focusedFlowId,
  onInspectPackets,
}) => {
  const [flowSearch, setFlowSearch] = useState(focusedFlowId ?? "");
  const [protoFilter, setProtoFilter] = useState("ALL");
  const [page, setPage] = useState(0);
  const pageSize = 25;

  useEffect(() => {
    if (focusedFlowId) {
      setFlowSearch(focusedFlowId);
      setProtoFilter("ALL");
      setPage(0);
    }
  }, [focusedFlowId]);

  const dnsRecords = bundle.dns_analysis.records ?? [];
  const protocols = useMemo(
    () => Array.from(new Set(bundle.flows.map((f) => f.application_protocol))).sort(),
    [bundle.flows],
  );

  const filteredFlows = useMemo(() => {
    const q = flowSearch.trim().toLowerCase();
    return bundle.flows.filter((f) => {
      if (protoFilter !== "ALL" && f.application_protocol !== protoFilter) return false;
      if (q) {
        const hay = `${f.flow_id} ${f.initiator_ip} ${f.responder_ip} ${f.connection_state}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [bundle.flows, flowSearch, protoFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredFlows.length / pageSize));
  const pagedFlows = filteredFlows.slice(page * pageSize, (page + 1) * pageSize);

  const dnsFindings = bundle.active_alerts.filter((a) =>
    a.detector_types.includes("dns_tunnelling"),
  );
  const beaconFindings = bundle.active_alerts.filter((a) =>
    a.detector_types.includes("network_beaconing"),
  );
  const anomFindings = bundle.active_alerts.filter((a) =>
    a.detector_types.includes("protocol_anomaly"),
  );

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-slate-200">
            Reconstructed Bidirectional Flows ({filteredFlows.length} / {bundle.flows.length})
          </h3>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <div className="relative">
              <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-400" />
              <input
                type="text"
                value={flowSearch}
                onChange={(e) => {
                  setFlowSearch(e.target.value);
                  setPage(0);
                }}
                placeholder="Filter IP, flow ID, state..."
                className="rounded-lg border border-slate-700 bg-slate-950 py-1.5 pl-8 pr-3 text-xs text-slate-100 placeholder-slate-500"
              />
            </div>
            <select
              value={protoFilter}
              onChange={(e) => {
                setProtoFilter(e.target.value);
                setPage(0);
              }}
              className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-200"
            >
              <option value="ALL">All Protocols</option>
              {protocols.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => {
                const csv = toCsv(
                  ["Flow ID", "Initiator", "Initiator Port", "Responder", "Responder Port", "Proto", "Out Bytes", "In Bytes", "Ratio", "Bytes/s", "Conns/min", "State", "Retx Reliability"],
                  filteredFlows.map((f) => [
                    f.flow_id,
                    f.initiator_ip,
                    f.initiator_port,
                    f.responder_ip,
                    f.responder_port,
                    f.application_protocol,
                    f.bytes_initiator_to_responder,
                    f.bytes_responder_to_initiator,
                    f.outbound_to_inbound_ratio,
                    f.bytes_per_second,
                    f.connection_frequency_per_min,
                    f.connection_state,
                    f.retransmission_reliability,
                  ]),
                );
                downloadTextFile("flows_export.csv", csv, "text/csv;charset=utf-8");
              }}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-200 hover:border-sky-500/50"
            >
              <Download className="h-3.5 w-3.5" /> Export CSV
            </button>
          </div>
        </div>

        <div className="max-h-80 overflow-auto">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-slate-950 text-[11px] uppercase text-slate-400">
              <tr>
                <th className="px-3 py-2">Initiator</th>
                <th className="px-3 py-2">Responder</th>
                <th className="px-3 py-2">Proto</th>
                <th className="px-3 py-2">Out / In</th>
                <th className="px-3 py-2">Ratio</th>
                <th className="px-3 py-2">Rate / Size / IAT</th>
                <th className="px-3 py-2">State (Basis)</th>
                <th className="px-3 py-2">Packets</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {pagedFlows.map((f) => (
                <tr key={f.flow_id} className="hover:bg-slate-800/40">
                  <td className="px-3 py-2 font-mono text-[11px] text-slate-200">
                    {f.initiator_ip}:{f.initiator_port ?? "-"}
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-slate-200">
                    {f.responder_ip}:{f.responder_port ?? "-"}
                  </td>
                  <td className="px-3 py-2">{f.application_protocol}</td>
                  <td className="px-3 py-2">
                    {formatBytes(f.bytes_initiator_to_responder)} /{" "}
                    {formatBytes(f.bytes_responder_to_initiator)}
                  </td>
                  <td className="px-3 py-2 font-mono">
                    {f.outbound_to_inbound_ratio !== null ? f.outbound_to_inbound_ratio : "-"}
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-slate-400">
                    <div>
                      {f.avg_packet_size.toFixed(0)}B
                      {f.mean_iat_seconds !== null && f.mean_iat_seconds !== undefined
                        ? ` • ${f.mean_iat_seconds.toFixed(3)}s`
                        : ""}
                    </div>
                    {(f.bytes_per_second !== undefined || f.connection_frequency_per_min !== undefined) && (
                      <div className="text-[10px] text-slate-500">
                        {f.bytes_per_second !== undefined ? `${formatBytes(f.bytes_per_second)}/s` : ""}
                        {f.connection_frequency_per_min !== undefined
                          ? ` • ${f.connection_frequency_per_min}/min`
                          : ""}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-slate-400">
                    <div>{f.connection_state}</div>
                    {f.state_basis && (
                      <div className="text-[10px] text-slate-500">{f.state_basis}</div>
                    )}
                    {f.retransmission_reliability &&
                      f.retransmission_reliability !== "not_applicable" && (
                        <div className="text-[10px] text-amber-300/80">
                          Retx: {f.retransmission_count} ({f.retransmission_reliability})
                        </div>
                      )}
                  </td>
                  <td className="px-3 py-2">
                    <button
                      type="button"
                      onClick={() => onInspectPackets({ flowId: f.flow_id })}
                      className="rounded border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 text-[11px] text-sky-300 hover:bg-sky-500/20"
                    >
                      {f.total_packets} pkts
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-2.5 flex items-center justify-between text-xs text-slate-400">
          <span>
            Page {page + 1} of {totalPages} ({filteredFlows.length} flows)
          </span>
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              className="rounded border border-slate-700 p-1 hover:bg-slate-800 disabled:opacity-40"
            >
              <ChevronLeft className="h-3.5 w-3.5" />
            </button>
            <button
              type="button"
              disabled={page + 1 >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              className="rounded border border-slate-700 p-1 hover:bg-slate-800 disabled:opacity-40"
            >
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
          <h4 className="mb-2 font-semibold text-slate-200">
            DNS Tunnelling Indicators ({dnsFindings.length})
          </h4>
          {dnsFindings.length === 0 ? (
            <p className="text-slate-500">No DNS tunnelling findings detected.</p>
          ) : (
            dnsFindings.map((a) => (
              <div key={a.alert_id} className="mb-2 rounded border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="font-semibold text-amber-300">{String(a.evidence.parent_domain ?? a.destination_ip)}</div>
                <div className="mt-1 text-[11px] text-slate-400">
                  Queries: {String(a.evidence.query_count ?? "-")} • Max Entropy:{" "}
                  {String(a.evidence.max_entropy ?? "-")} • Max Len:{" "}
                  {String(a.evidence.max_query_length ?? "-")}
                </div>
              </div>
            ))
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
          <h4 className="mb-2 font-semibold text-slate-200">
            Beaconing Analysis ({beaconFindings.length})
          </h4>
          {beaconFindings.length === 0 ? (
            <p className="text-slate-500">No periodic beaconing patterns detected.</p>
          ) : (
            beaconFindings.map((a) => (
              <div key={a.alert_id} className="mb-2 rounded border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="font-mono font-semibold text-sky-300">
                  {a.destination_ip}:{a.destination_port}
                </div>
                <div className="mt-1 text-[11px] text-slate-400">
                  Conns: {String(a.evidence.connection_count ?? "-")} • Mean Interval:{" "}
                  {String(a.evidence.mean_interval_seconds ?? "-")}s • CV:{" "}
                  {String(a.evidence.interval_cv ?? "-")}
                </div>
              </div>
            ))
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
          <h4 className="mb-2 font-semibold text-slate-200">
            Protocol Anomalies ({anomFindings.length})
          </h4>
          {anomFindings.length === 0 ? (
            <p className="text-slate-500">No protocol anomalies detected.</p>
          ) : (
            anomFindings.map((a) => (
              <div key={a.alert_id} className="mb-2 rounded border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="font-semibold text-rose-300">{a.title}</div>
                <div className="mt-1 text-[11px] text-slate-400">
                  {a.source_ip ?? "-"} → {a.destination_ip ?? "-"}:{a.destination_port ?? "-"} ({a.protocol})
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <h3 className="mb-3 text-sm font-semibold text-slate-200">
            DNS Queries &amp; Responses ({bundle.dns_analysis.total_queries} queries)
          </h3>
          <div className="max-h-72 overflow-auto">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-slate-950 text-[11px] uppercase text-slate-400">
                <tr>
                  <th className="px-2.5 py-2">Type</th>
                  <th className="px-2.5 py-2">Query Name</th>
                  <th className="px-2.5 py-2">Len</th>
                  <th className="px-2.5 py-2">Code / Answers</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {dnsRecords.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-3 py-6 text-center text-slate-500">
                      No DNS packets observed.
                    </td>
                  </tr>
                ) : (
                  dnsRecords.slice(0, 100).map((d) => (
                    <tr key={`${d.packet_index}-${d.query_name}`} className="hover:bg-slate-800/40">
                      <td className="px-2.5 py-1.5 font-mono text-[11px]">
                        {d.is_response ? "RESP" : d.query_type || "QRY"}
                      </td>
                      <td className="px-2.5 py-1.5 font-mono text-[11px] text-slate-200 break-all">
                        {d.query_name || "-"}
                      </td>
                      <td className="px-2.5 py-1.5">{d.query_length}</td>
                      <td className="px-2.5 py-1.5 text-[11px] text-slate-400">
                        {d.response_code || "-"} {d.response_ips.join(", ")}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <h3 className="mb-3 text-sm font-semibold text-slate-200">
            HTTP &amp; TLS Metadata ({bundle.http_analysis.total_requests} HTTP,{" "}
            {bundle.tls_analysis.total_handshakes} TLS)
          </h3>
          <div className="max-h-72 space-y-3 overflow-auto text-xs">
            <div>
              <div className="mb-1 text-[11px] font-semibold uppercase text-slate-400">
                Observed HTTP Requests (Upload Total:{" "}
                {formatBytes(bundle.http_analysis.total_upload_payload_bytes)})
              </div>
              {bundle.http_analysis.sample_requests.length === 0 ? (
                <p className="text-slate-500">No cleartext HTTP requests observed.</p>
              ) : (
                bundle.http_analysis.sample_requests.map((r, idx) => (
                  <div
                    key={idx}
                    className="mb-1.5 rounded border border-slate-800 bg-slate-950/60 p-2 font-mono text-[11px]"
                  >
                    <span className="text-sky-300">{r.method}</span>{" "}
                    <span className="text-slate-200">{r.host || r.dst_ip}</span>
                    <span className="text-slate-400">{r.uri}</span>{" "}
                    <span className="text-amber-300">({formatBytes(r.payload_size)})</span>
                  </div>
                ))
              )}
            </div>

            <div>
              <div className="mb-1 text-[11px] font-semibold uppercase text-slate-400">
                Observable TLS SNIs (Payloads Encrypted)
              </div>
              {bundle.tls_analysis.observed_snis.length === 0 ? (
                <p className="text-slate-500">No TLS ClientHello SNIs observed.</p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {bundle.tls_analysis.observed_snis.map((s) => (
                    <span
                      key={s.sni}
                      className="rounded border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-[11px] text-slate-200"
                    >
                      {s.sni} ({s.count})
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
