import React from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { InvestigationBundle } from "../types/forensics";
import { formatBytes } from "../utils/format";

interface TrafficAnalyticsProps {
  bundle: InvestigationBundle;
}

const PROTO_COLORS = ["#38bdf8", "#818cf8", "#34d399", "#fbbf24", "#f87171", "#a78bfa"];
const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#3b82f6",
  INFORMATIONAL: "#64748b",
};

export const TrafficAnalytics: React.FC<TrafficAnalyticsProps> = ({ bundle }) => {
  const directionData = [
    { name: "Outbound", bytes: bundle.summary.outbound_bytes, fill: "#f97316" },
    { name: "Inbound", bytes: bundle.summary.inbound_bytes, fill: "#38bdf8" },
  ];

  const hostChartData = bundle.top_hosts.slice(0, 8).map((h) => ({
    ip: h.ip,
    sent: h.bytes_sent,
    received: h.bytes_received,
  }));

  const portChartData = bundle.top_ports.slice(0, 8).map((p) => ({
    port: `:${p.port}`,
    flows: p.flow_count,
    bytes: p.total_bytes,
  }));

  const sevDist = bundle.summary.severity_distribution ?? {};
  const severityData = (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] as const).map(
    (sev) => ({
      severity: sev,
      count: Number(sevDist[sev] ?? 0),
      fill: SEV_COLORS[sev],
    }),
  );

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-200">Traffic Volume Over Time (Bytes)</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={bundle.traffic_over_time}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="timestamp" stroke="#94a3b8" fontSize={11} />
              <YAxis stroke="#94a3b8" fontSize={11} tickFormatter={(v) => formatBytes(Number(v))} />
              <Tooltip
                contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", fontSize: 12 }}
                formatter={(val) => formatBytes(Number(val))}
              />
              <Area type="monotone" dataKey="bytes" stroke="#38bdf8" fill="#38bdf8" fillOpacity={0.25} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-200">Inbound vs Outbound Bytes</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={directionData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="name" stroke="#94a3b8" fontSize={12} />
              <YAxis stroke="#94a3b8" fontSize={11} tickFormatter={(v) => formatBytes(Number(v))} />
              <Tooltip
                contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", fontSize: 12 }}
                formatter={(val) => formatBytes(Number(val))}
              />
              <Bar dataKey="bytes" radius={[6, 6, 0, 0]}>
                {directionData.map((entry) => (
                  <Cell key={entry.name} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-200">Protocol Distribution (Packets)</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={bundle.protocol_distribution}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="protocol" stroke="#94a3b8" fontSize={11} />
              <YAxis stroke="#94a3b8" fontSize={11} />
              <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", fontSize: 12 }} />
              <Bar dataKey="packet_count" name="Packets" radius={[6, 6, 0, 0]}>
                {bundle.protocol_distribution.map((row, idx) => (
                  <Cell key={row.protocol} fill={PROTO_COLORS[idx % PROTO_COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-200">Top Communicating Hosts</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={hostChartData} layout="vertical" margin={{ left: 24 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis type="number" stroke="#94a3b8" fontSize={11} tickFormatter={(v) => formatBytes(Number(v))} />
              <YAxis type="category" dataKey="ip" stroke="#94a3b8" fontSize={11} width={110} />
              <Tooltip
                contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", fontSize: 12 }}
                formatter={(val) => formatBytes(Number(val))}
              />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Bar dataKey="sent" name="Sent" stackId="a" fill="#f97316" />
              <Bar dataKey="received" name="Received" stackId="a" fill="#38bdf8" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-200">Top Destination Ports</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={portChartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="port" stroke="#94a3b8" fontSize={11} />
              <YAxis stroke="#94a3b8" fontSize={11} />
              <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", fontSize: 12 }} />
              <Bar dataKey="flows" name="Flows" fill="#818cf8" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-200">Active Alert Severity Distribution</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={severityData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="severity" stroke="#94a3b8" fontSize={11} />
              <YAxis stroke="#94a3b8" fontSize={11} allowDecimals={false} />
              <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", fontSize: 12 }} />
              <Bar dataKey="count" name="Active Alerts" radius={[6, 6, 0, 0]}>
                {severityData.map((entry) => (
                  <Cell key={entry.severity} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-200">
          DNS Query Frequency &amp; Suspicious Activity Over Time
        </h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={bundle.traffic_over_time}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="timestamp" stroke="#94a3b8" fontSize={11} />
              <YAxis stroke="#94a3b8" fontSize={11} />
              <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Line type="monotone" dataKey="dns_queries" name="DNS Queries" stroke="#34d399" strokeWidth={2} />
              <Line
                type="monotone"
                dataKey="suspicious_events"
                name="Suspicious Alerts"
                stroke="#ef4444"
                strokeWidth={2}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};
