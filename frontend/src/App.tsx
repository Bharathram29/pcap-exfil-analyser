import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  Clock,
  Download,
  FileCode2,
  FileSearch,
  GitBranch,
  Layers,
  Shield,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { AlertManagement } from "./components/AlertManagement";
import { FlowsAndDnsView } from "./components/FlowsAndDnsView";
import { IncidentTimeline } from "./components/IncidentTimeline";
import { IncidentsView } from "./components/IncidentsView";
import { NetworkGraph } from "./components/NetworkGraph";
import { OverviewKpis } from "./components/OverviewKpis";
import { PacketEvidenceView } from "./components/PacketEvidenceView";
import { TrafficAnalytics } from "./components/TrafficAnalytics";
import { UploadPanel } from "./components/UploadPanel";
import {
  cancelAnalysis,
  fetchAnalysisStatus,
  fetchAuditAndIntegrity,
  fetchInvestigationBundle,
  getReportDownloadUrl,
  listInvestigations,
  startAnalysis,
  updateAlertStatus,
  updateIncidentStatus,
  uploadPcapWithProgress,
} from "./services/api";
import type {
  AuditLogEntry,
  IntegrityVerification,
  InvestigationBundle,
  InvestigationListItem,
  InvestigationStatus,
} from "./types/forensics";

type TabId = "overview" | "incidents" | "alerts" | "graph" | "timeline" | "flows" | "packets";

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [bundle, setBundle] = useState<InvestigationBundle | null>(null);
  const [history, setHistory] = useState<InvestigationListItem[]>([]);
  const [uploadProgress, setUploadProgress] = useState<number>(0);
  const [analysisProgress, setAnalysisProgress] = useState<number>(0);
  const [analysisStage, setAnalysisStage] = useState<string>("");
  const [runningId, setRunningId] = useState<string | null>(null);
  const [stage, setStage] = useState<"idle" | "uploading" | "analyzing" | "complete" | "error">("idle");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [packetDrillFilter, setPacketDrillFilter] = useState<
    { alertId?: string; flowId?: string; ip?: string } | undefined
  >(undefined);
  const [showIntegrityModal, setShowIntegrityModal] = useState(false);
  const [integrityData, setIntegrityData] = useState<{
    audit_logs: AuditLogEntry[];
    integrity: IntegrityVerification;
  } | null>(null);
  const cancelledRef = useRef(false);

  const refreshHistory = useCallback(async () => {
    const items = await listInvestigations();
    setHistory(items);
    return items;
  }, []);

  const loadInvestigation = useCallback(async (analysisId: string) => {
    try {
      setErrorMessage(null);
      const data = await fetchInvestigationBundle(analysisId);
      if (data.status === "COMPLETED") {
        setBundle(data);
        setStage("complete");
      } else if (data.status === "INGESTED") {
        setStage("analyzing");
        setAnalysisProgress(10);
        setAnalysisStage("Running analysis pipeline...");
        await startAnalysis(analysisId, false);
        const completed = await fetchInvestigationBundle(analysisId);
        setBundle(completed);
        setStage("complete");
      }
    } catch (err) {
      setStage("error");
      setErrorMessage(err instanceof Error ? err.message : "Failed to load investigation.");
    }
  }, []);

  useEffect(() => {
    void (async () => {
      const items = await refreshHistory();
      const firstCompleted = items.find((i) => i.status === "COMPLETED");
      if (firstCompleted) {
        await loadInvestigation(firstCompleted.analysis_id);
      }
    })();
  }, [refreshHistory, loadInvestigation]);

  const handleUploadAndAnalyze = async (file: File) => {
    setErrorMessage(null);
    setUploadProgress(0);
    setAnalysisProgress(0);
    setAnalysisStage("Queued");
    cancelledRef.current = false;
    setStage("uploading");
    try {
      const uploaded = await uploadPcapWithProgress(file, setUploadProgress);
      setRunningId(uploaded.analysis_id);
      setStage("analyzing");
      await startAnalysis(uploaded.analysis_id, true);

      // Poll live progress until completed, failed, or cancelled
      while (!cancelledRef.current) {
        const st = await fetchAnalysisStatus(uploaded.analysis_id);
        setAnalysisProgress(st.progress_pct);
        setAnalysisStage(st.stage);
        if (st.status === "COMPLETED") {
          const completed = await fetchInvestigationBundle(uploaded.analysis_id);
          setBundle(completed);
          setStage("complete");
          setActiveTab("overview");
          await refreshHistory();
          return;
        }
        if (st.status === "FAILED" || st.status === "CANCELLED") {
          throw new Error(`Analysis ${st.status.toLowerCase()}.`);
        }
        await new Promise((r) => setTimeout(r, 400));
      }
    } catch (err) {
      setStage("error");
      setErrorMessage(err instanceof Error ? err.message : "PCAP processing failed.");
    } finally {
      setRunningId(null);
    }
  };

  const handleCancelAnalysis = async () => {
    if (!runningId) return;
    cancelledRef.current = true;
    await cancelAnalysis(runningId);
    setStage("error");
    setErrorMessage("Analysis cancellation requested.");
  };

  const handleAlertStatusChange = async (alertId: string, newStatus: InvestigationStatus) => {
    if (!bundle) return;
    await updateAlertStatus(bundle.analysis_id, alertId, newStatus);
    setBundle((prev) => {
      if (!prev) return prev;
      const patchList = <T extends { alert_id: string; status: InvestigationStatus }>(arr: T[]) =>
        arr.map((item) => (item.alert_id === alertId ? { ...item, status: newStatus } : item));
      return {
        ...prev,
        alerts: patchList(prev.alerts),
        active_alerts: patchList(prev.active_alerts),
        suppressed_alerts: patchList(prev.suppressed_alerts),
      };
    });
  };

  const handleIncidentStatusChange = async (incidentId: string, newStatus: InvestigationStatus) => {
    if (!bundle) return;
    await updateIncidentStatus(bundle.analysis_id, incidentId, newStatus);
    setBundle((prev) => {
      if (!prev) return prev;
      const patch = <T extends { incident_id: string; status: InvestigationStatus }>(arr: T[] = []) =>
        arr.map((item) => (item.incident_id === incidentId ? { ...item, status: newStatus } : item));
      return {
        ...prev,
        incidents: patch(prev.incidents),
        active_incidents: patch(prev.active_incidents),
        suppressed_incidents: patch(prev.suppressed_incidents),
      };
    });
  };

  const handleInspectPackets = (opts: { alertId?: string; flowId?: string; ip?: string }) => {
    setPacketDrillFilter(opts);
    setActiveTab("packets");
  };

  const openIntegrityPanel = async () => {
    if (!bundle) return;
    try {
      const data = await fetchAuditAndIntegrity(bundle.analysis_id);
      setIntegrityData(data);
      setShowIntegrityModal(true);
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to load audit & integrity data.");
    }
  };

  const tabs: Array<{ id: TabId; label: string; icon: React.ComponentType<{ className?: string }> }> = [
    { id: "overview", label: "Overview & Analytics", icon: Activity },
    { id: "incidents", label: `Incidents (${bundle?.incidents?.length ?? 0})`, icon: ShieldCheck },
    { id: "alerts", label: `Alerts (${bundle?.alerts.length ?? 0})`, icon: ShieldAlert },
    { id: "graph", label: "Network Graph", icon: GitBranch },
    { id: "timeline", label: "Incident Timeline", icon: Clock },
    { id: "flows", label: "Flows & DNS/HTTP", icon: Layers },
    { id: "packets", label: "Packet Evidence", icon: FileSearch },
  ];

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100">
      <header className="sticky top-0 z-30 border-b border-slate-800/90 bg-[#070b14]/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-4 py-3 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-sky-500/30 bg-sky-500/10 text-sky-400">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight text-slate-50">
                PCAP Exfiltration Analyser
              </h1>
              <p className="text-[11px] text-slate-400">
                From Raw Packets to Actionable Security Intelligence.
              </p>
            </div>
          </div>

          {bundle && (
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => void openIntegrityPanel()}
                className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-500/20"
              >
                <ShieldCheck className="h-3.5 w-3.5" />
                Integrity &amp; Audit
              </button>
              <span className="hidden rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1.5 font-mono text-[11px] text-slate-300 sm:inline-block">
                ID: {bundle.analysis_id.slice(0, 12)}
              </span>
              <a
                href={getReportDownloadUrl(bundle.analysis_id, "html")}
                download
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-sky-500/50 hover:text-sky-300"
              >
                <FileCode2 className="h-3.5 w-3.5" />
                HTML Report
              </a>
              <a
                href={getReportDownloadUrl(bundle.analysis_id, "pdf")}
                download
                className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3 py-1.5 text-xs font-semibold text-slate-950 hover:bg-sky-400"
              >
                <Download className="h-3.5 w-3.5" />
                PDF Report
              </a>
            </div>
          )}
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-4 py-6 sm:px-6">
        <UploadPanel
          onUploadAndAnalyze={handleUploadAndAnalyze}
          onCancelAnalysis={handleCancelAnalysis}
          uploadProgress={uploadProgress}
          analysisProgress={analysisProgress}
          analysisStage={analysisStage}
          stage={stage}
          errorMessage={errorMessage}
          history={history}
          activeAnalysisId={bundle?.analysis_id ?? null}
          onSelectInvestigation={(id) => void loadInvestigation(id)}
        />

        {bundle && (
          <div className="space-y-5">
            <nav className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
              {tabs.map((t) => {
                const Icon = t.icon;
                const active = activeTab === t.id;
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setActiveTab(t.id)}
                    className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-medium transition ${
                      active
                        ? "bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/40"
                        : "bg-slate-900/60 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                    {t.label}
                  </button>
                );
              })}
            </nav>

            {activeTab === "overview" && (
              <div className="space-y-6">
                <OverviewKpis bundle={bundle} />
                <TrafficAnalytics bundle={bundle} />
              </div>
            )}

            {activeTab === "incidents" && (
              <IncidentsView
                incidents={bundle.incidents ?? []}
                alerts={bundle.alerts}
                onIncidentStatusChange={handleIncidentStatusChange}
                onInspectPackets={handleInspectPackets}
              />
            )}

            {activeTab === "alerts" && (
              <AlertManagement
                alerts={bundle.alerts}
                onStatusChange={handleAlertStatusChange}
                onInspectPackets={handleInspectPackets}
              />
            )}

            {activeTab === "graph" && (
              <NetworkGraph
                nodes={bundle.network_graph.nodes}
                edges={bundle.network_graph.edges}
                flows={bundle.flows}
                alerts={bundle.active_alerts}
                onInspectPackets={handleInspectPackets}
              />
            )}

            {activeTab === "timeline" && (
              <IncidentTimeline
                events={bundle.timeline}
                onInspectPackets={handleInspectPackets}
              />
            )}

            {activeTab === "flows" && (
              <FlowsAndDnsView
                bundle={bundle}
                onInspectPackets={handleInspectPackets}
              />
            )}

            {activeTab === "packets" && (
              <PacketEvidenceView
                analysisId={bundle.analysis_id}
                initialFilter={packetDrillFilter}
                onClearFilter={() => setPacketDrillFilter(undefined)}
              />
            )}
          </div>
        )}
      </main>

      {showIntegrityModal && integrityData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="max-h-[85vh] w-full max-w-2xl overflow-auto rounded-xl border border-slate-700 bg-slate-900 p-5 text-xs shadow-2xl">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-100">
                Forensic Integrity Verification &amp; Audit Trail
              </h3>
              <button
                type="button"
                onClick={() => setShowIntegrityModal(false)}
                className="rounded border border-slate-700 px-2.5 py-1 text-slate-300 hover:bg-slate-800"
              >
                Close
              </button>
            </div>
            <div className="mb-4 space-y-1.5 rounded-lg border border-slate-800 bg-slate-950 p-3">
              <div>
                Original Capture Verified:{" "}
                <strong className={integrityData.integrity.capture_integrity_verified ? "text-emerald-400" : "text-red-400"}>
                  {String(integrityData.integrity.capture_integrity_verified)}
                </strong>
              </div>
              <div>
                HTML Report Verified:{" "}
                <strong className={integrityData.integrity.html_report_verified ? "text-emerald-400" : "text-amber-300"}>
                  {String(integrityData.integrity.html_report_verified)}
                </strong>
              </div>
              <div>
                PDF Report Verified:{" "}
                <strong className={integrityData.integrity.pdf_report_verified ? "text-emerald-400" : "text-amber-300"}>
                  {String(integrityData.integrity.pdf_report_verified)}
                </strong>
              </div>
              <p className="pt-1 text-[11px] text-slate-400">
                {integrityData.integrity.disclaimer}
              </p>
            </div>

            <h4 className="mb-2 font-semibold text-slate-200">
              Investigation Audit Log ({integrityData.audit_logs.length})
            </h4>
            <div className="space-y-1.5">
              {integrityData.audit_logs.map((entry) => (
                <div
                  key={entry.id}
                  className="rounded border border-slate-800 bg-slate-950/70 p-2 font-mono text-[11px]"
                >
                  <span className="text-sky-400">{entry.action}</span> •{" "}
                  <span className="text-slate-400">{entry.actor}</span> •{" "}
                  <span className="text-slate-500">{entry.created_at}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
