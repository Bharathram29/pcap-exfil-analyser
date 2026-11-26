import React, { useRef, useState } from "react";
import {
  AlertCircle,
  CheckCircle2,
  FileUp,
  History,
  Loader2,
  StopCircle,
  UploadCloud,
} from "lucide-react";
import type { InvestigationListItem } from "../types/forensics";
import { formatBytes, shortTimestamp } from "../utils/format";

interface UploadPanelProps {
  onUploadAndAnalyze: (file: File) => Promise<void>;
  onCancelAnalysis?: () => Promise<void>;
  uploadProgress: number;
  analysisProgress?: number;
  analysisStage?: string;
  stage: "idle" | "uploading" | "analyzing" | "complete" | "error";
  errorMessage: string | null;
  history: InvestigationListItem[];
  activeAnalysisId: string | null;
  onSelectInvestigation: (analysisId: string) => void;
}

export const UploadPanel: React.FC<UploadPanelProps> = ({
  onUploadAndAnalyze,
  onCancelAnalysis,
  uploadProgress,
  analysisProgress = 0,
  analysisStage = "",
  stage,
  errorMessage,
  history,
  activeAnalysisId,
  onSelectInvestigation,
}) => {
  const [dragging, setDragging] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const handleFile = async (file: File | undefined) => {
    if (!file) return;
    const lower = file.name.toLowerCase();
    if (!lower.endsWith(".pcap") && !lower.endsWith(".pcapng")) {
      setLocalError("Invalid file type. Only .pcap and .pcapng captures are accepted.");
      return;
    }
    setLocalError(null);
    await onUploadAndAnalyze(file);
  };

  const busy = stage === "uploading" || stage === "analyzing";

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          if (!busy) setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          if (!busy) {
            void handleFile(e.dataTransfer.files?.[0]);
          }
        }}
        className={`lg:col-span-2 rounded-xl border-2 border-dashed p-6 transition-colors ${
          dragging
            ? "border-sky-400 bg-sky-500/10"
            : "border-slate-700 bg-slate-900/70 hover:border-slate-600"
        }`}
      >
        <div className="flex flex-col items-center justify-center text-center">
          <div className="mb-3 rounded-full bg-sky-500/10 p-3 text-sky-400">
            {busy ? <Loader2 className="h-7 w-7 animate-spin" /> : <UploadCloud className="h-7 w-7" />}
          </div>
          <h2 className="text-base font-semibold text-slate-100">
            Ingest PCAP / PCAPNG Capture for Forensic Analysis
          </h2>
          <p className="mt-1 text-xs text-slate-400">
            Drag and drop a <code>.pcap</code> or <code>.pcapng</code> file here, or browse locally.
            SHA-256 verification and signature checks run automatically before parsing.
          </p>

          <input
            ref={inputRef}
            type="file"
            accept=".pcap,.pcapng"
            className="hidden"
            onChange={(e) => void handleFile(e.target.files?.[0])}
          />

          <button
            type="button"
            disabled={busy}
            onClick={() => inputRef.current?.click()}
            className="mt-4 inline-flex items-center gap-2 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 shadow hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <FileUp className="h-4 w-4" />
            {busy ? "Processing Capture..." : "Select PCAP File"}
          </button>

          {stage === "uploading" && (
            <div className="mt-4 w-full max-w-md">
              <div className="mb-1 flex justify-between text-xs text-slate-300">
                <span>Uploading capture...</span>
                <span>{uploadProgress}%</span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full bg-sky-400 transition-all"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          )}

          {stage === "analyzing" && (
            <div className="mt-4 w-full max-w-md space-y-2">
              <div className="flex items-center justify-between text-xs text-sky-300">
                <span className="inline-flex items-center gap-1.5">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  {analysisStage || "Dissecting packets & correlating incidents..."}
                </span>
                <span>{analysisProgress}%</span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full bg-emerald-400 transition-all"
                  style={{ width: `${Math.max(5, analysisProgress)}%` }}
                />
              </div>
              {onCancelAnalysis && (
                <button
                  type="button"
                  onClick={() => void onCancelAnalysis()}
                  className="inline-flex items-center gap-1 rounded border border-red-500/40 bg-red-500/10 px-2.5 py-1 text-[11px] text-red-300 hover:bg-red-500/20"
                >
                  <StopCircle className="h-3.5 w-3.5" />
                  Cancel Analysis
                </button>
              )}
            </div>
          )}

          {stage === "complete" && (
            <div className="mt-3 flex items-center gap-1.5 text-xs text-emerald-400">
              <CheckCircle2 className="h-4 w-4" />
              Analysis complete. Evidence, correlated incidents, and HTML/PDF reports are ready.
            </div>
          )}

          {(localError || errorMessage) && (
            <div className="mt-3 flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-300">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{localError || errorMessage}</span>
            </div>
          )}
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-300">
            <History className="h-4 w-4 text-sky-400" />
            Recent Investigations
          </div>
          <span className="text-xs text-slate-500">{history.length}</span>
        </div>
        <div className="max-h-48 space-y-2 overflow-y-auto pr-1">
          {history.length === 0 ? (
            <p className="text-xs text-slate-500">No previous captures recorded yet.</p>
          ) : (
            history.map((item) => {
              const isActive = item.analysis_id === activeAnalysisId;
              return (
                <button
                  key={item.analysis_id}
                  type="button"
                  onClick={() => onSelectInvestigation(item.analysis_id)}
                  className={`w-full rounded-lg border px-3 py-2 text-left transition ${
                    isActive
                      ? "border-sky-500/60 bg-sky-500/10"
                      : "border-slate-800 bg-slate-950/50 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-xs font-medium text-slate-200">
                      {item.filename}
                    </span>
                    <span
                      className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${
                        item.status === "COMPLETED"
                          ? "bg-emerald-500/20 text-emerald-300"
                          : "bg-slate-700 text-slate-300"
                      }`}
                    >
                      {item.status}
                    </span>
                  </div>
                  <div className="mt-1 flex items-center justify-between text-[11px] text-slate-400">
                    <span>{formatBytes(item.file_size_bytes)}</span>
                    <span>{shortTimestamp(item.created_at)}</span>
                  </div>
                </button>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
