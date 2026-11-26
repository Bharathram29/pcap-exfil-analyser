import type { Severity } from "../types/forensics";

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const idx = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / Math.pow(1024, idx);
  return `${value >= 10 || idx === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[idx]}`;
}

export function severityClasses(severity: Severity | string): string {
  switch (severity.toUpperCase()) {
    case "CRITICAL":
      return "bg-red-500/20 text-red-300 border-red-500/40";
    case "HIGH":
      return "bg-orange-500/20 text-orange-300 border-orange-500/40";
    case "MEDIUM":
      return "bg-amber-500/20 text-amber-300 border-amber-500/40";
    case "LOW":
      return "bg-sky-500/20 text-sky-300 border-sky-500/40";
    default:
      return "bg-slate-600/30 text-slate-300 border-slate-500/40";
  }
}

export function shortTimestamp(utcIso: string): string {
  if (!utcIso) return "-";
  return utcIso.replace("T", " ").replace("+00:00", " UTC").slice(0, 23);
}

export function downloadTextFile(filename: string, content: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export function toCsv(
  headers: string[],
  rows: Array<Array<string | number | boolean | null | undefined>>,
): string {
  const esc = (val: string | number | boolean | null | undefined): string => {
    const raw = val === null || val === undefined ? "" : String(val);
    const safe = /^[=+\-@]/.test(raw) ? `'${raw}` : raw;
    return `"${safe.replace(/"/g, '""')}"`;
  };
  return [headers.map(esc).join(","), ...rows.map((r) => r.map(esc).join(","))].join("\n");
}
