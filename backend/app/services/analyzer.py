"""End-to-end PCAP forensic analysis pipeline orchestrator."""

from __future__ import annotations

import json
import time
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.core.database import DatabaseManager
from app.core.logging import analysis_id_ctx, get_logger
from app.detectors.base import DetectorConfig
from app.detectors.engine import DetectionEngine
from app.detectors.flow_analyzer import FlowAnalyzer
from app.detectors.rule_engine import YamlRuleEngine
from app.models.alert import SecurityAlert
from app.models.detection import DetectionContext
from app.models.flow import NetworkFlow
from app.models.incident import CorrelationConfig
from app.models.investigation import build_investigation_bundle
from app.models.packet import CaptureMetadata, NormalizedPacket
from app.parsers.packet_parser import PacketParser
from app.reporting.reporter import ForensicReporter
from app.services.alert_manager import AlertManager
from app.services.allowlist import AllowlistManager
from app.services.audit import AuditService
from app.services.ingestion import inspect_capture_header
from app.services.mitre_mapper import MitreMapper
from app.services.packet_store import PacketStore
from app.services.threat_intel import ThreatIntelService
from app.utils.network import is_external_ip
from app.utils.security import compute_sha256_file, safe_resolve_within

logger = get_logger("services.analyzer")


class AnalysisNotFoundError(LookupError):
    """Raised when a requested analysis_id does not exist."""


class AnalysisCancelledError(RuntimeError):
    """Raised when a running analysis is cancelled by user/operator request."""


def build_network_graph(
    flows: list[NetworkFlow],
    active_alerts: list[SecurityAlert],
) -> dict[str, Any]:
    """Build node/edge graph data for interactive SOC topology visualization."""
    alert_ips: dict[str, list[str]] = defaultdict(list)
    alert_edges: set[tuple[str, str]] = set()
    for a in active_alerts:
        if a.source_ip:
            alert_ips[a.source_ip].append(a.severity)
        if a.destination_ip:
            alert_ips[a.destination_ip].append(a.severity)
        if a.source_ip and a.destination_ip:
            alert_edges.add((a.source_ip, a.destination_ip))

    node_metrics: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"bytes_sent": 0, "bytes_received": 0, "flow_count": 0}
    )
    edge_agg: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"bytes": 0, "packets": 0, "flows": 0, "protocols": set(), "ports": set()}
    )

    for f in flows:
        node_metrics[f.initiator_ip]["bytes_sent"] += f.bytes_initiator_to_responder
        node_metrics[f.initiator_ip]["bytes_received"] += f.bytes_responder_to_initiator
        node_metrics[f.initiator_ip]["flow_count"] += 1

        node_metrics[f.responder_ip]["bytes_sent"] += f.bytes_responder_to_initiator
        node_metrics[f.responder_ip]["bytes_received"] += f.bytes_initiator_to_responder
        node_metrics[f.responder_ip]["flow_count"] += 1

        ekey = (f.initiator_ip, f.responder_ip)
        edge_agg[ekey]["bytes"] += f.total_bytes
        edge_agg[ekey]["packets"] += f.total_packets
        edge_agg[ekey]["flows"] += 1
        edge_agg[ekey]["protocols"].add(f.application_protocol)
        if f.responder_port is not None:
            edge_agg[ekey]["ports"].add(f.responder_port)

    nodes = []
    for ip, stats in sorted(
        node_metrics.items(),
        key=lambda item: -(item[1]["bytes_sent"] + item[1]["bytes_received"]),
    )[:60]:
        sevs = alert_ips.get(ip, [])
        nodes.append(
            {
                "id": ip,
                "ip": ip,
                "is_external": is_external_ip(ip),
                "is_suspicious": len(sevs) > 0,
                "alert_count": len(sevs),
                "highest_severity": sevs[0] if sevs else None,
                "bytes_sent": stats["bytes_sent"],
                "bytes_received": stats["bytes_received"],
                "flow_count": stats["flow_count"],
            }
        )

    included_ids = {n["id"] for n in nodes}
    edges = []
    for (src, dst), ed in sorted(edge_agg.items(), key=lambda item: -item[1]["bytes"])[:120]:
        if src not in included_ids or dst not in included_ids:
            continue
        edges.append(
            {
                "id": f"{src}->{dst}",
                "source": src,
                "target": dst,
                "total_bytes": ed["bytes"],
                "total_packets": ed["packets"],
                "flow_count": ed["flows"],
                "protocols": sorted(ed["protocols"]),
                "ports": sorted(ed["ports"])[:10],
                "is_suspicious": (src, dst) in alert_edges or (dst, src) in alert_edges,
            }
        )

    return {"nodes": nodes, "edges": edges}


class AnalysisOrchestrator:
    """Execute and persist end-to-end PCAP forensic analysis pipelines."""

    def __init__(self, settings: Settings, db: DatabaseManager) -> None:
        self.settings = settings
        self.db = db

    def run_analysis(
        self,
        analysis_id: str,
        *,
        progress_callback: Callable[[int, str], None] | None = None,
        should_cancel: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        """Run full parsing, flow, detection, MITRE, alert, and report generation."""
        inv_row = self._fetch_investigation_row(analysis_id)
        if inv_row is None:
            raise AnalysisNotFoundError(f"Investigation {analysis_id!r} not found.")

        def _report(pct: int, stage: str) -> None:
            if should_cancel is not None and should_cancel():
                raise AnalysisCancelledError(f"Analysis {analysis_id} cancelled.")
            if progress_callback is not None:
                progress_callback(pct, stage)

        token = analysis_id_ctx.set(analysis_id)
        start_time = time.perf_counter()
        audit = AuditService()
        run_id = audit.start_run(self.db, analysis_id)
        audit.log_event(self.db, analysis_id, "ANALYSIS_STARTED", details={"run_id": run_id})
        self._update_investigation_status(analysis_id, "PROCESSING")
        _report(5, "Validating capture")

        try:
            stored_path = Path(inv_row["stored_path"])
            if not stored_path.is_file():
                raise FileNotFoundError(f"Stored capture missing: {stored_path}")

            cap_fmt, link_type, link_name, supported, warnings = inspect_capture_header(stored_path)
            metadata = CaptureMetadata(
                analysis_id=analysis_id,
                original_filename=inv_row["filename"],
                sanitized_filename=inv_row["filename"],
                stored_path=str(stored_path),
                file_size_bytes=int(inv_row["file_size_bytes"]),
                sha256=inv_row["sha256"],
                capture_format=cap_fmt,
                ingested_at_utc=inv_row["created_at"],
                link_layer_type=link_type,
                link_layer_name=link_name,
                supported_link_layer=supported,
                warnings=warnings,
            )

            _report(20, "Dissecting packets")
            parser = PacketParser(max_packets=self.settings.max_packets_per_capture)
            parsed = parser.parse_capture(metadata)

            _report(45, "Reconstructing flows")
            flow_analyzer = FlowAnalyzer(
                idle_timeout_seconds=self.settings.flow_idle_timeout_seconds
            )
            flow_result = flow_analyzer.analyze(parsed.packets)

            context = DetectionContext(
                metadata=metadata,
                packets=parsed.packets,
                flows=flow_result.flows,
            )

            _report(60, "Running heuristic & YAML detections")

            detector_cfg = DetectorConfig.from_yaml(
                self.settings.rules_dir / "detector_config.yaml"
            )
            heuristic_findings = DetectionEngine(detector_cfg).run(context)
            rules_path = self.settings.rules_dir / "detection_rules.yaml"
            yaml_findings = YamlRuleEngine().evaluate(context, rules_path=rules_path)
            all_findings = heuristic_findings + yaml_findings

            # Backfill packet_indices from flow_map for any finding referencing a flow
            flow_by_id = {f.flow_id: f for f in flow_result.flows}
            for finding in all_findings:
                if not finding.packet_indices and finding.flow_id and finding.flow_id in flow_by_id:
                    finding.packet_indices = list(flow_by_id[finding.flow_id].packet_indices[:200])
                if finding.packet_indices and "packet_indices" not in finding.evidence:
                    finding.evidence["packet_indices"] = list(finding.packet_indices[:100])

            allowlist_path = self.settings.rules_dir / "allowlist.yaml"
            allowlist_mgr = (
                AllowlistManager.from_yaml(allowlist_path)
                if allowlist_path.is_file()
                else None
            )

            corr_cfg = CorrelationConfig(
                time_window_seconds=self.settings.correlation_time_window_seconds,
                match_source_port=self.settings.correlation_match_source_port,
                match_destination_port=self.settings.correlation_match_destination_port,
                match_protocol=self.settings.correlation_match_protocol,
                match_rule=self.settings.correlation_match_rule,
            )
            alert_mgr = AlertManager()
            alert_result = alert_mgr.process_findings(
                all_findings,
                mitre_mapper=MitreMapper(),
                allowlist_manager=allowlist_mgr,
                correlation_config=corr_cfg,
            )
            _report(80, "Correlating alerts & storing packet evidence")
            alert_mgr.save_alerts(self.db, analysis_id, alert_result.alerts)
            alert_mgr.save_incidents(self.db, analysis_id, alert_result.incidents)
            PacketStore().save_packets(
                self.db,
                analysis_id,
                parsed.packets,
                flow_result.packet_flow_map,
                alert_result.alerts,
                max_store=self.settings.max_stored_packets_per_analysis,
            )

            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            bundle = build_investigation_bundle(
                metadata=metadata,
                packets=parsed.packets,
                flow_result=flow_result,
                alert_result=alert_result,
                processing_duration_ms=elapsed_ms,
                status="COMPLETED",
            )

            # Enrich DNS analysis with individual DNS observations for /dns endpoint
            bundle.dns_analysis["records"] = self._extract_dns_records(parsed.packets)

            # Optional, non-blocking external threat intelligence enrichment
            bundle.threat_intelligence = self._collect_threat_intel(
                alert_result.active_alerts, bundle.dns_analysis, bundle.tls_analysis
            )

            # Generate standalone HTML & PDF reports and compute integrity digests
            _report(92, "Generating forensic HTML & PDF reports")
            reporter = ForensicReporter(self.settings.reports_dir)
            artifacts = reporter.generate_reports(bundle)
            html_sha = compute_sha256_file(artifacts.html_path)
            pdf_sha = compute_sha256_file(artifacts.pdf_path)
            bundle.integrity = {
                "capture_sha256": metadata.sha256,
                "original_capture_preserved": True,
                "html_report_sha256": html_sha,
                "pdf_report_sha256": pdf_sha,
                "analysis_run_id": run_id,
            }

            bundle_dict = bundle.to_dict()
            bundle_dict["network_graph"] = build_network_graph(
                flow_result.flows, alert_result.active_alerts
            )

            self._save_bundle_json(analysis_id, bundle_dict)
            self._mark_completed(analysis_id, elapsed_ms, bundle.summary)
            audit.complete_run(
                self.db,
                run_id,
                duration_ms=elapsed_ms,
                packet_count=len(parsed.packets),
                flow_count=flow_result.total_flows,
                active_alert_count=len(alert_result.active_alerts),
                incident_count=len(alert_result.active_incidents),
                html_report_sha256=html_sha,
                pdf_report_sha256=pdf_sha,
            )
            audit.log_event(
                self.db,
                analysis_id,
                "ANALYSIS_COMPLETED",
                details={
                    "run_id": run_id,
                    "duration_ms": elapsed_ms,
                    "packet_count": len(parsed.packets),
                    "flow_count": flow_result.total_flows,
                    "active_alerts": len(alert_result.active_alerts),
                    "active_incidents": len(alert_result.active_incidents),
                    "html_report_sha256": html_sha,
                    "pdf_report_sha256": pdf_sha,
                },
            )
            logger.info(
                "Analysis completed in %.2f ms (%d packets, %d flows, %d active alerts)",
                elapsed_ms,
                len(parsed.packets),
                flow_result.total_flows,
                len(alert_result.active_alerts),
            )
            if progress_callback is not None:
                progress_callback(100, "Completed")
            return bundle_dict
        except AnalysisCancelledError as exc:
            logger.info("Analysis cancelled for %s", analysis_id)
            audit.fail_run(self.db, run_id, "Cancelled by operator")
            audit.log_event(self.db, analysis_id, "ANALYSIS_CANCELLED", details={"run_id": run_id})
            self._update_investigation_status(analysis_id, "CANCELLED")
            raise exc
        except Exception as exc:
            logger.exception("Analysis failed for %s: %s", analysis_id, exc)
            audit.fail_run(self.db, run_id, str(exc))
            audit.log_event(
                self.db,
                analysis_id,
                "ANALYSIS_FAILED",
                details={"run_id": run_id, "error": str(exc)[:300]},
            )
            self._mark_failed(analysis_id, str(exc))
            raise
        finally:
            analysis_id_ctx.reset(token)

    def load_bundle(self, analysis_id: str) -> dict[str, Any]:
        """Load persisted analysis JSON or raise AnalysisNotFoundError."""
        inv_row = self._fetch_investigation_row(analysis_id)
        if inv_row is None:
            raise AnalysisNotFoundError(f"Investigation {analysis_id!r} not found.")

        bundle_path = self._bundle_path(analysis_id)
        if bundle_path.is_file():
            return json.loads(bundle_path.read_text(encoding="utf-8"))

        return {
            "analysis_id": analysis_id,
            "status": inv_row["status"],
            "capture_metadata": {
                "analysis_id": analysis_id,
                "original_filename": inv_row["filename"],
                "file_size_bytes": inv_row["file_size_bytes"],
                "sha256": inv_row["sha256"],
                "ingested_at_utc": inv_row["created_at"],
            },
            "error_message": inv_row["error_message"],
            "summary": json.loads(inv_row["summary_json"]) if inv_row["summary_json"] else None,
        }

    def sync_alert_status_in_bundle(
        self,
        analysis_id: str,
        alert_id: str,
        new_status: str,
    ) -> None:
        """Keep persisted JSON bundle in sync when an analyst updates an alert status."""
        bundle_path = self._bundle_path(analysis_id)
        if not bundle_path.is_file():
            return
        bundle_dict = json.loads(bundle_path.read_text(encoding="utf-8"))
        for key in ("alerts", "active_alerts", "suppressed_alerts"):
            for item in bundle_dict.get(key, []):
                if item.get("alert_id") == alert_id:
                    item["status"] = new_status
        bundle_path.write_text(json.dumps(bundle_dict), encoding="utf-8")

    def sync_incident_status_in_bundle(
        self,
        analysis_id: str,
        incident_id: str,
        new_status: str,
    ) -> None:
        """Keep persisted JSON bundle in sync when an analyst updates an incident status."""
        bundle_path = self._bundle_path(analysis_id)
        if not bundle_path.is_file():
            return
        bundle_dict = json.loads(bundle_path.read_text(encoding="utf-8"))
        for key in ("incidents", "active_incidents", "suppressed_incidents"):
            for item in bundle_dict.get(key, []):
                if item.get("incident_id") == incident_id:
                    item["status"] = new_status
        bundle_path.write_text(json.dumps(bundle_dict), encoding="utf-8")

    def list_investigations(self, limit: int = 50) -> list[dict[str, Any]]:
        """List recent investigations stored in SQLite."""
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT analysis_id, filename, file_size_bytes, sha256, status,
                       created_at, completed_at, processing_duration_ms,
                       summary_json, error_message
                FROM investigations
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        items: list[dict[str, Any]] = []
        for row in rows:
            items.append(
                {
                    "analysis_id": row["analysis_id"],
                    "filename": row["filename"],
                    "file_size_bytes": row["file_size_bytes"],
                    "sha256": row["sha256"],
                    "status": row["status"],
                    "created_at": row["created_at"],
                    "completed_at": row["completed_at"],
                    "processing_duration_ms": row["processing_duration_ms"],
                    "summary": (
                        json.loads(row["summary_json"]) if row["summary_json"] else None
                    ),
                    "error_message": row["error_message"],
                }
            )
        return items

    def _collect_threat_intel(
        self,
        active_alerts: list[SecurityAlert],
        dns_analysis: dict[str, Any],
        tls_analysis: dict[str, Any],
    ) -> dict[str, Any]:
        ips: list[str] = []
        domains: list[str] = []
        for a in active_alerts:
            if a.destination_ip:
                ips.append(a.destination_ip)
            ev = a.evidence
            if isinstance(ev.get("parent_domain"), str):
                domains.append(ev["parent_domain"])
            for sni in ev.get("observed_tls_snis", []) or []:
                if isinstance(sni, str):
                    domains.append(sni)
        for item in dns_analysis.get("top_parent_domains", [])[:5]:
            if isinstance(item, dict) and item.get("domain"):
                domains.append(str(item["domain"]))
        for item in tls_analysis.get("observed_snis", [])[:5]:
            if isinstance(item, dict) and item.get("sni"):
                domains.append(str(item["sni"]))
        try:
            return ThreatIntelService(self.settings).enrich_indicators(ips, domains)
        except Exception as exc:
            logger.warning("Threat intel enrichment skipped: %s", exc)
            return {
                "enabled": self.settings.threat_intel_enabled,
                "source_label": "EXTERNAL_THREAT_INTEL",
                "error": str(exc),
                "results": [],
            }

    def enrich_threat_intel(self, analysis_id: str) -> dict[str, Any]:
        """Run threat intel enrichment against a completed investigation bundle."""
        bundle_dict = self.load_bundle(analysis_id)
        if bundle_dict.get("status") != "COMPLETED":
            raise AnalysisNotFoundError(
                f"Investigation {analysis_id!r} is not completed."
            )
        ips = [
            a["destination_ip"]
            for a in bundle_dict.get("active_alerts", [])
            if a.get("destination_ip")
        ]
        domains: list[str] = []
        for a in bundle_dict.get("active_alerts", []):
            ev = a.get("evidence", {})
            if isinstance(ev.get("parent_domain"), str):
                domains.append(ev["parent_domain"])
        for s in bundle_dict.get("tls_analysis", {}).get("observed_snis", [])[:5]:
            if isinstance(s, dict) and s.get("sni"):
                domains.append(str(s["sni"]))

        intel = ThreatIntelService(self.settings).enrich_indicators(ips, domains)
        bundle_dict["threat_intelligence"] = intel
        self._save_bundle_json(analysis_id, bundle_dict)
        AuditService().log_event(
            self.db,
            analysis_id,
            "THREAT_INTEL_ENRICHED",
            actor="analyst",
            details={"result_count": len(intel.get("results", []))},
        )
        return intel

    def ensure_report_file(self, analysis_id: str, fmt: str) -> Path:
        """Return existing report path or regenerate from persisted bundle."""
        ext = "pdf" if fmt.lower() == "pdf" else "html"
        report_path = safe_resolve_within(
            self.settings.reports_dir,
            self.settings.reports_dir / f"report_{analysis_id}.{ext}",
        )
        if report_path.is_file():
            return report_path
        bundle_dict = self.load_bundle(analysis_id)
        if bundle_dict.get("status") != "COMPLETED":
            raise AnalysisNotFoundError(
                f"Report unavailable; investigation {analysis_id!r} status is "
                f"{bundle_dict.get('status')}."
            )
        reporter = ForensicReporter(self.settings.reports_dir)
        regenerated = reporter.regenerate_from_dict(bundle_dict, fmt=ext)
        AuditService().log_event(
            self.db,
            analysis_id,
            "REPORT_REGENERATED",
            details={"format": ext, "sha256": compute_sha256_file(regenerated)},
        )
        return regenerated

    def _bundle_path(self, analysis_id: str) -> Path:
        self.settings.ensure_directories()
        safe_id = "".join(ch for ch in analysis_id if ch.isalnum() or ch in {"-", "_"})
        if not safe_id:
            raise AnalysisNotFoundError("Invalid analysis_id.")
        return safe_resolve_within(
            self.settings.analyses_dir,
            self.settings.analyses_dir / f"{safe_id}.json",
        )

    def _save_bundle_json(self, analysis_id: str, bundle_dict: dict[str, Any]) -> None:
        path = self._bundle_path(analysis_id)
        path.write_text(json.dumps(bundle_dict), encoding="utf-8")

    def _fetch_investigation_row(self, analysis_id: str) -> Any:
        with self.db.connection() as conn:
            return conn.execute(
                "SELECT * FROM investigations WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()

    def _update_investigation_status(self, analysis_id: str, status: str) -> None:
        now = datetime.now(UTC).isoformat()
        with self.db.connection() as conn:
            conn.execute(
                "UPDATE investigations SET status = ?, updated_at = ? WHERE analysis_id = ?",
                (status, now, analysis_id),
            )

    def _mark_completed(
        self, analysis_id: str, duration_ms: float, summary: dict[str, Any]
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self.db.connection() as conn:
            conn.execute(
                """
                UPDATE investigations
                SET status = ?, completed_at = ?, updated_at = ?,
                    processing_duration_ms = ?, summary_json = ?, error_message = NULL
                WHERE analysis_id = ?
                """,
                ("COMPLETED", now, now, duration_ms, json.dumps(summary), analysis_id),
            )

    def _mark_failed(self, analysis_id: str, error_message: str) -> None:
        now = datetime.now(UTC).isoformat()
        with self.db.connection() as conn:
            conn.execute(
                """
                UPDATE investigations
                SET status = ?, updated_at = ?, error_message = ?
                WHERE analysis_id = ?
                """,
                ("FAILED", now, error_message, analysis_id),
            )

    def _extract_dns_records(self, packets: list[NormalizedPacket]) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for pkt in packets:
            if pkt.dns is None:
                continue
            records.append(
                {
                    "packet_index": pkt.packet_index,
                    "timestamp": pkt.timestamp_utc,
                    "src_ip": pkt.src_ip,
                    "dst_ip": pkt.dst_ip,
                    "is_response": pkt.dns.is_response,
                    "query_name": pkt.dns.query_name,
                    "query_type": pkt.dns.query_type,
                    "response_code": pkt.dns.response_code,
                    "response_ips": pkt.dns.response_ips,
                    "query_length": pkt.dns.query_length,
                    "subdomain_length": pkt.dns.subdomain_length,
                    "parent_domain": pkt.dns.parent_domain,
                }
            )
            if len(records) >= 500:
                break
        return records
