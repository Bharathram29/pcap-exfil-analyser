"""Standalone HTML and PDF forensic incident report generator."""

from __future__ import annotations

import html
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models.investigation import InvestigationBundle
from app.utils.security import safe_resolve_within

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#3b82f6",
    "INFORMATIONAL": "#64748b",
}


@dataclass(slots=True)
class ReportArtifacts:
    """Paths to generated standalone HTML and PDF reports."""

    html_path: Path
    pdf_path: Path


class ForensicReporter:
    """Render standalone escaped HTML and ReportLab PDF forensic reports."""

    def __init__(self, reports_dir: Path) -> None:
        self.reports_dir = reports_dir
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(enabled_extensions=("html", "j2", "xml")),
        )

    def generate_reports(self, bundle: InvestigationBundle) -> ReportArtifacts:
        """Generate both standalone HTML and PDF reports inside reports_dir."""
        html_path = self.generate_html(bundle)
        pdf_path = self.generate_pdf(bundle)
        return ReportArtifacts(html_path=html_path, pdf_path=pdf_path)

    def regenerate_from_dict(self, bundle_dict: dict[str, Any], fmt: str = "html") -> Path:
        """Regenerate HTML or PDF report from a persisted JSON bundle dict."""
        ns = self._dict_to_bundle_view(bundle_dict)
        if fmt.lower() == "pdf":
            return self.generate_pdf(ns)  # type: ignore[arg-type]
        return self.generate_html(ns)  # type: ignore[arg-type]

    def _dict_to_bundle_view(self, d: dict[str, Any]) -> SimpleNamespace:
        def wrap_obj(obj: Any) -> Any:
            if isinstance(obj, dict):
                return SimpleNamespace(**{k: wrap_obj(v) for k, v in obj.items()})
            if isinstance(obj, list):
                return [wrap_obj(item) for item in obj]
            return obj

        return SimpleNamespace(
            analysis_id=d["analysis_id"],
            status=d["status"],
            generated_at_utc=d["generated_at_utc"],
            processing_duration_ms=d["processing_duration_ms"],
            capture_metadata=wrap_obj(d["capture_metadata"]),
            summary=d["summary"],
            protocol_distribution=d.get("protocol_distribution", []),
            traffic_over_time=d.get("traffic_over_time", []),
            top_hosts=d.get("top_hosts", []),
            top_ports=d.get("top_ports", []),
            dns_analysis=d.get("dns_analysis", {}),
            http_analysis=d.get("http_analysis", {}),
            tls_analysis=d.get("tls_analysis", {}),
            flows=[wrap_obj(f) for f in d.get("flows", [])],
            alerts=[wrap_obj(a) for a in d.get("alerts", [])],
            active_alerts=[wrap_obj(a) for a in d.get("active_alerts", [])],
            suppressed_alerts=[wrap_obj(a) for a in d.get("suppressed_alerts", [])],
            incidents=[wrap_obj(inc) for inc in d.get("incidents", [])],
            active_incidents=[wrap_obj(inc) for inc in d.get("active_incidents", [])],
            suppressed_incidents=[wrap_obj(inc) for inc in d.get("suppressed_incidents", [])],
            mitre_mappings=[wrap_obj(m) for m in d.get("mitre_mappings", [])],
            timeline=[wrap_obj(t) for t in d.get("timeline", [])],
            limitations=d.get("limitations", []),
            threat_intelligence=d.get("threat_intelligence", {}),
            integrity=d.get("integrity", {}),
        )

    def generate_html(self, bundle: InvestigationBundle) -> Path:
        """Render a standalone HTML report with all untrusted strings escaped."""
        out_path = safe_resolve_within(
            self.reports_dir,
            self.reports_dir / f"report_{bundle.analysis_id}.html",
        )
        sev_dist = bundle.summary.get("severity_distribution", {})
        max_count = max([1, *sev_dist.values()]) if sev_dist else 1
        bars = []
        for idx, sev in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")):
            count = int(sev_dist.get(sev, 0))
            width = int((count / max_count) * 420) if count > 0 else 0
            bars.append(
                {
                    "label": sev,
                    "count": count,
                    "width": width,
                    "y": 10 + idx * 27,
                    "color": SEVERITY_COLORS[sev],
                }
            )

        top_flows = sorted(bundle.flows, key=lambda f: -f.total_bytes)[:12]
        recommended_steps = self._collect_recommended_steps(bundle)
        spec_types = {
            "dns_tunnelling",
            "http_upload",
            "outbound_exfiltration",
            "network_beaconing",
        }
        specialized_alerts = [
            a
            for a in bundle.active_alerts
            if any(dt in spec_types for dt in getattr(a, "detector_types", []))
        ]
        beaconing_alerts = [
            a
            for a in bundle.active_alerts
            if "network_beaconing" in getattr(a, "detector_types", [])
        ]
        packet_evidence_rows = self._collect_packet_evidence_rows(bundle)

        template = self.jinja_env.get_template("report.html.j2")
        html_content = template.render(
            bundle=bundle,
            severity_chart_bars=bars,
            top_flows=top_flows,
            recommended_steps=recommended_steps,
            specialized_alerts=specialized_alerts,
            beaconing_alerts=beaconing_alerts,
            packet_evidence_rows=packet_evidence_rows,
        )
        out_path.write_text(html_content, encoding="utf-8")
        return out_path

    def generate_pdf(self, bundle: InvestigationBundle) -> Path:
        """Render a structured standalone PDF forensic report using ReportLab."""
        out_path = safe_resolve_within(
            self.reports_dir,
            self.reports_dir / f"report_{bundle.analysis_id}.pdf",
        )
        doc = SimpleDocTemplate(
            str(out_path),
            pagesize=letter,
            leftMargin=0.6 * inch,
            rightMargin=0.6 * inch,
            topMargin=0.6 * inch,
            bottomMargin=0.6 * inch,
            title=f"PCAP Exfiltration Analyser Report - {bundle.analysis_id}",
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=16,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6,
        )
        h2_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontSize=12,
            textColor=colors.HexColor("#0369a1"),
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "BodySmall",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=11.5,
        )
        cell_style = ParagraphStyle(
            "CellSmall",
            parent=styles["Normal"],
            fontSize=7.5,
            leading=9.5,
        )

        def p(text: object, style: ParagraphStyle = body_style) -> Paragraph:
            return Paragraph(html.escape(str(text or ""), quote=True), style)

        story: list[object] = [
            p("PCAP Exfiltration Analyser — Network Forensic Incident Report", title_style),
            p(
                f"From Raw Packets to Actionable Security Intelligence | "
                f"Investigation ID: {bundle.analysis_id} | Generated UTC: {bundle.generated_at_utc}"
            ),
            Spacer(1, 8),
        ]

        # 1. Capture Metadata
        story.append(p("1. Investigation & Capture Forensic Metadata", h2_style))
        meta = bundle.capture_metadata
        meta_rows = [
            [p("Original Filename", cell_style), p(meta.original_filename, cell_style),
             p("Format", cell_style), p(meta.capture_format.upper(), cell_style)],
            [p("SHA-256", cell_style), p(meta.sha256, cell_style),
             p("Size (Bytes)", cell_style), p(f"{meta.file_size_bytes:,}", cell_style)],
            [p("Link Layer", cell_style), p(meta.link_layer_name or "Unknown", cell_style),
             p("Ingested (UTC)", cell_style), p(meta.ingested_at_utc, cell_style)],
            [p("Malformed Packets", cell_style), p(str(meta.malformed_packet_count), cell_style),
             p("Duration (ms)", cell_style), p(str(bundle.processing_duration_ms), cell_style)],
        ]
        story.append(
            self._styled_table(meta_rows, [1.2 * inch, 2.5 * inch, 1.2 * inch, 2.3 * inch])
        )

        # 2. Executive Summary
        story.append(p("2. Executive Summary", h2_style))
        s = bundle.summary
        total_alerts_n = s.get("total_alerts", len(bundle.alerts))
        allow_alerts_n = s.get("allowlisted_alerts", s["suppressed_events"])
        corr_inc_n = s.get("correlated_incidents", len(getattr(bundle, "incidents", [])))
        active_inc_n = s.get("active_incidents", len(getattr(bundle, "active_incidents", [])))
        allow_inc_n = s.get(
            "allowlisted_incidents", len(getattr(bundle, "suppressed_incidents", []))
        )
        story.append(
            p(
                f"Analysed {s['total_packets']:,} packets across {s['total_flows']:,} flows "
                f"({s['unique_source_ips']} unique source IPs, "
                f"{s['unique_destination_ips']} unique destination IPs). "
                f"Total alerts: {total_alerts_n} ({s['suspicious_events']} active, "
                f"{allow_alerts_n} allowlisted). Correlated incidents: {corr_inc_n} "
                f"({active_inc_n} active, {allow_inc_n} allowlisted). "
                f"Active severity breakdown: {s['critical_alerts']} Critical, "
                f"{s['high_alerts']} High, {s['medium_alerts']} Medium, "
                f"{s['low_alerts']} Low; mapped to {len(bundle.mitre_mappings)} "
                f"MITRE ATT&CK technique(s)."
            )
        )
        story.append(
            p(
                "Note: Confirmed packet/flow observations are separated from heuristic indicators "
                "and inferred ATT&CK techniques; heuristics alone do not prove data theft."
            )
        )

        # 3. Severity Bar Chart & Packet Stats
        story.append(p("3. Severity Distribution & Packet Statistics", h2_style))
        story.append(self._build_severity_chart(s.get("severity_distribution", {})))
        stats_rows = [[p("Protocol", cell_style), p("Packets", cell_style), p("Bytes", cell_style)]]
        for row in bundle.protocol_distribution[:10]:
            stats_rows.append(
                [p(row["protocol"], cell_style), p(f"{row['packet_count']:,}", cell_style),
                 p(f"{row['byte_count']:,}", cell_style)]
            )
        story.append(
            self._styled_table(stats_rows, [2.4 * inch, 2.4 * inch, 2.4 * inch], has_header=True)
        )

        # 4. Top Hosts & Flows
        story.append(p("4. Top Communicating Hosts & Flows", h2_style))
        host_rows = [[p("Host IP", cell_style), p("Sent", cell_style),
                      p("Received", cell_style), p("Alerts", cell_style)]]
        for h in bundle.top_hosts[:10]:
            host_rows.append([
                p(h["ip"], cell_style), p(f"{h['bytes_sent']:,}", cell_style),
                p(f"{h['bytes_received']:,}", cell_style), p(str(h["alert_count"]), cell_style),
            ])
        story.append(
            self._styled_table(
                host_rows, [2.4 * inch, 1.8 * inch, 1.8 * inch, 1.2 * inch], has_header=True
            )
        )

        # 5. Correlated Incidents
        story.append(p("5. Correlated Security Incidents", h2_style))
        inc_rows = [
            [
                p("ID & Status", cell_style),
                p("Sev", cell_style),
                p("Risk (0-100)", cell_style),
                p("Conf", cell_style),
                p("Incident Title & Hosts", cell_style),
            ]
        ]
        for inc in getattr(bundle, "incidents", [])[:30]:
            tag = " [ALLOWLISTED]" if getattr(inc, "suppressed", False) else ""
            title_hosts = (
                f"{inc.incident_title}{tag} | "
                f"{', '.join(inc.source_hosts)} -> {', '.join(inc.destination_hosts)} "
                f"({inc.alert_count} alerts, {len(inc.packet_indices)} pkt refs)"
            )
            inc_rows.append([
                p(f"{inc.incident_id} ({inc.status})", cell_style),
                p(inc.overall_severity, cell_style),
                p(f"{inc.risk_score:.1f}", cell_style),
                p(f"{int(inc.overall_confidence * 100)}%", cell_style),
                p(title_hosts, cell_style),
            ])
        if len(inc_rows) == 1:
            inc_rows.append([p("-", cell_style), p("-", cell_style), p("-", cell_style),
                             p("-", cell_style), p("No incidents", cell_style)])
        story.append(
            self._styled_table(
                inc_rows,
                [1.35 * inch, 0.7 * inch, 0.8 * inch, 0.55 * inch, 3.8 * inch],
                has_header=True,
            )
        )

        # 6. DNS, HTTP, TLS Metadata & Beaconing Findings
        story.append(p("6. DNS, HTTP, TLS Metadata & Beaconing Analysis", h2_style))
        dns = bundle.dns_analysis
        http = bundle.http_analysis
        tls = bundle.tls_analysis
        story.append(
            p(
                f"DNS: {dns['total_queries']} queries, {dns['unique_domains']} unique domains, "
                f"{dns['nxdomain_count']} NXDOMAIN replies. "
                f"HTTP: {http['total_requests']} requests, {http['total_upload_payload_bytes']:,} "
                f"upload bytes. TLS: {tls['total_handshakes']} handshakes "
                "(encrypted payloads not inspected)."
            )
        )
        beaconing_alerts = [
            a
            for a in bundle.active_alerts
            if "network_beaconing" in getattr(a, "detector_types", [])
        ]
        beacon_rows = [[p("Endpoint", cell_style), p("Conns", cell_style),
                        p("Mean Int (s)", cell_style), p("Periodicity/CV", cell_style),
                        p("Note", cell_style)]]
        for b in beaconing_alerts[:20]:
            ev = b.evidence if isinstance(b.evidence, dict) else vars(b.evidence)
            beacon_rows.append([
                p(f"{b.source_ip} -> {b.destination_ip}:{b.destination_port or '-'}", cell_style),
                p(str(ev.get("connection_count", "-")), cell_style),
                p(str(ev.get("mean_interval_seconds", "-")), cell_style),
                p(
                    f"P={ev.get('periodicity_score', '-')} / CV={ev.get('interval_cv', '-')}",
                    cell_style,
                ),
                p(b.explanation[:130], cell_style),
            ])
        if len(beacon_rows) > 1:
            story.append(p("Dedicated Beaconing Findings:", body_style))
            story.append(
                self._styled_table(
                    beacon_rows,
                    [1.8 * inch, 0.65 * inch, 0.9 * inch, 1.15 * inch, 2.7 * inch],
                    has_header=True,
                )
            )
        else:
            story.append(p("No periodic beaconing findings triggered.", body_style))

        # 7. Detected Suspicious Events & Risk Explanations
        story.append(p("7. Individual Suspicious Events, Risk Scoring & Packet Refs", h2_style))
        alert_rows = [[p("Sev", cell_style), p("Risk / Conf", cell_style), p("Title", cell_style),
                       p("Endpoints & Pkts", cell_style), p("Explanation & Rationale", cell_style)]]
        for a in bundle.alerts[:40]:
            title_txt = f"{a.title}{' [ALLOWLISTED]' if a.suppressed else ''}"
            pkt_refs = ", ".join(str(x) for x in getattr(a, "packet_indices", [])[:8]) or "-"
            ep_txt = (
                f"{a.source_ip or '-'} -> {a.destination_ip or '-'}:{a.destination_port or '-'} "
                f"[pkts: {pkt_refs}]"
            )
            rationale = getattr(a.priority_breakdown, "rationale", "")
            risk_v = getattr(a.priority_breakdown, "risk_score", None) or a.priority_score
            alert_rows.append([
                p(a.severity, cell_style),
                p(f"Risk: {float(risk_v):.1f}\nConf: {int(a.confidence * 100)}%", cell_style),
                p(title_txt, cell_style),
                p(ep_txt, cell_style),
                p(f"{a.explanation[:150]} | {rationale[:100]}", cell_style),
            ])
        if len(alert_rows) == 1:
            alert_rows.append([p("-", cell_style), p("-", cell_style),
                               p("No alerts", cell_style), p("-", cell_style), p("-", cell_style)])
        story.append(
            self._styled_table(
                alert_rows,
                [0.7 * inch, 0.7 * inch, 1.5 * inch, 1.6 * inch, 2.7 * inch],
                has_header=True,
            )
        )
        if len(bundle.alerts) > 40:
            story.append(
                p(f"Note: Showing top 40 of {len(bundle.alerts)} alerts in PDF summary; "
                  "full alert list is preserved in the HTML report and JSON bundle.")
            )

        # 8. MITRE ATT&CK Mappings
        story.append(p("8. MITRE ATT&CK Mappings", h2_style))
        mitre_rows = [[p("ID", cell_style), p("Name", cell_style),
                       p("Tactic", cell_style), p("Conf", cell_style), p("Reason", cell_style)]]
        for m in bundle.mitre_mappings:
            mitre_rows.append([
                p(m.technique_id, cell_style), p(m.technique_name, cell_style),
                p(m.tactic, cell_style), p(m.confidence_level, cell_style),
                p(f"{m.reason} ({m.reference_url})", cell_style),
            ])
        if len(mitre_rows) == 1:
            mitre_rows.append([p("-", cell_style), p("None", cell_style),
                               p("-", cell_style), p("-", cell_style), p("-", cell_style)])
        story.append(
            self._styled_table(
                mitre_rows,
                [0.8 * inch, 1.6 * inch, 1.1 * inch, 0.7 * inch, 3.0 * inch],
                has_header=True,
            )
        )

        # 9. Chronological Incident Timeline
        story.append(p("9. Chronological Incident Timeline", h2_style))
        tl_rows = [[p("UTC Time", cell_style), p("Src -> Dst", cell_style),
                    p("Rule", cell_style), p("Sev", cell_style)]]
        for ev in bundle.timeline[:40]:
            tl_rows.append([
                p(ev.timestamp, cell_style),
                p(f"{ev.source_ip or '-'} -> {ev.destination_ip or '-'}", cell_style),
                p(ev.detection_rule, cell_style),
                p(ev.severity, cell_style),
            ])
        if len(tl_rows) == 1:
            tl_rows.append([p("-", cell_style), p("No events", cell_style),
                            p("-", cell_style), p("-", cell_style)])
        story.append(
            self._styled_table(
                tl_rows, [2.0 * inch, 2.3 * inch, 2.0 * inch, 0.9 * inch], has_header=True
            )
        )

        # 10. Structured Packet-Level Evidence Reference Table
        story.append(p("10. Packet-Level Forensic Evidence References", h2_style))
        pkt_ev_rows = self._collect_packet_evidence_rows(bundle)
        pkt_table_rows = [[p("Pkt #", cell_style), p("UTC Time", cell_style),
                           p("Src -> Dst", cell_style), p("Proto", cell_style),
                           p("Flow / Incident / Alert", cell_style)]]
        for row in pkt_ev_rows[:25]:
            pkt_table_rows.append([
                p(str(row["packet_index"]), cell_style),
                p(str(row["timestamp"])[:22], cell_style),
                p(f"{row['src']} -> {row['dst']}", cell_style),
                p(str(row["protocol"]), cell_style),
                p(f"{row['context']} ({row['ref_id']})", cell_style),
            ])
        if len(pkt_table_rows) == 1:
            pkt_table_rows.append([p("-", cell_style), p("-", cell_style),
                                   p("No packet references attached", cell_style),
                                   p("-", cell_style), p("-", cell_style)])
        story.append(
            self._styled_table(
                pkt_table_rows,
                [0.65 * inch, 1.45 * inch, 2.0 * inch, 0.7 * inch, 2.4 * inch],
                has_header=True,
            )
        )

        # 11. Recommended Investigation Steps & Limitations
        story.append(p("11. Recommended Steps & Limitations", h2_style))
        for step in self._collect_recommended_steps(bundle)[:10]:
            story.append(p(f"• {step}"))
        story.append(Spacer(1, 6))
        for lim in bundle.limitations:
            story.append(p(f"• {lim}"))

        doc.build(story)
        return out_path

    def _collect_packet_evidence_rows(
        self, bundle: InvestigationBundle
    ) -> list[dict[str, Any]]:
        """Collect structured packet-level evidence rows from alerts and protocol records."""
        rows: list[dict[str, Any]] = []
        seen_keys: set[tuple[int, str]] = set()
        for a in getattr(bundle, "alerts", [])[:25]:
            pkt_idxs = list(getattr(a, "packet_indices", []) or [])
            for pidx in pkt_idxs[:4]:
                key = (int(pidx), a.alert_id)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                rows.append(
                    {
                        "packet_index": pidx,
                        "timestamp": a.timestamp,
                        "src": f"{a.source_ip or '-'}:{a.source_port or '-'}",
                        "dst": f"{a.destination_ip or '-'}:{a.destination_port or '-'}",
                        "protocol": a.protocol,
                        "context": a.title[:60],
                        "ref_id": (
                            f"inc={a.incident_id or '-'} | "
                            f"flow={a.flow_id or '-'} | alert={a.alert_id}"
                        ),
                    }
                )
        for rec in bundle.dns_analysis.get("records", [])[:15]:
            if len(rows) >= 35:
                break
            pidx = rec.get("packet_index")
            if pidx is None:
                continue
            rows.append(
                {
                    "packet_index": pidx,
                    "timestamp": rec.get("timestamp", ""),
                    "src": rec.get("src_ip") or "-",
                    "dst": rec.get("dst_ip") or "-",
                    "protocol": f"DNS/{rec.get('query_type') or 'Q'}",
                    "context": str(rec.get("query_name") or "-")[:60],
                    "ref_id": "dns_record",
                }
            )
        return rows[:35]

    def _collect_recommended_steps(self, bundle: InvestigationBundle) -> list[str]:
        steps: list[str] = []
        for a in bundle.active_alerts:
            for step in a.recommended_investigation_steps:
                if step not in steps:
                    steps.append(step)
        return steps

    def _styled_table(
        self,
        data: list[list[Paragraph]],
        col_widths: list[float],
        has_header: bool = False,
    ) -> Table:
        table = Table(data, colWidths=col_widths, repeatRows=1 if has_header else 0)
        cmds: list[tuple[Any, ...]] = [
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        if has_header:
            cmds.extend(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ]
            )
        table.setStyle(TableStyle(cmds))
        return table

    def _build_severity_chart(self, sev_dist: dict[str, int]) -> Drawing:
        drawing = Drawing(420, 120)
        chart = VerticalBarChart()
        chart.x = 40
        chart.y = 20
        chart.height = 85
        chart.width = 350
        labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        values = [
            int(sev_dist.get("CRITICAL", 0)),
            int(sev_dist.get("HIGH", 0)),
            int(sev_dist.get("MEDIUM", 0)),
            int(sev_dist.get("LOW", 0)),
            int(sev_dist.get("INFORMATIONAL", 0)),
        ]
        chart.data = [values]
        chart.categoryAxis.categoryNames = labels
        chart.valueAxis.valueMin = 0
        chart.valueAxis.valueMax = max(1, *values) + 1
        chart.valueAxis.valueStep = 1
        chart.bars[0].fillColor = colors.HexColor("#0284c7")
        drawing.add(chart)
        return drawing
