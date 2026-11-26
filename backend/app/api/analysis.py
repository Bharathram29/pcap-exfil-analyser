"""Investigation execution, query, alert workflow, and report download endpoints."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse

from app.core.config import Settings
from app.core.database import DatabaseManager
from app.core.security import require_api_key_if_configured, validate_analysis_id
from app.schemas.analysis import (
    AlertStatusUpdateRequest,
    AlertStatusUpdateResponse,
    AnalysisStartRequest,
    AnalysisStartResponse,
    IncidentStatusUpdateRequest,
    IncidentStatusUpdateResponse,
    InvestigationListItem,
)
from app.services.alert_manager import AlertManager
from app.services.analyzer import (
    AnalysisCancelledError,
    AnalysisNotFoundError,
    AnalysisOrchestrator,
)
from app.services.audit import AuditService
from app.services.packet_store import PacketStore

router = APIRouter(
    tags=["analysis"],
    dependencies=[Depends(require_api_key_if_configured)],
)


def _orchestrator(request: Request) -> AnalysisOrchestrator:
    settings: Settings = request.app.state.settings
    db: DatabaseManager = request.app.state.db
    return AnalysisOrchestrator(settings=settings, db=db)


def _require_completed_bundle(
    orchestrator: AnalysisOrchestrator,
    analysis_id: str,
) -> dict[str, Any]:
    validate_analysis_id(analysis_id)
    try:
        bundle = orchestrator.load_bundle(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    if bundle.get("status") != "COMPLETED":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Analysis {analysis_id} is not completed (status={bundle.get('status')}).",
        )
    return bundle


def _set_job_state(
    request: Request,
    analysis_id: str,
    *,
    status_val: str | None = None,
    progress_pct: int | None = None,
    stage: str | None = None,
    cancel_requested: bool | None = None,
) -> dict[str, Any]:
    with request.app.state.jobs_lock:
        job = request.app.state.analysis_jobs.setdefault(
            analysis_id,
            {"status": "INGESTED", "progress_pct": 0, "stage": "Queued", "cancel_requested": False},
        )
        if status_val is not None:
            job["status"] = status_val
        if progress_pct is not None:
            job["progress_pct"] = progress_pct
        if stage is not None:
            job["stage"] = stage
        if cancel_requested is not None:
            job["cancel_requested"] = cancel_requested
        return dict(job)


def _run_background_analysis(
    settings: Settings,
    db: DatabaseManager,
    jobs: dict[str, dict[str, Any]],
    jobs_lock: Any,
    analysis_id: str,
) -> None:
    def progress_cb(pct: int, stage: str) -> None:
        with jobs_lock:
            job = jobs.setdefault(analysis_id, {})
            job["status"] = "PROCESSING" if pct < 100 else "COMPLETED"
            job["progress_pct"] = pct
            job["stage"] = stage

    def should_cancel() -> bool:
        with jobs_lock:
            return bool(jobs.get(analysis_id, {}).get("cancel_requested", False))

    orch = AnalysisOrchestrator(settings=settings, db=db)
    try:
        orch.run_analysis(analysis_id, progress_callback=progress_cb, should_cancel=should_cancel)
    except AnalysisCancelledError:
        with jobs_lock:
            jobs[analysis_id] = {
                "status": "CANCELLED",
                "progress_pct": 0,
                "stage": "Cancelled",
                "cancel_requested": True,
            }
    except Exception:
        with jobs_lock:
            jobs[analysis_id] = {
                "status": "FAILED",
                "progress_pct": 0,
                "stage": "Failed",
                "cancel_requested": False,
            }


@router.get("/api/investigations", response_model=list[InvestigationListItem])
def list_investigations(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
) -> list[InvestigationListItem]:
    """List past and active PCAP forensic investigations."""
    orch = _orchestrator(request)
    return [InvestigationListItem(**item) for item in orch.list_investigations(limit=limit)]


@router.post("/api/analysis/start", response_model=AnalysisStartResponse)
def start_analysis(
    request: Request,
    payload: AnalysisStartRequest,
    background_tasks: BackgroundTasks,
) -> AnalysisStartResponse:
    """Trigger the end-to-end PCAP forensic pipeline for an ingested capture."""
    validate_analysis_id(payload.analysis_id)
    orch = _orchestrator(request)
    try:
        # Ensure investigation exists before starting
        orch.load_bundle(payload.analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    _set_job_state(
        request,
        payload.analysis_id,
        status_val="PROCESSING",
        progress_pct=1,
        stage="Queued",
        cancel_requested=False,
    )

    if payload.run_async:
        background_tasks.add_task(
            _run_background_analysis,
            request.app.state.settings,
            request.app.state.db,
            request.app.state.analysis_jobs,
            request.app.state.jobs_lock,
            payload.analysis_id,
        )
        return AnalysisStartResponse(
            analysis_id=payload.analysis_id,
            status="PROCESSING",
            message="Analysis queued in background.",
        )

    try:
        bundle = orch.run_analysis(
            payload.analysis_id,
            progress_callback=lambda pct, stg: _set_job_state(
                request,
                payload.analysis_id,
                status_val="PROCESSING" if pct < 100 else "COMPLETED",
                progress_pct=pct,
                stage=stg,
            ),
        )
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except Exception as exc:
        _set_job_state(request, payload.analysis_id, status_val="FAILED", stage="Failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis pipeline failed due to an internal processing error.",
        ) from exc

    return AnalysisStartResponse(
        analysis_id=payload.analysis_id,
        status=bundle["status"],
        processing_duration_ms=bundle.get("processing_duration_ms"),
        message="Analysis completed successfully.",
    )


@router.get("/api/analysis/{analysis_id}/status")
def get_analysis_status(request: Request, analysis_id: str) -> dict[str, Any]:
    """Return live progress and status for a running or completed investigation."""
    validate_analysis_id(analysis_id)
    orch = _orchestrator(request)
    try:
        bundle = orch.load_bundle(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    with request.app.state.jobs_lock:
        job = dict(request.app.state.analysis_jobs.get(analysis_id, {}))

    db_status = bundle.get("status", "UNKNOWN")
    if db_status == "COMPLETED":
        return {
            "analysis_id": analysis_id,
            "status": "COMPLETED",
            "progress_pct": 100,
            "stage": "Completed",
            "cancel_requested": False,
        }
    return {
        "analysis_id": analysis_id,
        "status": job.get("status", db_status),
        "progress_pct": job.get("progress_pct", 0),
        "stage": job.get("stage", db_status),
        "cancel_requested": job.get("cancel_requested", False),
    }


@router.post("/api/analysis/{analysis_id}/cancel")
def cancel_analysis(request: Request, analysis_id: str) -> dict[str, Any]:
    """Request cooperative cancellation of a background analysis task."""
    validate_analysis_id(analysis_id)
    orch = _orchestrator(request)
    try:
        orch.load_bundle(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    job = _set_job_state(request, analysis_id, cancel_requested=True)
    return {"analysis_id": analysis_id, "cancel_requested": True, "status": job["status"]}


@router.get("/api/analysis/{analysis_id}")
def get_analysis(request: Request, analysis_id: str) -> dict[str, Any]:
    """Return full analysis state or completed forensic bundle."""
    validate_analysis_id(analysis_id)
    orch = _orchestrator(request)
    try:
        return orch.load_bundle(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/api/analysis/{analysis_id}/summary")
def get_analysis_summary(request: Request, analysis_id: str) -> dict[str, Any]:
    """Return dashboard KPIs, analytics series, host/port rankings, and network graph."""
    orch = _orchestrator(request)
    bundle = _require_completed_bundle(orch, analysis_id)
    return {
        "analysis_id": analysis_id,
        "status": bundle["status"],
        "generated_at_utc": bundle["generated_at_utc"],
        "capture_metadata": bundle["capture_metadata"],
        "summary": bundle["summary"],
        "protocol_distribution": bundle["protocol_distribution"],
        "traffic_over_time": bundle["traffic_over_time"],
        "top_hosts": bundle["top_hosts"],
        "top_ports": bundle["top_ports"],
        "http_analysis": bundle["http_analysis"],
        "tls_analysis": bundle["tls_analysis"],
        "network_graph": bundle.get("network_graph", {"nodes": [], "edges": []}),
        "limitations": bundle.get("limitations", []),
    }


@router.get("/api/analysis/{analysis_id}/alerts")
def get_analysis_alerts(
    request: Request,
    analysis_id: str,
    severity: str | None = Query(default=None),
    protocol: str | None = Query(default=None),
    alert_status: str | None = Query(default=None, alias="status"),
    include_suppressed: bool = Query(default=True),
    search: str | None = Query(default=None),
) -> dict[str, Any]:
    """Return filtered alerts (active and optionally allowlist-suppressed)."""
    orch = _orchestrator(request)
    bundle = _require_completed_bundle(orch, analysis_id)
    alerts = list(bundle.get("alerts", []))

    if not include_suppressed:
        alerts = [a for a in alerts if not a.get("suppressed")]
    if severity:
        sev_u = severity.strip().upper()
        alerts = [a for a in alerts if str(a.get("severity", "")).upper() == sev_u]
    if protocol:
        proto_u = protocol.strip().upper()
        alerts = [a for a in alerts if str(a.get("protocol", "")).upper() == proto_u]
    if alert_status:
        st_l = alert_status.strip().lower()
        alerts = [a for a in alerts if str(a.get("status", "")).lower() == st_l]
    if search:
        q = search.strip().lower()
        alerts = [
            a
            for a in alerts
            if q in str(a.get("title", "")).lower()
            or q in str(a.get("source_ip", "")).lower()
            or q in str(a.get("destination_ip", "")).lower()
            or q in str(a.get("explanation", "")).lower()
        ]

    return {
        "analysis_id": analysis_id,
        "total": len(alerts),
        "active_count": sum(1 for a in alerts if not a.get("suppressed")),
        "suppressed_count": sum(1 for a in alerts if a.get("suppressed")),
        "alerts": alerts,
    }


@router.patch(
    "/api/analysis/{analysis_id}/alerts/{alert_id}",
    response_model=AlertStatusUpdateResponse,
)
def update_alert_status(
    request: Request,
    analysis_id: str,
    alert_id: str,
    payload: AlertStatusUpdateRequest,
) -> AlertStatusUpdateResponse:
    """Update an alert's SOC investigation workflow status."""
    orch = _orchestrator(request)
    _require_completed_bundle(orch, analysis_id)

    db: DatabaseManager = request.app.state.db
    updated = AlertManager().update_alert_status(db, analysis_id, alert_id, payload.status)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id!r} not found in analysis {analysis_id!r}.",
        )
    orch.sync_alert_status_in_bundle(analysis_id, alert_id, payload.status)
    AuditService().log_event(
        db,
        analysis_id,
        "ALERT_STATUS_UPDATED",
        actor="analyst",
        details={"alert_id": alert_id, "new_status": payload.status},
    )
    return AlertStatusUpdateResponse(
        analysis_id=analysis_id,
        alert_id=alert_id,
        status=payload.status,
        updated=True,
    )


@router.get("/api/analysis/{analysis_id}/incidents")
def get_analysis_incidents(
    request: Request,
    analysis_id: str,
    severity: str | None = Query(default=None),
    incident_status: str | None = Query(default=None, alias="status"),
    include_suppressed: bool = Query(default=True),
    search: str | None = Query(default=None),
) -> dict[str, Any]:
    """Return correlated security incidents with drill-down metadata."""
    orch = _orchestrator(request)
    bundle = _require_completed_bundle(orch, analysis_id)
    incidents = list(bundle.get("incidents", []))

    if not include_suppressed:
        incidents = [i for i in incidents if not i.get("suppressed")]
    if severity:
        sev_u = severity.strip().upper()
        incidents = [i for i in incidents if str(i.get("overall_severity", "")).upper() == sev_u]
    if incident_status:
        st_l = incident_status.strip().lower()
        incidents = [i for i in incidents if str(i.get("status", "")).lower() == st_l]
    if search:
        q = search.strip().lower()
        incidents = [
            i
            for i in incidents
            if q in str(i.get("incident_title", "")).lower()
            or any(q in h.lower() for h in i.get("source_hosts", []))
            or any(q in h.lower() for h in i.get("destination_hosts", []))
            or any(q in c.lower() for c in i.get("detection_categories", []))
        ]

    return {
        "analysis_id": analysis_id,
        "total": len(incidents),
        "active_count": sum(1 for i in incidents if not i.get("suppressed")),
        "suppressed_count": sum(1 for i in incidents if i.get("suppressed")),
        "incidents": incidents,
    }


@router.get("/api/analysis/{analysis_id}/incidents/{incident_id}")
def get_incident_detail(
    request: Request,
    analysis_id: str,
    incident_id: str,
) -> dict[str, Any]:
    """Return a correlated incident and all constituent raw alerts for drill-down."""
    orch = _orchestrator(request)
    bundle = _require_completed_bundle(orch, analysis_id)
    incidents = list(bundle.get("incidents", []))
    inc = next((i for i in incidents if i.get("incident_id") == incident_id), None)
    if inc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id!r} not found in analysis {analysis_id!r}.",
        )
    alert_ids = set(inc.get("alert_ids", []))
    alerts = [a for a in bundle.get("alerts", []) if a.get("alert_id") in alert_ids]
    return {
        "analysis_id": analysis_id,
        "incident": inc,
        "alerts": alerts,
    }


@router.patch(
    "/api/analysis/{analysis_id}/incidents/{incident_id}",
    response_model=IncidentStatusUpdateResponse,
)
def update_incident_status(
    request: Request,
    analysis_id: str,
    incident_id: str,
    payload: IncidentStatusUpdateRequest,
) -> IncidentStatusUpdateResponse:
    """Update a correlated incident's SOC investigation workflow status."""
    orch = _orchestrator(request)
    _require_completed_bundle(orch, analysis_id)

    db: DatabaseManager = request.app.state.db
    updated = AlertManager().update_incident_status(db, analysis_id, incident_id, payload.status)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id!r} not found in analysis {analysis_id!r}.",
        )
    orch.sync_incident_status_in_bundle(analysis_id, incident_id, payload.status)
    AuditService().log_event(
        db,
        analysis_id,
        "INCIDENT_STATUS_UPDATED",
        actor="analyst",
        details={"incident_id": incident_id, "new_status": payload.status},
    )
    return IncidentStatusUpdateResponse(
        analysis_id=analysis_id,
        incident_id=incident_id,
        status=payload.status,
        updated=True,
    )


@router.get("/api/analysis/{analysis_id}/flows")
def get_analysis_flows(
    request: Request,
    analysis_id: str,
    protocol: str | None = Query(default=None),
    direction: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Return reconstructed bidirectional network flows."""
    orch = _orchestrator(request)
    bundle = _require_completed_bundle(orch, analysis_id)
    flows = list(bundle.get("flows", []))

    if protocol:
        proto_u = protocol.strip().upper()
        flows = [
            f
            for f in flows
            if str(f.get("application_protocol", "")).upper() == proto_u
            or str(f.get("transport_protocol", "")).upper() == proto_u
        ]
    if direction:
        dir_l = direction.strip().lower()
        flows = [f for f in flows if str(f.get("direction", "")).lower() == dir_l]

    total = len(flows)
    sliced = flows[offset : offset + limit]
    return {"analysis_id": analysis_id, "total": total, "flows": sliced}


@router.get("/api/analysis/{analysis_id}/packets")
def get_analysis_packets(
    request: Request,
    analysis_id: str,
    ip: str | None = Query(default=None),
    src_ip: str | None = Query(default=None),
    dst_ip: str | None = Query(default=None),
    port: int | None = Query(default=None, ge=0, le=65535),
    protocol: str | None = Query(default=None),
    start_time: float | None = Query(default=None),
    end_time: float | None = Query(default=None),
    alert_id: str | None = Query(default=None),
    flow_id: str | None = Query(default=None),
    search: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Search and paginate stored packet-level forensic evidence."""
    orch = _orchestrator(request)
    _require_completed_bundle(orch, analysis_id)
    db: DatabaseManager = request.app.state.db
    return PacketStore().query_packets(
        db,
        analysis_id,
        ip=ip,
        src_ip=src_ip,
        dst_ip=dst_ip,
        port=port,
        protocol=protocol,
        start_time=start_time,
        end_time=end_time,
        alert_id=alert_id,
        flow_id=flow_id,
        search=search,
        limit=limit,
        offset=offset,
    )


@router.get("/api/analysis/{analysis_id}/packets/{packet_index}")
def get_packet_detail(
    request: Request,
    analysis_id: str,
    packet_index: int,
) -> dict[str, Any]:
    """Return full decoded metadata, related flow, and related alerts for a single packet."""
    orch = _orchestrator(request)
    bundle = _require_completed_bundle(orch, analysis_id)
    db: DatabaseManager = request.app.state.db
    pkt = PacketStore().get_packet(db, analysis_id, packet_index)
    if pkt is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Packet #{packet_index} not found in analysis {analysis_id!r}.",
        )
    rel_flow = next(
        (f for f in bundle.get("flows", []) if f.get("flow_id") == pkt.get("flow_id")),
        None,
    )
    alert_ids = set(pkt.get("alert_ids", []))
    rel_alerts = [a for a in bundle.get("alerts", []) if a.get("alert_id") in alert_ids]
    return {
        "analysis_id": analysis_id,
        "packet": pkt,
        "flow": rel_flow,
        "alerts": rel_alerts,
    }


@router.get("/api/analysis/{analysis_id}/dns")
def get_analysis_dns(request: Request, analysis_id: str) -> dict[str, Any]:
    """Return DNS aggregate statistics and observed DNS query/response records."""
    orch = _orchestrator(request)
    bundle = _require_completed_bundle(orch, analysis_id)
    return {
        "analysis_id": analysis_id,
        "dns_analysis": bundle.get("dns_analysis", {}),
    }


@router.get("/api/analysis/{analysis_id}/timeline")
def get_analysis_timeline(request: Request, analysis_id: str) -> dict[str, Any]:
    """Return chronological security incident timeline."""
    orch = _orchestrator(request)
    bundle = _require_completed_bundle(orch, analysis_id)
    timeline = bundle.get("timeline", [])
    return {"analysis_id": analysis_id, "total": len(timeline), "timeline": timeline}


@router.get("/api/analysis/{analysis_id}/mitre")
def get_analysis_mitre(request: Request, analysis_id: str) -> dict[str, Any]:
    """Return validated MITRE ATT&CK Enterprise mappings for the investigation."""
    orch = _orchestrator(request)
    bundle = _require_completed_bundle(orch, analysis_id)
    mappings = bundle.get("mitre_mappings", [])
    return {"analysis_id": analysis_id, "total": len(mappings), "mitre_mappings": mappings}


@router.get("/api/analysis/{analysis_id}/threat-intel")
def get_analysis_threat_intel(request: Request, analysis_id: str) -> dict[str, Any]:
    """Return optional external threat intelligence enrichment separated from packet evidence."""
    orch = _orchestrator(request)
    bundle = _require_completed_bundle(orch, analysis_id)
    return {
        "analysis_id": analysis_id,
        "threat_intelligence": bundle.get("threat_intelligence", {}),
    }


@router.post("/api/analysis/{analysis_id}/threat-intel/enrich")
def trigger_threat_intel_enrichment(request: Request, analysis_id: str) -> dict[str, Any]:
    """Run non-blocking external threat intelligence enrichment on investigation indicators."""
    orch = _orchestrator(request)
    try:
        intel = orch.enrich_threat_intel(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"analysis_id": analysis_id, "threat_intelligence": intel}


@router.get("/api/analysis/{analysis_id}/audit")
def get_analysis_audit(
    request: Request,
    analysis_id: str,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """Return forensic audit log trail and analysis run history for an investigation."""
    orch = _orchestrator(request)
    try:
        bundle = orch.load_bundle(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    db: DatabaseManager = request.app.state.db
    audit = AuditService()
    return {
        "analysis_id": analysis_id,
        "audit_logs": audit.list_events(db, analysis_id, limit=limit),
        "analysis_history": audit.list_runs(db, analysis_id),
        "integrity": bundle.get("integrity", {}),
    }


@router.get("/api/analysis/{analysis_id}/integrity")
def verify_analysis_integrity(request: Request, analysis_id: str) -> dict[str, Any]:
    """Verify capture and generated report SHA-256 digests against stored forensic metadata."""
    orch = _orchestrator(request)
    bundle = _require_completed_bundle(orch, analysis_id)
    inv_row = orch._fetch_investigation_row(analysis_id)
    if inv_row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    integrity = bundle.get("integrity", {})
    settings: Settings = request.app.state.settings
    result = AuditService().verify_integrity(
        stored_pcap_path=Path(inv_row["stored_path"]),
        expected_pcap_sha256=inv_row["sha256"],
        html_report_path=settings.reports_dir / f"report_{analysis_id}.html",
        expected_html_sha256=integrity.get("html_report_sha256"),
        pdf_report_path=settings.reports_dir / f"report_{analysis_id}.pdf",
        expected_pdf_sha256=integrity.get("pdf_report_sha256"),
    )
    return {"analysis_id": analysis_id, **result}


@router.get("/api/analysis/{analysis_id}/report")
def download_analysis_report(
    request: Request,
    analysis_id: str,
    fmt: str = Query(default="html", alias="format"),
) -> FileResponse:
    """Download the generated standalone HTML or PDF forensic incident report."""
    fmt_clean = fmt.strip().lower()
    if fmt_clean not in {"html", "pdf"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported report format. Use 'html' or 'pdf'.",
        )

    orch = _orchestrator(request)
    try:
        report_path = orch.ensure_report_file(analysis_id, fmt_clean)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    media_type = "application/pdf" if fmt_clean == "pdf" else "text/html; charset=utf-8"
    AuditService().log_event(
        request.app.state.db,
        analysis_id,
        "REPORT_DOWNLOADED",
        actor="analyst",
        details={"format": fmt_clean, "filename": report_path.name},
    )
    return FileResponse(
        path=str(report_path),
        media_type=media_type,
        filename=report_path.name,
    )
