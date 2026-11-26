"""Forensic audit logging, analysis history tracking, and integrity verification."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.database import DatabaseManager
from app.utils.security import compute_sha256_file


class AuditService:
    """Persist and query forensic investigation audit trails and run history."""

    def log_event(
        self,
        db: DatabaseManager,
        analysis_id: str,
        action: str,
        *,
        actor: str = "system",
        details: dict[str, Any] | None = None,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with db.connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (analysis_id, action, actor, details_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (analysis_id, action, actor, json.dumps(details or {}), now),
            )

    def list_events(
        self,
        db: DatabaseManager,
        analysis_id: str,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        with db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, analysis_id, action, actor, details_json, created_at
                FROM audit_logs
                WHERE analysis_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (analysis_id, limit),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "analysis_id": row["analysis_id"],
                "action": row["action"],
                "actor": row["actor"],
                "details": json.loads(row["details_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def start_run(self, db: DatabaseManager, analysis_id: str) -> str:
        run_id = f"run-{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC).isoformat()
        with db.connection() as conn:
            conn.execute(
                """
                INSERT INTO analysis_runs (run_id, analysis_id, status, started_at)
                VALUES (?, ?, ?, ?)
                """,
                (run_id, analysis_id, "PROCESSING", now),
            )
        return run_id

    def complete_run(
        self,
        db: DatabaseManager,
        run_id: str,
        *,
        duration_ms: float,
        packet_count: int,
        flow_count: int,
        active_alert_count: int,
        incident_count: int,
        html_report_sha256: str | None,
        pdf_report_sha256: str | None,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with db.connection() as conn:
            conn.execute(
                """
                UPDATE analysis_runs
                SET status = 'COMPLETED',
                    completed_at = ?,
                    processing_duration_ms = ?,
                    packet_count = ?,
                    flow_count = ?,
                    active_alert_count = ?,
                    incident_count = ?,
                    html_report_sha256 = ?,
                    pdf_report_sha256 = ?
                WHERE run_id = ?
                """,
                (
                    now,
                    duration_ms,
                    packet_count,
                    flow_count,
                    active_alert_count,
                    incident_count,
                    html_report_sha256,
                    pdf_report_sha256,
                    run_id,
                ),
            )

    def fail_run(self, db: DatabaseManager, run_id: str, error_message: str) -> None:
        now = datetime.now(UTC).isoformat()
        with db.connection() as conn:
            conn.execute(
                """
                UPDATE analysis_runs
                SET status = 'FAILED', completed_at = ?, error_message = ?
                WHERE run_id = ?
                """,
                (now, error_message[:500], run_id),
            )

    def list_runs(self, db: DatabaseManager, analysis_id: str) -> list[dict[str, Any]]:
        with db.connection() as conn:
            rows = conn.execute(
                """
                SELECT run_id, analysis_id, status, started_at, completed_at,
                       processing_duration_ms, packet_count, flow_count,
                       active_alert_count, incident_count, html_report_sha256,
                       pdf_report_sha256, error_message
                FROM analysis_runs
                WHERE analysis_id = ?
                ORDER BY started_at DESC
                """,
                (analysis_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def verify_integrity(
        self,
        *,
        stored_pcap_path: Path,
        expected_pcap_sha256: str,
        html_report_path: Path,
        expected_html_sha256: str | None,
        pdf_report_path: Path,
        expected_pdf_sha256: str | None,
    ) -> dict[str, Any]:
        """Verify on-disk SHA-256 digests of original capture and generated reports."""
        pcap_present = stored_pcap_path.is_file()
        pcap_actual = compute_sha256_file(stored_pcap_path) if pcap_present else None
        pcap_match = bool(pcap_present and pcap_actual == expected_pcap_sha256)

        html_present = html_report_path.is_file()
        html_actual = compute_sha256_file(html_report_path) if html_present else None
        html_match = (
            bool(html_present and html_actual == expected_html_sha256)
            if expected_html_sha256
            else html_present
        )

        pdf_present = pdf_report_path.is_file()
        pdf_actual = compute_sha256_file(pdf_report_path) if pdf_present else None
        pdf_match = (
            bool(pdf_present and pdf_actual == expected_pdf_sha256)
            if expected_pdf_sha256
            else pdf_present
        )

        return {
            "capture_present": pcap_present,
            "capture_expected_sha256": expected_pcap_sha256,
            "capture_actual_sha256": pcap_actual,
            "capture_integrity_verified": pcap_match,
            "html_report_present": html_present,
            "html_report_expected_sha256": expected_html_sha256,
            "html_report_actual_sha256": html_actual,
            "html_report_verified": html_match,
            "pdf_report_present": pdf_present,
            "pdf_report_expected_sha256": expected_pdf_sha256,
            "pdf_report_actual_sha256": pdf_actual,
            "pdf_report_verified": pdf_match,
            "disclaimer": (
                "SHA-256 verification checks local file integrity against recorded digests; "
                "this does not constitute formal legal certification or full organizational "
                "chain-of-custody compliance without procedural controls."
            ),
        }
