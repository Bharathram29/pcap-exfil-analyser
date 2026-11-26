"""SQLite persistence layer for investigations, forensic metadata, and alerts."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS investigations (
    analysis_id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    processing_duration_ms REAL,
    error_message TEXT,
    summary_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_investigations_created_at
    ON investigations (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_investigations_sha256
    ON investigations (sha256);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    analysis_id TEXT NOT NULL,
    rule_id TEXT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    priority_score REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'New',
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,
    timestamp TEXT,
    suppressed INTEGER NOT NULL DEFAULT 0,
    allowlist_reason TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES investigations (analysis_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alerts_analysis_id
    ON alerts (analysis_id);

CREATE INDEX IF NOT EXISTS idx_alerts_severity
    ON alerts (analysis_id, severity);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    analysis_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    risk_score REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open',
    alert_count INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    suppressed INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES investigations (analysis_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_incidents_analysis_id
    ON incidents (analysis_id);

CREATE INDEX IF NOT EXISTS idx_incidents_severity
    ON incidents (analysis_id, severity);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL,
    packet_index INTEGER NOT NULL,
    timestamp_epoch REAL NOT NULL,
    timestamp_utc TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    transport_protocol TEXT,
    length INTEGER NOT NULL,
    ttl INTEGER,
    ip_version INTEGER,
    flow_id TEXT,
    tcp_flags TEXT,
    alert_ids_json TEXT NOT NULL DEFAULT '[]',
    incident_ids_json TEXT NOT NULL DEFAULT '[]',
    decoded_fields_json TEXT NOT NULL DEFAULT '{}',
    raw_summary TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (analysis_id) REFERENCES investigations (analysis_id) ON DELETE CASCADE,
    UNIQUE (analysis_id, packet_index)
);

CREATE INDEX IF NOT EXISTS idx_packets_analysis_idx
    ON packets (analysis_id, packet_index);

CREATE INDEX IF NOT EXISTS idx_packets_src_ip
    ON packets (analysis_id, src_ip);

CREATE INDEX IF NOT EXISTS idx_packets_dst_ip
    ON packets (analysis_id, dst_ip);

CREATE INDEX IF NOT EXISTS idx_packets_proto
    ON packets (analysis_id, protocol);

CREATE INDEX IF NOT EXISTS idx_packets_flow_id
    ON packets (analysis_id, flow_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'system',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_analysis_id
    ON audit_logs (analysis_id, created_at DESC);

CREATE TABLE IF NOT EXISTS analysis_runs (
    run_id TEXT PRIMARY KEY,
    analysis_id TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    processing_duration_ms REAL,
    packet_count INTEGER DEFAULT 0,
    flow_count INTEGER DEFAULT 0,
    active_alert_count INTEGER DEFAULT 0,
    incident_count INTEGER DEFAULT 0,
    html_report_sha256 TEXT,
    pdf_report_sha256 TEXT,
    error_message TEXT,
    FOREIGN KEY (analysis_id) REFERENCES investigations (analysis_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_runs_analysis_id
    ON analysis_runs (analysis_id, started_at DESC);
"""


class DatabaseManager:
    """Thread-safe SQLite helper using per-operation connections and WAL mode."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a configured SQLite connection with commit/rollback semantics."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_schema(self) -> None:
        """Create tables and indexes and apply safe additive column migrations."""
        with self.connection() as conn:
            conn.executescript(SCHEMA_SQL)
            self._ensure_column(conn, "investigations", "investigator_id", "TEXT DEFAULT 'analyst'")
            self._ensure_column(conn, "investigations", "started_at", "TEXT")
            self._ensure_column(conn, "packets", "tcp_flags", "TEXT")
            self._ensure_column(conn, "packets", "incident_ids_json", "TEXT NOT NULL DEFAULT '[]'")

    def _ensure_column(
        self, conn: sqlite3.Connection, table: str, column: str, col_def: str
    ) -> None:
        cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table});").fetchall()}
        if column not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def};")

    def check_health(self) -> bool:
        """Verify database read/write connectivity."""
        try:
            with self.connection() as conn:
                row = conn.execute("SELECT 1 AS ok;").fetchone()
                return bool(row and row["ok"] == 1)
        except sqlite3.Error:
            return False
