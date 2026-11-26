"""Structured logging configuration with investigation correlation context."""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

analysis_id_ctx: ContextVar[str | None] = ContextVar("analysis_id", default=None)


class AnalysisContextFilter(logging.Filter):
    """Attach the active analysis_id from ContextVar to every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.analysis_id = analysis_id_ctx.get() or "-"
        return True


class JsonFormatter(logging.Formatter):
    """Emit structured JSON log lines for production and SIEM ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "analysis_id": getattr(record, "analysis_id", "-"),
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", json_logs: bool = False) -> None:
    """Configure root logger with either JSON or human-readable output."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Clear existing handlers to make repeated calls (e.g. tests) deterministic
    root_logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(AnalysisContextFilter())

    if json_logs:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt=(
                    "%(asctime)s | %(levelname)-8s | analysis=%(analysis_id)s "
                    "| %(name)s | %(message)s"
                ),
                datefmt="%Y-%m-%dT%H:%M:%SZ",
            )
        )

    root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger."""
    return logging.getLogger(name)
