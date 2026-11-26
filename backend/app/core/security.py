"""API security helpers: constant-time API key auth and strict ID validation."""

from __future__ import annotations

import hmac
import re

from fastapi import HTTPException, Request, status

_ANALYSIS_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def validate_analysis_id(analysis_id: str) -> str:
    """Validate analysis_id format strictly to prevent path or query abuse."""
    if not _ANALYSIS_ID_RE.match(analysis_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid analysis_id format.",
        )
    return analysis_id


def require_api_key_if_configured(request: Request) -> None:
    """Enforce X-API-Key or Bearer token when PCAP_ANALYSER_API_KEY is configured."""
    settings = request.app.state.settings
    configured = settings.api_key
    if configured is None:
        return

    expected = configured.get_secret_value()
    provided = request.headers.get("X-API-Key", "").strip()
    if not provided:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.lower().startswith("bearer "):
            provided = auth_header[7:].strip()

    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API credentials.",
        )
