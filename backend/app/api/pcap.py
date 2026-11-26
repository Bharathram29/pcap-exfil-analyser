"""PCAP/PCAPNG upload and secure ingestion endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status

from app.core.config import Settings
from app.core.database import DatabaseManager
from app.core.security import require_api_key_if_configured
from app.schemas.analysis import PcapUploadResponse
from app.services.ingestion import (
    FileTooLargeError,
    InvalidExtensionError,
    InvalidSignatureError,
    MalformedCaptureError,
    PcapIngestionError,
    PcapIngestor,
)

router = APIRouter(
    prefix="/api/pcap",
    tags=["pcap"],
    dependencies=[Depends(require_api_key_if_configured)],
)


@router.post(
    "/upload",
    response_model=PcapUploadResponse,
    status_code=status.HTTP_201_CREATED,
)
def upload_pcap(
    request: Request,
    file: Annotated[UploadFile, File()],
) -> PcapUploadResponse:
    """Validate, hash, and securely store an uploaded .pcap or .pcapng file."""
    settings: Settings = request.app.state.settings
    db: DatabaseManager = request.app.state.db
    ingestor = PcapIngestor(settings=settings, db=db)

    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is missing a filename.",
        )

    try:
        metadata = ingestor.ingest_stream(file.file, original_filename=file.filename)
    except FileTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=str(exc),
        ) from exc
    except (
        InvalidExtensionError,
        InvalidSignatureError,
        MalformedCaptureError,
        PcapIngestionError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    finally:
        file.file.close()

    return PcapUploadResponse(
        analysis_id=metadata.analysis_id,
        filename=metadata.sanitized_filename,
        file_size_bytes=metadata.file_size_bytes,
        sha256=metadata.sha256,
        capture_format=metadata.capture_format,
        link_layer_type=metadata.link_layer_type,
        link_layer_name=metadata.link_layer_name,
        supported_link_layer=metadata.supported_link_layer,
        warnings=metadata.warnings,
        status="INGESTED",
        ingested_at_utc=metadata.ingested_at_utc,
    )
