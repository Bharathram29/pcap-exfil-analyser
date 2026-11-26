"""Secure PCAP and PCAPNG ingestion engine with forensic integrity tracking."""

from __future__ import annotations

import shutil
import sqlite3
import struct
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from app.core.config import Settings
from app.core.database import DatabaseManager
from app.core.logging import get_logger
from app.models.packet import CaptureMetadata
from app.services.audit import AuditService
from app.utils.security import (
    UnsafePathError,
    compute_sha256_file,
    safe_resolve_within,
    sanitize_filename,
)

logger = get_logger("services.ingestion")

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}

# Classic & nanosecond PCAP magic numbers: (endian_char, format_label)
PCAP_MAGICS: dict[bytes, tuple[str, str]] = {
    b"\xd4\xc3\xb2\xa1": ("<", "pcap_le_us"),
    b"\xa1\xb2\xc3\xd4": (">", "pcap_be_us"),
    b"\x4d\x3c\xb2\xa1": ("<", "pcap_le_ns"),
    b"\xa1\xb2\x3c\x4d": (">", "pcap_be_ns"),
}

PCAPNG_SHB_TYPE = b"\x0a\x0d\x0d\x0a"
PCAPNG_BYTE_ORDER_MAGICS: dict[bytes, str] = {
    b"\x4d\x3c\x2b\x1a": "<",
    b"\x1a\x2b\x3c\x4d": ">",
}

SUPPORTED_LINK_TYPES: dict[int, str] = {
    0: "BSD Loopback (NULL)",
    1: "Ethernet (EN10MB)",
    101: "Raw IP",
    108: "OpenBSD Loopback",
    113: "Linux Cooked SLL",
    228: "Raw IPv4",
    229: "Raw IPv6",
    276: "Linux Cooked SLL2",
}


class PcapIngestionError(Exception):
    """Base error for capture ingestion failures."""


class InvalidExtensionError(PcapIngestionError):
    """Raised when the uploaded filename does not end in .pcap or .pcapng."""


class InvalidSignatureError(PcapIngestionError):
    """Raised when file magic bytes do not match PCAP or PCAPNG."""


class FileTooLargeError(PcapIngestionError):
    """Raised when the capture exceeds the configured maximum upload size."""


class MalformedCaptureError(PcapIngestionError):
    """Raised when a capture header is too short or unrecoverably corrupted."""


def inspect_capture_header(file_path: Path) -> tuple[str, int | None, str | None, bool, list[str]]:
    """Inspect magic bytes and link-layer header without loading the whole file."""
    warnings: list[str] = []
    file_size = file_path.stat().st_size
    if file_size == 0:
        raise InvalidSignatureError("Capture file is empty (0 bytes).")
    if file_size < 12:
        raise InvalidSignatureError("File is too small to contain a valid PCAP/PCAPNG header.")

    with file_path.open("rb") as handle:
        header = handle.read(4096)

    magic4 = header[:4]
    if magic4 in PCAP_MAGICS:
        endian, _label = PCAP_MAGICS[magic4]
        if len(header) < 24:
            raise MalformedCaptureError("PCAP global header is truncated (< 24 bytes).")
        (link_type,) = struct.unpack(f"{endian}I", header[20:24])
        link_name = SUPPORTED_LINK_TYPES.get(link_type, f"Unsupported DLT ({link_type})")
        supported = link_type in SUPPORTED_LINK_TYPES
        if not supported:
            warnings.append(f"Unsupported link-layer type DLT={link_type}; dissection limited.")
        return "pcap", link_type, link_name, supported, warnings

    if magic4 == PCAPNG_SHB_TYPE:
        endian = PCAPNG_BYTE_ORDER_MAGICS.get(header[8:12])
        if endian is None:
            raise InvalidSignatureError("Invalid PCAPNG section header byte-order magic.")
        link_type, link_name, supported = _extract_pcapng_link_type(header, endian)
        if link_type is not None and not supported:
            warnings.append(f"Unsupported link-layer type DLT={link_type}; dissection limited.")
        return "pcapng", link_type, link_name, supported, warnings

    raise InvalidSignatureError(
        f"Unrecognized capture file signature: {magic4.hex()}"
    )


def _extract_pcapng_link_type(header: bytes, endian: str) -> tuple[int | None, str | None, bool]:
    """Scan initial PCAPNG blocks for the first Interface Description Block (type 1)."""
    offset = 0
    limit = len(header)
    while offset + 12 <= limit:
        block_type, block_len = struct.unpack(f"{endian}II", header[offset : offset + 8])
        if block_len < 12 or offset + block_len > limit:
            break
        if block_type == 1 and offset + 16 <= limit:
            (link_type,) = struct.unpack(f"{endian}H", header[offset + 8 : offset + 10])
            link_name = SUPPORTED_LINK_TYPES.get(link_type, f"Unsupported DLT ({link_type})")
            return link_type, link_name, link_type in SUPPORTED_LINK_TYPES
        offset += block_len
    return None, "PCAPNG (Link type pending)", True


class PcapIngestor:
    """Validates, stores safely, hashes, and registers incoming PCAP/PCAPNG files."""

    def __init__(self, settings: Settings, db: DatabaseManager) -> None:
        self.settings = settings
        self.db = db

    def ingest_stream(
        self,
        stream: BinaryIO,
        original_filename: str,
        analysis_id: str | None = None,
    ) -> CaptureMetadata:
        """Stream an uploaded binary file to confined storage with size & header checks."""
        try:
            clean_name = sanitize_filename(original_filename)
        except UnsafePathError as exc:
            raise PcapIngestionError(str(exc)) from exc

        self._validate_extension(clean_name)

        inv_id = analysis_id or uuid.uuid4().hex
        self.settings.ensure_directories()
        target_dir = safe_resolve_within(
            self.settings.upload_dir,
            self.settings.upload_dir / inv_id,
        )
        target_dir.mkdir(parents=True, exist_ok=True)
        dest_path = safe_resolve_within(target_dir, target_dir / clean_name)

        max_bytes = self.settings.max_upload_size_bytes
        bytes_written = 0
        chunk_size = 1024 * 256

        try:
            with dest_path.open("wb") as out_file:
                while chunk := stream.read(chunk_size):
                    bytes_written += len(chunk)
                    if bytes_written > max_bytes:
                        raise FileTooLargeError(
                            f"Upload exceeds maximum allowed size of {max_bytes} bytes."
                        )
                    out_file.write(chunk)

            return self._finalize_ingested_file(
                dest_path=dest_path,
                analysis_id=inv_id,
                original_filename=original_filename,
                clean_name=clean_name,
            )
        except Exception:
            if target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)
            raise

    def ingest_existing_file(
        self,
        source_path: Path,
        analysis_id: str | None = None,
        copy_to_vault: bool = True,
    ) -> CaptureMetadata:
        """Ingest a local PCAP/PCAPNG file on disk."""
        if not source_path.is_file():
            raise FileNotFoundError(f"Capture file not found: {source_path}")

        clean_name = sanitize_filename(source_path.name)
        self._validate_extension(clean_name)

        file_size = source_path.stat().st_size
        if file_size > self.settings.max_upload_size_bytes:
            raise FileTooLargeError(
                f"File size {file_size} exceeds maximum "
                f"{self.settings.max_upload_size_bytes} bytes."
            )

        inv_id = analysis_id or uuid.uuid4().hex
        if copy_to_vault:
            self.settings.ensure_directories()
            target_dir = safe_resolve_within(
                self.settings.upload_dir, self.settings.upload_dir / inv_id
            )
            target_dir.mkdir(parents=True, exist_ok=True)
            dest_path = safe_resolve_within(target_dir, target_dir / clean_name)
            shutil.copy2(source_path, dest_path)
        else:
            dest_path = source_path.resolve()

        return self._finalize_ingested_file(
            dest_path=dest_path,
            analysis_id=inv_id,
            original_filename=source_path.name,
            clean_name=clean_name,
        )

    def _validate_extension(self, filename: str) -> None:
        ext = Path(filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise InvalidExtensionError(
                f"Unsupported file extension {ext!r}. Allowed: {sorted(ALLOWED_EXTENSIONS)}"
            )

    def _finalize_ingested_file(
        self,
        dest_path: Path,
        analysis_id: str,
        original_filename: str,
        clean_name: str,
    ) -> CaptureMetadata:
        file_size = dest_path.stat().st_size
        capture_format, link_type, link_name, supported, warnings = inspect_capture_header(
            dest_path
        )
        sha256 = compute_sha256_file(dest_path)
        now_utc = datetime.now(UTC).isoformat()

        metadata = CaptureMetadata(
            analysis_id=analysis_id,
            original_filename=original_filename,
            sanitized_filename=clean_name,
            stored_path=str(dest_path),
            file_size_bytes=file_size,
            sha256=sha256,
            capture_format=capture_format,
            ingested_at_utc=now_utc,
            link_layer_type=link_type,
            link_layer_name=link_name,
            supported_link_layer=supported,
            warnings=warnings,
        )
        self._record_investigation(metadata)
        AuditService().log_event(
            self.db,
            analysis_id,
            "PCAP_INGESTED",
            actor="ingest",
            details={
                "filename": clean_name,
                "file_size_bytes": file_size,
                "sha256": sha256,
                "capture_format": capture_format,
                "link_layer_type": link_type,
            },
        )
        logger.info(
            "Ingested %s (%s, %d bytes, sha256=%s)",
            clean_name,
            capture_format,
            file_size,
            sha256[:12],
        )
        return metadata

    def _record_investigation(self, metadata: CaptureMetadata) -> None:
        """Persist initial forensic investigation record in SQLite."""
        try:
            with self.db.connection() as conn:
                conn.execute(
                    """
                    INSERT INTO investigations (
                        analysis_id, filename, stored_path, file_size_bytes,
                        sha256, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        metadata.analysis_id,
                        metadata.sanitized_filename,
                        metadata.stored_path,
                        metadata.file_size_bytes,
                        metadata.sha256,
                        "INGESTED",
                        metadata.ingested_at_utc,
                        metadata.ingested_at_utc,
                    ),
                )
        except sqlite3.Error as exc:
            raise PcapIngestionError(f"Failed to persist investigation metadata: {exc}") from exc
