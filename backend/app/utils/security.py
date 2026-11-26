"""File path sanitization, path confinement, and cryptographic hashing utilities."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath, PureWindowsPath

_SAFE_CHAR_RE = re.compile(r"[^A-Za-z0-9._-]+")


class UnsafePathError(ValueError):
    """Raised when a supplied filename or path attempts traversal or is invalid."""


def sanitize_filename(raw_filename: str) -> str:
    """Return a safe basename stripped of directory traversal and control characters."""
    if not raw_filename or "\x00" in raw_filename:
        raise UnsafePathError("Filename is empty or contains null bytes.")

    # Normalize both Windows and POSIX separators before extracting basename
    posix_name = PurePosixPath(raw_filename).name
    win_name = PureWindowsPath(posix_name).name
    basename = win_name.strip()

    if not basename or basename in {".", ".."} or ".." in basename:
        raise UnsafePathError(f"Unsafe filename rejected: {raw_filename!r}")

    cleaned = _SAFE_CHAR_RE.sub("_", basename).lstrip(".")
    if not cleaned:
        raise UnsafePathError(f"Filename has no usable characters: {raw_filename!r}")

    return cleaned[:200]


def safe_resolve_within(base_dir: Path, target_path: Path) -> Path:
    """Resolve target_path and verify it resides strictly inside base_dir."""
    resolved_base = base_dir.resolve()
    resolved_target = target_path.resolve()
    if resolved_target == resolved_base or not resolved_target.is_relative_to(resolved_base):
        raise UnsafePathError(
            f"Path {resolved_target} escapes confined directory {resolved_base}."
        )
    return resolved_target


def compute_sha256_file(file_path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Stream-compute the SHA-256 hex digest of a file on disk."""
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def compute_sha256_bytes(data: bytes) -> str:
    """Compute the SHA-256 hex digest of an in-memory byte buffer."""
    return hashlib.sha256(data).hexdigest()
