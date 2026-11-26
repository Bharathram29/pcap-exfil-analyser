"""Health check response schema."""

from pydantic import BaseModel


class DirectoryStatus(BaseModel):
    upload_dir_exists: bool
    reports_dir_exists: bool
    rules_dir_exists: bool


class HealthResponse(BaseModel):
    status: str
    app_name: str
    version: str
    environment: str
    database_ok: bool
    timestamp_utc: str
    directories: DirectoryStatus
