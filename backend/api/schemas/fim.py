"""Pydantic schemas for File Integrity Monitoring (FIM) REST endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class BaselineQueryParams(BaseModel):
    """Query parameters for listing and filtering FIM baselines."""

    host_id: Optional[UUID] = None
    status: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class BaselineCreateRequest(BaseModel):
    """Payload to trigger or record creation of a new FIM baseline."""

    host_id: UUID
    paths: list[str] = Field(min_length=1)
    include_patterns: Optional[list[str]] = None
    exclude_patterns: Optional[list[str]] = None

    @field_validator("paths")
    @classmethod
    def validate_paths(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("paths list must not be empty.")
        clean_paths: list[str] = []
        for p in v:
            if not isinstance(p, str) or not p.strip():
                raise ValueError("path must be a non-empty string.")
            if "\x00" in p:
                raise ValueError("path must not contain null bytes.")
            s = p.strip()
            if not s.startswith("/"):
                raise ValueError(f"path '{p}' must be an absolute path starting with '/'.")
            clean_paths.append(s)
        return clean_paths


class BaselineResponse(BaseModel):
    """Summary of a file integrity baseline."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    host_id: UUID
    hostname: Optional[str] = None
    version: int
    status: str
    path_scope: list[str]
    include_patterns: Optional[list[str]] = None
    exclude_patterns: Optional[list[str]] = None
    total_files: int
    total_bytes: int
    scan_duration_ms: Optional[int] = None
    error_message: Optional[str] = None
    baseline_at: datetime
    completed_at: Optional[datetime] = None
    created_at: datetime

    @classmethod
    def from_orm_model(cls, b: Any) -> BaselineResponse:
        hostname = getattr(b.host, "hostname", None) if getattr(b, "host", None) else None
        return cls(
            id=b.id,
            host_id=b.host_id,
            hostname=hostname,
            version=b.version,
            status=b.status,
            path_scope=b.path_scope or [],
            include_patterns=b.include_patterns,
            exclude_patterns=b.exclude_patterns,
            total_files=b.total_files,
            total_bytes=b.total_bytes,
            scan_duration_ms=b.scan_duration_ms,
            error_message=b.error_message,
            baseline_at=b.baseline_at,
            completed_at=b.completed_at,
            created_at=b.created_at,
        )


class BaselineDetailResponse(BaselineResponse):
    """Detailed baseline including scan metadata."""

    baseline_metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_orm_model(cls, b: Any) -> BaselineDetailResponse:
        hostname = getattr(b.host, "hostname", None) if getattr(b, "host", None) else None
        return cls(
            id=b.id,
            host_id=b.host_id,
            hostname=hostname,
            version=b.version,
            status=b.status,
            path_scope=b.path_scope or [],
            include_patterns=b.include_patterns,
            exclude_patterns=b.exclude_patterns,
            total_files=b.total_files,
            total_bytes=b.total_bytes,
            scan_duration_ms=b.scan_duration_ms,
            error_message=b.error_message,
            baseline_metadata=b.baseline_metadata,
            baseline_at=b.baseline_at,
            completed_at=b.completed_at,
            created_at=b.created_at,
        )


class PaginatedBaselineResponse(BaseModel):
    """Paginated collection of FIM baselines."""

    items: list[BaselineResponse]
    total: int
    limit: int
    offset: int


class BaselineFileResponse(BaseModel):
    """Single file entry recorded inside a baseline."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    baseline_id: UUID
    host_id: UUID
    file_path: str
    file_name: Optional[str] = None
    file_type: str
    hash_sha256: Optional[str] = None
    hash_sha1: Optional[str] = None
    hash_md5: Optional[str] = None
    file_size: Optional[int] = None
    permissions: Optional[str] = None
    mode: Optional[int] = None
    owner_uid: Optional[int] = None
    owner_gid: Optional[int] = None
    owner_user: Optional[str] = None
    owner_group: Optional[str] = None
    mtime: Optional[datetime] = None
    ctime: Optional[datetime] = None
    inode: Optional[int] = None
    device_id: Optional[int] = None
    symlink_target: Optional[str] = None
    is_suid: bool = False
    is_sgid: bool = False
    is_executable: bool = False
    fingerprint_metadata: Optional[dict[str, Any]] = None
    created_at: datetime


class PaginatedBaselineFileResponse(BaseModel):
    """Paginated collection of baseline files."""

    items: list[BaselineFileResponse]
    total: int
    limit: int
    offset: int


class DeviationQueryParams(BaseModel):
    """Query parameters for listing and filtering FIM deviations."""

    host_id: Optional[UUID] = None
    baseline_id: Optional[UUID] = None
    file_path: Optional[str] = None
    deviation_type: Optional[str] = None
    severity: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class DeviationResponse(BaseModel):
    """Single FIM deviation record."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    host_id: UUID
    hostname: Optional[str] = None
    baseline_id: UUID
    baseline_file_id: Optional[UUID] = None
    detection_id: Optional[UUID] = None
    file_path: str
    file_type: Optional[str] = None
    deviation_type: str
    severity: str
    is_content_modified: bool
    is_metadata_modified: bool
    expected_values: Optional[dict[str, Any]] = None
    observed_values: Optional[dict[str, Any]] = None
    summary: Optional[str] = None
    explanation: Optional[str] = None
    detected_at: datetime
    created_at: datetime

    @classmethod
    def from_orm_model(cls, d: Any) -> DeviationResponse:
        hostname = getattr(d.host, "hostname", None) if getattr(d, "host", None) else None
        return cls(
            id=d.id,
            host_id=d.host_id,
            hostname=hostname,
            baseline_id=d.baseline_id,
            baseline_file_id=d.baseline_file_id,
            detection_id=d.detection_id,
            file_path=d.file_path,
            file_type=d.file_type,
            deviation_type=d.deviation_type,
            severity=d.severity,
            is_content_modified=d.is_content_modified,
            is_metadata_modified=d.is_metadata_modified,
            expected_values=d.expected_values,
            observed_values=d.observed_values,
            summary=d.summary,
            explanation=d.explanation,
            detected_at=d.detected_at,
            created_at=d.created_at,
        )


class DeviationDetailResponse(DeviationResponse):
    """Detailed FIM deviation response."""
    pass


class PaginatedDeviationResponse(BaseModel):
    """Paginated collection of FIM deviations."""

    items: list[DeviationResponse]
    total: int
    limit: int
    offset: int


class VerifyIntegrityRequest(BaseModel):
    """Request payload to trigger differential integrity verification."""

    host_id: UUID
    baseline_id: Optional[UUID] = None
    paths: Optional[list[str]] = None

    @field_validator("paths")
    @classmethod
    def validate_paths(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is None:
            return None
        if not v:
            raise ValueError("paths list must not be empty if provided.")
        clean_paths: list[str] = []
        for p in v:
            if not isinstance(p, str) or not p.strip():
                raise ValueError("path must be a non-empty string.")
            if "\x00" in p:
                raise ValueError("path must not contain null bytes.")
            s = p.strip()
            if not s.startswith("/"):
                raise ValueError(f"path '{p}' must be an absolute path starting with '/'.")
            clean_paths.append(s)
        return clean_paths


class VerifyIntegrityResponse(BaseModel):
    """Result of an integrity verification execution."""

    baseline_id: UUID
    host_id: UUID
    deviations_count: int
    detections_count: int
    deviations: list[DeviationResponse]
