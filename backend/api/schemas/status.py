"""System status and error Pydantic schemas for OSIRIS Phase 1.5 Backend API."""

from __future__ import annotations

from pydantic import BaseModel


class StatusResponse(BaseModel):
    """System health and operational status response."""

    status: str
    system: str
    database: str
    host_id: str


class ErrorDetail(BaseModel):
    """Structured error detail response."""

    detail: str
    error_code: str
