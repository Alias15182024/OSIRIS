"""System status route handlers for OSIRIS Phase 1.5 Backend API."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.api.deps import get_db
from backend.api.schemas.status import StatusResponse
from backend.config import settings

logger = logging.getLogger("osiris.api.status")

router = APIRouter()


@router.get("/status", response_model=StatusResponse)
def get_system_status(db: Session = Depends(get_db)) -> StatusResponse:
    """Check overall system health and live database connectivity.

    Executes a lightweight query against the database session to confirm
    connectivity. Never exposes raw database credentials, connection strings,
    or internal tracebacks.
    """
    try:
        db.execute(text("SELECT 1"))
        db_status = "connected"
        overall_status = "healthy"
    except Exception as exc:
        logger.warning(
            "Database connectivity check failed: %s", exc.__class__.__name__
        )
        db_status = "disconnected"
        overall_status = "degraded"

    return StatusResponse(
        status=overall_status,
        system="osiris",
        database=db_status,
        host_id=settings.host_id,
    )
