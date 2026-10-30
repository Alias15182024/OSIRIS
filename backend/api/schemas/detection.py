"""Pydantic schemas for detection rules and alert endpoints (Phase 2 Milestone 2.4)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class DetectionQueryParams(BaseModel):
    """Query parameters for filtering and paginating detections."""

    host_id: Optional[UUID] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    rule_id: Optional[str] = None
    status: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class DetectionRuleResponse(BaseModel):
    """Declarative detection rule definition representation."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: str
    name: str
    description: Optional[str] = None
    category: str
    severity: str
    enabled: bool
    version: int
    rule_type: str
    conditions: dict[str, Any]
    sequence_conditions: Optional[dict[str, Any]] = None
    time_window_seconds: Optional[int] = None
    rule_metadata: Optional[dict[str, Any]] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


class DetectionResponse(BaseModel):
    """Single detection alert matching Detection ORM entity."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: UUID
    rule_code: Optional[str] = None
    rule_name: Optional[str] = None
    rule_version: int
    host_id: UUID
    hostname: Optional[str] = None
    event_id: Optional[UUID] = None
    process_id: Optional[UUID] = None
    session_id: Optional[UUID] = None
    timestamp: datetime
    severity: str
    title: str
    description: Optional[str] = None
    category: str
    status: str
    notification_status: str
    matched_conditions: dict[str, Any]
    evidence: dict[str, Any]
    dedup_hash: Optional[str] = None
    created_at: datetime
    acknowledged_at: Optional[datetime] = None
    acknowledged_by_id: Optional[UUID] = None
    acknowledged_by_username: Optional[str] = None

    @classmethod
    def from_orm_model(cls, detection: Any) -> DetectionResponse:
        """Construct DetectionResponse with related rule and host labels."""
        rule_code = getattr(detection.rule, "rule_id", None) if getattr(detection, "rule", None) else None
        rule_name = getattr(detection.rule, "name", None) if getattr(detection, "rule", None) else None
        hostname = getattr(detection.host, "hostname", None) if getattr(detection, "host", None) else None
        ack_user = getattr(detection.acknowledged_by, "username", None) if getattr(detection, "acknowledged_by", None) else None

        return cls(
            id=detection.id,
            rule_id=detection.rule_id,
            rule_code=rule_code,
            rule_name=rule_name,
            rule_version=detection.rule_version,
            host_id=detection.host_id,
            hostname=hostname,
            event_id=detection.event_id,
            process_id=detection.process_id,
            session_id=detection.session_id,
            timestamp=detection.timestamp,
            severity=detection.severity,
            title=detection.title,
            description=detection.description,
            category=detection.category,
            status=detection.status,
            notification_status=detection.notification_status,
            matched_conditions=detection.matched_conditions or {},
            evidence=detection.evidence or {},
            dedup_hash=detection.dedup_hash,
            created_at=detection.created_at,
            acknowledged_at=detection.acknowledged_at,
            acknowledged_by_id=detection.acknowledged_by_id,
            acknowledged_by_username=ack_user,
        )


class PaginatedDetectionResponse(BaseModel):
    """Paginated collection of detection alerts."""

    items: list[DetectionResponse]
    total: int
    limit: int
    offset: int


class AcknowledgeDetectionRequest(BaseModel):
    """Request payload to acknowledge a detection alert."""

    notes: Optional[str] = None
