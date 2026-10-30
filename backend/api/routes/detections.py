"""Detection route handlers for OSIRIS (Phase 2 Milestone 2.4)."""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user, get_db
from backend.api.schemas.detection import (
    AcknowledgeDetectionRequest,
    DetectionQueryParams,
    DetectionResponse,
    DetectionRuleResponse,
    PaginatedDetectionResponse,
)
from backend.db.models.app_user import AppUser
from backend.db.models.detection_rule import DetectionRule
from backend.services.detection.service import DetectionService, _ensure_utc

router = APIRouter()
_detection_service = DetectionService()


@router.get("", response_model=PaginatedDetectionResponse)
def list_detections(
    params: DetectionQueryParams = Depends(),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> PaginatedDetectionResponse:
    """List security detections with filtering and pagination.

    Supported query parameters:
    - host_id: UUID of monitored host
    - severity: Filter by severity ('info', 'low', 'medium', 'high', 'critical')
    - category: Filter by rule category (e.g., 'privilege_escalation', 'reconnaissance')
    - rule_id: Filter by unique rule ID (e.g., 'OSIRIS-PRIV-001')
    - status: Filter by detection status ('open', 'acknowledged', 'resolved', 'closed')
    - start_time: Earliest detection timestamp (inclusive)
    - end_time: Latest detection timestamp (inclusive)
    - limit: Page size (default 50, minimum 1, maximum 500)
    - offset: Page offset (default 0, minimum 0)
    """
    if params.start_time and params.end_time:
        st = _ensure_utc(params.start_time)
        et = _ensure_utc(params.end_time)
        if st is not None and et is not None and st > et:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="start_time must be less than or equal to end_time",
            )

    items, total = _detection_service.get_detections(
        db=db,
        host_id=params.host_id,
        severity=params.severity,
        category=params.category,
        rule_id=params.rule_id,
        status=params.status,
        start_time=params.start_time,
        end_time=params.end_time,
        limit=params.limit,
        offset=params.offset,
    )

    return PaginatedDetectionResponse(
        items=[DetectionResponse.from_orm_model(d) for d in items],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )


@router.get("/rules", response_model=list[DetectionRuleResponse])
def list_detection_rules(
    category: Optional[str] = Query(None, description="Filter rules by category"),
    severity: Optional[str] = Query(None, description="Filter rules by severity"),
    enabled: Optional[bool] = Query(None, description="Filter rules by enabled status"),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> list[DetectionRuleResponse]:
    """List registered declarative detection rules."""
    rules = _detection_service.get_rules(
        db=db,
        category=category,
        severity=severity,
        enabled=enabled,
    )
    return [DetectionRuleResponse.model_validate(r) for r in rules]


@router.get("/rules/{rule_identifier}", response_model=DetectionRuleResponse)
def get_detection_rule(
    rule_identifier: str,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> DetectionRuleResponse:
    """Retrieve a single detection rule by UUID or string rule_id."""
    # Check if rule_identifier is a UUID
    rule = None
    try:
        rule_uuid = uuid.UUID(rule_identifier)
        rule = db.execute(select(DetectionRule).where(DetectionRule.id == rule_uuid)).scalar_one_or_none()
    except ValueError:
        pass

    if rule is None:
        rule = db.execute(select(DetectionRule).where(DetectionRule.rule_id == rule_identifier)).scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_identifier}' not found",
        )

    return DetectionRuleResponse.model_validate(rule)


@router.get("/{detection_id}", response_model=DetectionResponse)
def get_detection(
    detection_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> DetectionResponse:
    """Retrieve a single detection alert by UUID."""
    detection = _detection_service.get_detection(db, detection_id)
    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection with ID '{detection_id}' not found",
        )

    return DetectionResponse.from_orm_model(detection)


@router.post("/{detection_id}/acknowledge", response_model=DetectionResponse)
def acknowledge_detection(
    detection_id: uuid.UUID,
    payload: Optional[AcknowledgeDetectionRequest] = None,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> DetectionResponse:
    """Acknowledge a detection alert and record user attribution."""
    notes = payload.notes if payload else None
    try:
        detection = _detection_service.acknowledge_detection(
            db=db,
            detection_id=detection_id,
            user_id=current_user.id,
            notes=notes,
        )
        db.commit()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )

    return DetectionResponse.from_orm_model(detection)
