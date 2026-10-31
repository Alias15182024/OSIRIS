"""File Integrity Monitoring (FIM) route handlers for OSIRIS (Phase 2 Milestone 2.5)."""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user, get_db
from backend.api.schemas.fim import (
    BaselineCreateRequest,
    BaselineDetailResponse,
    BaselineFileResponse,
    BaselineQueryParams,
    BaselineResponse,
    DeviationDetailResponse,
    DeviationQueryParams,
    DeviationResponse,
    PaginatedBaselineFileResponse,
    PaginatedBaselineResponse,
    PaginatedDeviationResponse,
    VerifyIntegrityRequest,
    VerifyIntegrityResponse,
)
from backend.db.models.app_user import AppUser
from backend.services.detection.service import _ensure_utc
from backend.services.fim.service import (
    BaselineNotFoundError,
    FimError,
    FimService,
    HostNotFoundError,
)

router = APIRouter()
_fim_service = FimService()


@router.get("/baselines", response_model=PaginatedBaselineResponse)
def list_baselines(
    params: BaselineQueryParams = Depends(),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> PaginatedBaselineResponse:
    """List file integrity baselines with filtering and pagination.

    Supported query parameters:
    - host_id: UUID of monitored host
    - status: Baseline creation status ('completed', 'failed', 'in_progress', 'pending')
    - start_time: Earliest baseline timestamp (inclusive)
    - end_time: Latest baseline timestamp (inclusive)
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

    items, total = _fim_service.get_baselines(
        db=db,
        host_id=params.host_id,
        status=params.status,
        start_time=params.start_time,
        end_time=params.end_time,
        limit=params.limit,
        offset=params.offset,
    )

    return PaginatedBaselineResponse(
        items=[BaselineResponse.from_orm_model(b) for b in items],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )


@router.post("/baselines", response_model=BaselineResponse, status_code=status.HTTP_201_CREATED)
def create_baseline(
    payload: BaselineCreateRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> BaselineResponse:
    """Create a new file integrity baseline for the specified host."""
    try:
        baseline = _fim_service.create_baseline(
            db=db,
            host_id=payload.host_id,
            paths=payload.paths,
            include_patterns=payload.include_patterns,
            exclude_patterns=payload.exclude_patterns,
        )
        db.commit()
    except HostNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except FimError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    return BaselineResponse.from_orm_model(baseline)


@router.get("/baselines/{baseline_id}", response_model=BaselineDetailResponse)
def get_baseline(
    baseline_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> BaselineDetailResponse:
    """Retrieve full details of a specific baseline."""
    baseline = _fim_service.get_baseline_by_id(db=db, baseline_id=baseline_id)
    if baseline is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline '{baseline_id}' not found.",
        )
    return BaselineDetailResponse.from_orm_model(baseline)


@router.get("/baselines/{baseline_id}/files", response_model=PaginatedBaselineFileResponse)
def get_baseline_files(
    baseline_id: uuid.UUID,
    path_prefix: Optional[str] = Query(None, description="Filter files by path prefix"),
    file_type: Optional[str] = Query(None, description="Filter by file type ('file', 'symlink', etc.)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> PaginatedBaselineFileResponse:
    """List individual files recorded in a baseline."""
    baseline = _fim_service.get_baseline_by_id(db=db, baseline_id=baseline_id)
    if baseline is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline '{baseline_id}' not found.",
        )

    items, total = _fim_service.get_baseline_files(
        db=db,
        baseline_id=baseline_id,
        path_prefix=path_prefix,
        file_type=file_type,
        limit=limit,
        offset=offset,
    )

    return PaginatedBaselineFileResponse(
        items=[BaselineFileResponse.model_validate(f) for f in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/deviations", response_model=PaginatedDeviationResponse)
def list_deviations(
    params: DeviationQueryParams = Depends(),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> PaginatedDeviationResponse:
    """List file integrity deviations with filtering and pagination.

    Supported query parameters:
    - host_id: UUID of monitored host
    - baseline_id: UUID of reference baseline
    - file_path: Substring search in file path
    - deviation_type: Deviation type ('new_file', 'deleted_file', 'modified_file', 'permission_changed', etc.)
    - severity: Threat severity ('info', 'low', 'medium', 'high', 'critical')
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

    items, total = _fim_service.get_deviations(
        db=db,
        host_id=params.host_id,
        baseline_id=params.baseline_id,
        file_path=params.file_path,
        deviation_type=params.deviation_type,
        severity=params.severity,
        start_time=params.start_time,
        end_time=params.end_time,
        limit=params.limit,
        offset=params.offset,
    )

    return PaginatedDeviationResponse(
        items=[DeviationResponse.from_orm_model(d) for d in items],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )


@router.get("/deviations/{deviation_id}", response_model=DeviationDetailResponse)
def get_deviation(
    deviation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> DeviationDetailResponse:
    """Retrieve full details of a specific deviation."""
    dev = _fim_service.get_deviation_by_id(db=db, deviation_id=deviation_id)
    if dev is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deviation '{deviation_id}' not found.",
        )
    return DeviationDetailResponse.from_orm_model(dev)


@router.post("/verify", response_model=VerifyIntegrityResponse)
def verify_integrity(
    payload: VerifyIntegrityRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> VerifyIntegrityResponse:
    """Execute differential file integrity verification against a baseline."""
    try:
        baseline, deviations, detections = _fim_service.verify_host_integrity(
            db=db,
            host_id=payload.host_id,
            baseline_id=payload.baseline_id,
            paths=payload.paths,
        )
        db.commit()
    except HostNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except BaselineNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except FimError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    return VerifyIntegrityResponse(
        baseline_id=baseline.id,
        host_id=payload.host_id,
        deviations_count=len(deviations),
        detections_count=len(detections),
        deviations=[DeviationResponse.from_orm_model(d) for d in deviations],
    )
