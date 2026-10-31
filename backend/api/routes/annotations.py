"""FastAPI route handlers for Evidence Tags and Annotations (Phase 2 Milestone 2.7)."""

from __future__ import annotations

import logging
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user, get_db, require_roles
from backend.api.schemas.annotations import (
    AnnotationNoteCreateRequest,
    AnnotationNoteResponse,
    AnnotationNoteUpdateRequest,
    EvidenceAnnotationsResponse,
    TagAssociateRequest,
    TagAssociationResponse,
    TagCreateRequest,
    TagDisassociateRequest,
    TagResponse,
    TagUpdateRequest,
)
from backend.db.models.app_user import AppUser
from backend.services.workspace import (
    AnnotationNotFoundError,
    AnnotationService,
    TagAssociationDuplicateError,
    TagDuplicateError,
    TagNotFoundError,
    WorkspacePermissionError,
)

logger = logging.getLogger("osiris.api.annotations")
router = APIRouter()
annotation_service = AnnotationService()


# ── Evidence Tags ─────────────────────────────────────────────────────────────

@router.get(
    "/tags",
    response_model=list[TagResponse],
    summary="List available evidence tags",
)
def list_tags(
    category: Optional[str] = Query(None, description="Filter tags by category"),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> list[TagResponse]:
    """Retrieve all defined evidence tags with their active usage counts."""
    tag_rows = annotation_service.list_tags(db, category=category)
    results = []
    for tag, count in tag_rows:
        resp = TagResponse.model_validate(tag)
        resp.association_count = count
        results.append(resp)
    return results


@router.post(
    "/tags",
    response_model=TagResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new reusable evidence tag",
)
def create_tag(
    request: TagCreateRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> TagResponse:
    """Create a new reusable evidence tag."""
    try:
        tag = annotation_service.create_tag(
            db=db,
            name=request.name,
            description=request.description,
            color=request.color,
            category=request.category,
            user=current_user,
        )
        db.commit()
        db.refresh(tag)
        return TagResponse.model_validate(tag)
    except TagDuplicateError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.delete(
    "/tags/{tag_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an evidence tag",
)
def delete_tag(
    tag_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> None:
    """Delete an evidence tag and remove all associated bindings."""
    try:
        annotation_service.delete_tag(db, tag_id, current_user)
        db.commit()
    except TagNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.patch(
    "/tags/{tag_id}",
    response_model=TagResponse,
    summary="Update an existing evidence tag",
)
def update_tag(
    tag_id: uuid.UUID,
    request: TagUpdateRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> TagResponse:
    """Update metadata, color, or category for an existing evidence tag."""
    try:
        tag = annotation_service.update_tag(
            db=db,
            tag_id=tag_id,
            name=request.name,
            description=request.description,
            color=request.color,
            category=request.category,
            user=current_user,
        )
        db.commit()
        db.refresh(tag)
        resp = TagResponse.model_validate(tag)
        resp.association_count = len(tag.associations)
        return resp
    except TagNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except TagDuplicateError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


# ── Tag Associations ──────────────────────────────────────────────────────────

@router.post(
    "/tags/associate",
    response_model=TagAssociationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Attach an evidence tag to a forensic item",
)
def associate_tag(
    request: TagAssociateRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> TagAssociationResponse:
    """Attach an evidence tag to any supported forensic evidence item."""
    try:
        assoc = annotation_service.associate_tag(
            db=db,
            evidence_type=request.evidence_type,
            evidence_id=request.evidence_id,
            tag_id=request.tag_id,
            tag_name=request.tag_name,
            host_id=request.host_id,
            user=current_user,
        )
        db.commit()
        db.refresh(assoc)
        return TagAssociationResponse(
            id=assoc.id,
            tag_id=assoc.tag.id,
            tag_name=assoc.tag.name,
            tag_color=assoc.tag.color,
            tag_category=assoc.tag.category,
            evidence_type=assoc.evidence_type,
            evidence_id=assoc.evidence_id,
            host_id=assoc.host_id,
            created_by_id=assoc.created_by_id,
            created_at=assoc.created_at,
        )
    except (TagNotFoundError, ValueError) as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except TagAssociationDuplicateError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/tags/disassociate",
    summary="Remove a tag from an evidence item",
)
def disassociate_tag(
    request: TagDisassociateRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> dict:
    """Remove an active tag association from an evidence item."""
    removed = annotation_service.disassociate_tag(
        db=db,
        tag_id=request.tag_id,
        evidence_type=request.evidence_type,
        evidence_id=request.evidence_id,
    )
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tag association not found for this evidence item.",
        )
    db.commit()
    return {"status": "disassociated"}


# ── Annotations & Notes ───────────────────────────────────────────────────────

@router.get(
    "",
    response_model=EvidenceAnnotationsResponse,
    summary="Retrieve annotations and tags for an evidence item",
)
def get_evidence_annotations(
    evidence_type: str = Query(..., description="Target entity type (e.g. process, detection)"),
    evidence_id: str = Query(..., description="Target entity ID"),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> EvidenceAnnotationsResponse:
    """Retrieve all active tags and analyst notes associated with an evidence item."""
    assocs = annotation_service.get_tags_for_evidence(db, evidence_type, evidence_id)
    notes = annotation_service.list_notes_for_evidence(db, evidence_type, evidence_id)

    tag_items = [
        TagAssociationResponse(
            id=a.id,
            tag_id=a.tag.id,
            tag_name=a.tag.name,
            tag_color=a.tag.color,
            tag_category=a.tag.category,
            evidence_type=a.evidence_type,
            evidence_id=a.evidence_id,
            host_id=a.host_id,
            created_by_id=a.created_by_id,
            created_at=a.created_at,
        )
        for a in assocs
    ]

    note_items = [
        AnnotationNoteResponse(
            id=n.id,
            evidence_type=n.evidence_type,
            evidence_id=n.evidence_id,
            host_id=n.host_id,
            workspace_id=n.workspace_id,
            author_id=n.author_id,
            author_name=n.author.username if n.author else None,
            annotation_text=n.annotation_text,
            created_at=n.created_at,
            updated_at=n.updated_at,
        )
        for n in notes
    ]

    return EvidenceAnnotationsResponse(
        evidence_type=evidence_type,
        evidence_id=evidence_id,
        tags=tag_items,
        notes=note_items,
    )


@router.post(
    "/notes",
    response_model=AnnotationNoteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add an analyst note to an evidence item",
)
def create_note(
    request: AnnotationNoteCreateRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> AnnotationNoteResponse:
    """Add an analyst investigation note to any forensic evidence record."""
    note = annotation_service.create_note(
        db=db,
        evidence_type=request.evidence_type,
        evidence_id=request.evidence_id,
        text=request.annotation_text,
        host_id=request.host_id,
        workspace_id=request.workspace_id,
        user=current_user,
    )
    db.commit()
    db.refresh(note)
    return AnnotationNoteResponse(
        id=note.id,
        evidence_type=note.evidence_type,
        evidence_id=note.evidence_id,
        host_id=note.host_id,
        workspace_id=note.workspace_id,
        author_id=note.author_id,
        author_name=current_user.username,
        annotation_text=note.annotation_text,
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


@router.delete(
    "/notes/{note_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an analyst note",
)
def delete_note(
    note_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> None:
    """Delete an analyst note, verifying author or admin authorization."""
    try:
        annotation_service.delete_note(db, note_id, current_user)
        db.commit()
    except AnnotationNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except WorkspacePermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


@router.patch(
    "/notes/{note_id}",
    response_model=AnnotationNoteResponse,
    summary="Update an existing analyst note",
)
def update_note(
    note_id: uuid.UUID,
    request: AnnotationNoteUpdateRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> AnnotationNoteResponse:
    """Update text for an existing analyst investigation note."""
    try:
        note = annotation_service.update_note(
            db=db,
            note_id=note_id,
            text=request.annotation_text,
            user=current_user,
        )
        db.commit()
        db.refresh(note)
        return AnnotationNoteResponse(
            id=note.id,
            evidence_type=note.evidence_type,
            evidence_id=note.evidence_id,
            host_id=note.host_id,
            workspace_id=note.workspace_id,
            author_id=note.author_id,
            author_name=note.author.username if note.author else current_user.username,
            annotation_text=note.annotation_text,
            created_at=note.created_at,
            updated_at=note.updated_at,
        )
    except AnnotationNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except WorkspacePermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
