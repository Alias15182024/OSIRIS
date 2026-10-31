"""Pydantic schemas for Evidence Tagging and Analyst Annotations (Phase 2 Milestone 2.7)."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TagCreateRequest(BaseModel):
    """Payload to create a new reusable evidence tag."""

    name: str = Field(..., min_length=1, max_length=100, pattern="^[a-zA-Z0-9_-]+$")
    description: Optional[str] = None
    color: Optional[str] = Field(None, max_length=50)
    category: str = Field(default="general", max_length=50)


class TagUpdateRequest(BaseModel):
    """Payload to update an existing evidence tag."""

    name: Optional[str] = Field(None, min_length=1, max_length=100, pattern="^[a-zA-Z0-9_-]+$")
    description: Optional[str] = None
    color: Optional[str] = Field(None, max_length=50)
    category: Optional[str] = Field(None, max_length=50)


class TagResponse(BaseModel):
    """Detailed tag response model."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: Optional[str] = None
    color: Optional[str] = None
    category: str
    created_by_id: Optional[UUID] = None
    created_at: datetime
    association_count: int = 0


class TagAssociateRequest(BaseModel):
    """Payload to attach an evidence tag to a target entity."""

    tag_id: Optional[UUID] = None
    tag_name: Optional[str] = Field(None, min_length=1, max_length=100)
    evidence_type: str = Field(..., min_length=1, max_length=50)
    evidence_id: str = Field(..., min_length=1, max_length=255)
    host_id: Optional[UUID] = None


class TagDisassociateRequest(BaseModel):
    """Payload to remove an evidence tag association."""

    tag_id: UUID
    evidence_type: str = Field(..., min_length=1, max_length=50)
    evidence_id: str = Field(..., min_length=1, max_length=255)


class TagAssociationResponse(BaseModel):
    """Representation of an active tag association."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tag_id: UUID
    tag_name: str
    tag_color: Optional[str] = None
    tag_category: str
    evidence_type: str
    evidence_id: str
    host_id: Optional[UUID] = None
    created_by_id: Optional[UUID] = None
    created_at: datetime


class AnnotationNoteCreateRequest(BaseModel):
    """Payload to attach an analyst note to an evidence item."""

    evidence_type: str = Field(..., min_length=1, max_length=50)
    evidence_id: str = Field(..., min_length=1, max_length=255)
    annotation_text: str = Field(..., min_length=1)
    host_id: Optional[UUID] = None
    workspace_id: Optional[UUID] = None


class AnnotationNoteUpdateRequest(BaseModel):
    """Payload to edit an existing analyst note."""

    annotation_text: str = Field(..., min_length=1)


class AnnotationNoteResponse(BaseModel):
    """Representation of an analyst note."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    evidence_type: str
    evidence_id: str
    host_id: Optional[UUID] = None
    workspace_id: Optional[UUID] = None
    author_id: Optional[UUID] = None
    author_name: Optional[str] = None
    annotation_text: str
    created_at: datetime
    updated_at: Optional[datetime] = None


class EvidenceAnnotationsResponse(BaseModel):
    """Combined tags and notes for an evidence item."""

    evidence_type: str
    evidence_id: str
    tags: list[TagAssociationResponse] = Field(default_factory=list)
    notes: list[AnnotationNoteResponse] = Field(default_factory=list)
