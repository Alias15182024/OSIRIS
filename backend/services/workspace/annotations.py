"""Evidence tagging and analyst annotation service (Phase 2 Milestone 2.7)."""

from __future__ import annotations

import logging
from typing import Optional
import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.db.base import utcnow
from backend.db.models.app_user import AppUser
from backend.db.models.evidence_annotation import EvidenceAnnotation
from backend.db.models.evidence_tag import EvidenceTag
from backend.db.models.evidence_tag_association import EvidenceTagAssociation
from backend.services.workspace.models import (
    AnnotationNotFoundError,
    TagAssociationDuplicateError,
    TagDuplicateError,
    TagNotFoundError,
    WorkspacePermissionError,
)

logger = logging.getLogger("osiris.services.annotations")


class AnnotationService:
    """Manages reusable evidence tags, tag associations, and analyst notes."""

    # ── Tag Management ────────────────────────────────────────────────────────

    def create_tag(
        self,
        db: Session,
        name: str,
        description: Optional[str] = None,
        color: Optional[str] = None,
        category: str = "general",
        user: Optional[AppUser] = None,
    ) -> EvidenceTag:
        """Create a new reusable evidence tag."""
        norm_name = name.strip()
        existing = db.execute(
            select(EvidenceTag).where(func.lower(EvidenceTag.name) == norm_name.lower())
        ).scalar_one_or_none()
        if existing is not None:
            raise TagDuplicateError(f"Evidence tag '{norm_name}' already exists.")

        tag = EvidenceTag(
            name=norm_name,
            description=description.strip() if description else None,
            color=color.strip() if color else None,
            category=category.strip() if category else "general",
            created_by_id=user.id if user else None,
            created_at=utcnow(),
        )
        db.add(tag)
        try:
            db.flush()
            db.refresh(tag)
        except IntegrityError as exc:
            raise TagDuplicateError(f"Evidence tag '{norm_name}' already exists.") from exc
        logger.info("Evidence tag created: id=%s name='%s'", tag.id, tag.name)
        return tag

    def list_tags(
        self,
        db: Session,
        category: Optional[str] = None,
    ) -> list[tuple[EvidenceTag, int]]:
        """List all tags with their active association counts."""
        # Query tags with association count
        stmt = (
            select(
                EvidenceTag,
                func.count(EvidenceTagAssociation.id).label("assoc_count"),
            )
            .outerjoin(EvidenceTagAssociation, EvidenceTag.id == EvidenceTagAssociation.tag_id)
            .group_by(EvidenceTag.id)
            .order_by(EvidenceTag.name.asc())
        )
        if category:
            stmt = stmt.where(EvidenceTag.category == category)

        rows = db.execute(stmt).all()
        return [(row[0], row[1]) for row in rows]

    def get_tag(self, db: Session, tag_id: uuid.UUID) -> EvidenceTag:
        """Retrieve a tag by its UUID."""
        tag = db.get(EvidenceTag, tag_id)
        if tag is None:
            raise TagNotFoundError(f"Evidence tag '{tag_id}' not found.")
        return tag

    def delete_tag(
        self,
        db: Session,
        tag_id: uuid.UUID,
        user: AppUser,
    ) -> None:
        """Delete an evidence tag and cascade remove all its associations."""
        tag = self.get_tag(db, tag_id)
        db.delete(tag)
        db.flush()
        logger.info("Evidence tag deleted: id=%s user=%s", tag_id, user.username)

    def update_tag(
        self,
        db: Session,
        tag_id: uuid.UUID,
        name: Optional[str] = None,
        description: Optional[str] = None,
        color: Optional[str] = None,
        category: Optional[str] = None,
        user: Optional[AppUser] = None,
    ) -> EvidenceTag:
        """Update an existing evidence tag's metadata."""
        tag = self.get_tag(db, tag_id)
        if name is not None:
            norm_name = name.strip()
            existing = db.execute(
                select(EvidenceTag).where(
                    func.lower(EvidenceTag.name) == norm_name.lower(),
                    EvidenceTag.id != tag_id,
                )
            ).scalar_one_or_none()
            if existing is not None:
                raise TagDuplicateError(f"Evidence tag '{norm_name}' already exists.")
            tag.name = norm_name

        if description is not None:
            tag.description = description.strip() if description else None
        if color is not None:
            tag.color = color.strip() if color else None
        if category is not None:
            tag.category = category.strip() if category else "general"

        try:
            db.flush()
            db.refresh(tag)
        except IntegrityError as exc:
            raise TagDuplicateError(f"Evidence tag '{tag.name}' already exists.") from exc
        logger.info("Evidence tag updated: id=%s name='%s'", tag.id, tag.name)
        return tag

    # ── Tag Associations ──────────────────────────────────────────────────────

    def associate_tag(
        self,
        db: Session,
        evidence_type: str,
        evidence_id: str,
        tag_id: Optional[uuid.UUID] = None,
        tag_name: Optional[str] = None,
        host_id: Optional[uuid.UUID] = None,
        user: Optional[AppUser] = None,
    ) -> EvidenceTagAssociation:
        """Attach a tag to an evidence entity item."""
        if tag_id is not None:
            tag = self.get_tag(db, tag_id)
        elif tag_name:
            norm_name = tag_name.strip()
            tag = db.execute(
                select(EvidenceTag).where(func.lower(EvidenceTag.name) == norm_name.lower())
            ).scalar_one_or_none()
            if tag is None:
                tag = self.create_tag(db, name=norm_name, user=user)
        else:
            raise ValueError("Either tag_id or tag_name must be provided.")

        clean_evidence_id = str(evidence_id).strip()
        clean_evidence_type = evidence_type.strip()

        # Check for existing association
        stmt = select(EvidenceTagAssociation).where(
            EvidenceTagAssociation.tag_id == tag.id,
            EvidenceTagAssociation.evidence_type == clean_evidence_type,
            EvidenceTagAssociation.evidence_id == clean_evidence_id,
        )
        existing = db.execute(stmt).scalar_one_or_none()
        if existing is not None:
            raise TagAssociationDuplicateError(
                f"Evidence '{clean_evidence_type}:{clean_evidence_id}' already has tag '{tag.name}'."
            )

        assoc = EvidenceTagAssociation(
            tag_id=tag.id,
            evidence_type=clean_evidence_type,
            evidence_id=clean_evidence_id,
            host_id=host_id,
            created_by_id=user.id if user else None,
            created_at=utcnow(),
        )
        db.add(assoc)
        try:
            db.flush()
            db.refresh(assoc)
        except IntegrityError as exc:
            raise TagAssociationDuplicateError(
                f"Evidence '{clean_evidence_type}:{clean_evidence_id}' already has tag '{tag.name}'."
            ) from exc
        logger.info(
            "Tag '%s' associated with %s:%s",
            tag.name,
            clean_evidence_type,
            clean_evidence_id,
        )
        return assoc

    def disassociate_tag(
        self,
        db: Session,
        tag_id: uuid.UUID,
        evidence_type: str,
        evidence_id: str,
    ) -> bool:
        """Remove a tag association from an evidence item."""
        clean_evidence_id = str(evidence_id).strip()
        clean_evidence_type = evidence_type.strip()

        stmt = select(EvidenceTagAssociation).where(
            EvidenceTagAssociation.tag_id == tag_id,
            EvidenceTagAssociation.evidence_type == clean_evidence_type,
            EvidenceTagAssociation.evidence_id == clean_evidence_id,
        )
        assoc = db.execute(stmt).scalar_one_or_none()
        if assoc is None:
            return False

        db.delete(assoc)
        db.flush()
        logger.info("Tag '%s' removed from %s:%s", tag_id, clean_evidence_type, clean_evidence_id)
        return True

    def get_tags_for_evidence(
        self,
        db: Session,
        evidence_type: str,
        evidence_id: str,
    ) -> list[EvidenceTagAssociation]:
        """Retrieve all active tag associations for an evidence item."""
        clean_evidence_id = str(evidence_id).strip()
        clean_evidence_type = evidence_type.strip()

        stmt = (
            select(EvidenceTagAssociation)
            .where(
                EvidenceTagAssociation.evidence_type == clean_evidence_type,
                EvidenceTagAssociation.evidence_id == clean_evidence_id,
            )
            .order_by(EvidenceTagAssociation.created_at.asc())
        )
        return list(db.scalars(stmt).all())

    def get_evidence_by_tag(
        self,
        db: Session,
        tag_id: uuid.UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> list[EvidenceTagAssociation]:
        """Find evidence items associated with a given tag."""
        stmt = (
            select(EvidenceTagAssociation)
            .where(EvidenceTagAssociation.tag_id == tag_id)
            .order_by(EvidenceTagAssociation.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(db.scalars(stmt).all())

    # ── Notes & Annotations ───────────────────────────────────────────────────

    def create_note(
        self,
        db: Session,
        evidence_type: str,
        evidence_id: str,
        text: str,
        host_id: Optional[uuid.UUID] = None,
        workspace_id: Optional[uuid.UUID] = None,
        user: Optional[AppUser] = None,
    ) -> EvidenceAnnotation:
        """Create an analyst note on an evidence item."""
        note = EvidenceAnnotation(
            evidence_type=evidence_type.strip(),
            evidence_id=str(evidence_id).strip(),
            host_id=host_id,
            workspace_id=workspace_id,
            author_id=user.id if user else None,
            annotation_text=text.strip(),
            created_at=utcnow(),
        )
        db.add(note)
        db.flush()
        db.refresh(note)
        logger.info("Analyst note created: id=%s on %s:%s", note.id, evidence_type, evidence_id)
        return note

    def list_notes_for_evidence(
        self,
        db: Session,
        evidence_type: str,
        evidence_id: str,
    ) -> list[EvidenceAnnotation]:
        """List all analyst notes for an evidence item in chronological order."""
        stmt = (
            select(EvidenceAnnotation)
            .where(
                EvidenceAnnotation.evidence_type == evidence_type.strip(),
                EvidenceAnnotation.evidence_id == str(evidence_id).strip(),
            )
            .order_by(EvidenceAnnotation.created_at.asc())
        )
        return list(db.scalars(stmt).all())

    def delete_note(
        self,
        db: Session,
        note_id: uuid.UUID,
        user: AppUser,
    ) -> None:
        """Delete an analyst note, verifying author or admin privileges."""
        note = db.get(EvidenceAnnotation, note_id)
        if note is None:
            raise AnnotationNotFoundError(f"Annotation note '{note_id}' not found.")

        if user.role != "admin" and note.author_id != user.id:
            raise WorkspacePermissionError("You do not have permission to delete this annotation.")

        db.delete(note)
        db.flush()
        logger.info("Annotation note deleted: id=%s user=%s", note_id, user.username)

    def update_note(
        self,
        db: Session,
        note_id: uuid.UUID,
        text: str,
        user: AppUser,
    ) -> EvidenceAnnotation:
        """Update an analyst note, verifying author or admin privileges."""
        note = db.get(EvidenceAnnotation, note_id)
        if note is None:
            raise AnnotationNotFoundError(f"Annotation note '{note_id}' not found.")

        if user.role != "admin" and note.author_id != user.id:
            raise WorkspacePermissionError("You do not have permission to modify this annotation.")

        note.annotation_text = text.strip()
        note.updated_at = utcnow()
        db.flush()
        db.refresh(note)
        logger.info("Annotation note updated: id=%s user=%s", note_id, user.username)
        return note
