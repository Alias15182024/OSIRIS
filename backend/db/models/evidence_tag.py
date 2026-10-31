from __future__ import annotations

"""EvidenceTag model — reusable tags for investigation evidence."""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.app_user import AppUser
    from backend.db.models.evidence_tag_association import EvidenceTagAssociation


class EvidenceTag(Base):
    """Reusable tag for categorization and filtering of forensic evidence."""

    __tablename__ = "evidence_tags"
    __table_args__ = (
        Index("ix_evidence_tags_name", "name"),
        Index("ix_evidence_tags_category", "category"),
        UniqueConstraint("name", name="uq_evidence_tags_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    name: Mapped[str] = mapped_column(
        String(100), nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    color: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )
    category: Mapped[str] = mapped_column(
        String(50), nullable=False, default="general"
    )
    created_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("app_users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    # Relationships
    created_by: Mapped[Optional["AppUser"]] = relationship(
        foreign_keys=[created_by_id]
    )
    associations: Mapped[list["EvidenceTagAssociation"]] = relationship(
        back_populates="tag",
        cascade="all, delete-orphan",
    )
