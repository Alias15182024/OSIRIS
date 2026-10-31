from __future__ import annotations

"""EvidenceAnnotation model — analyst notes and interpretations on evidence items."""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.app_user import AppUser
    from backend.db.models.host import Host
    from backend.db.models.workspace import Workspace


class EvidenceAnnotation(Base):
    """Analyst note attached to a forensic evidence item or within a workspace."""

    __tablename__ = "evidence_annotations"
    __table_args__ = (
        Index("ix_evidence_annotations_target", "evidence_type", "evidence_id"),
        Index("ix_evidence_annotations_workspace_id", "workspace_id"),
        Index("ix_evidence_annotations_author_id", "author_id"),
        Index("ix_evidence_annotations_created_at", "created_at"),
        Index("ix_evidence_annotations_host_id", "host_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    evidence_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )
    evidence_id: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    host_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True
    )
    workspace_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=True
    )
    author_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("app_users.id", ondelete="SET NULL"), nullable=True
    )
    annotation_text: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    workspace: Mapped[Optional["Workspace"]] = relationship(
        back_populates="annotations"
    )
    author: Mapped[Optional["AppUser"]] = relationship(
        foreign_keys=[author_id]
    )
    host: Mapped[Optional["Host"]] = relationship(
        foreign_keys=[host_id]
    )
