from __future__ import annotations

"""EvidenceTagAssociation model — mapping tags to polymorphic evidence items."""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.app_user import AppUser
    from backend.db.models.evidence_tag import EvidenceTag
    from backend.db.models.host import Host


class EvidenceTagAssociation(Base):
    """Associates an evidence tag with a specific forensic evidence item."""

    __tablename__ = "evidence_tag_associations"
    __table_args__ = (
        Index("ix_evidence_tag_assoc_tag_id", "tag_id"),
        Index("ix_evidence_tag_assoc_target", "evidence_type", "evidence_id"),
        Index("ix_evidence_tag_assoc_host_id", "host_id"),
        Index("ix_evidence_tag_assoc_host_tag", "host_id", "tag_id"),
        UniqueConstraint(
            "tag_id", "evidence_type", "evidence_id",
            name="uq_evidence_tag_assoc",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    tag_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence_tags.id", ondelete="CASCADE"), nullable=False
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
    created_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("app_users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    # Relationships
    tag: Mapped["EvidenceTag"] = relationship(
        back_populates="associations"
    )
    host: Mapped[Optional["Host"]] = relationship(
        foreign_keys=[host_id]
    )
    created_by: Mapped[Optional["AppUser"]] = relationship(
        foreign_keys=[created_by_id]
    )
