from __future__ import annotations

"""Workspace model — persistent analyst investigation workspaces."""

import uuid
from datetime import datetime
from typing import Any, Optional, TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.app_user import AppUser
    from backend.db.models.host import Host
    from backend.db.models.incident import Incident
    from backend.db.models.evidence_annotation import EvidenceAnnotation

VALID_WORKSPACE_STATUSES = ("active", "archived")


class Workspace(Base):
    """An analyst investigation workspace preserving layout, graph, search, and pinned evidence."""

    __tablename__ = "workspaces"
    __table_args__ = (
        Index("ix_workspaces_owner_id", "owner_id"),
        Index("ix_workspaces_host_id", "host_id"),
        Index("ix_workspaces_incident_id", "incident_id"),
        Index("ix_workspaces_status", "status"),
        Index("ix_workspaces_created_at", "created_at"),
        CheckConstraint(
            "status IN ('active', 'archived')",
            name="chk_workspace_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    name: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    owner_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("app_users.id", ondelete="SET NULL"), nullable=True
    )
    host_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True
    )
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="active"
    )
    configuration: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
        nullable=False,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    owner: Mapped[Optional["AppUser"]] = relationship(
        foreign_keys=[owner_id]
    )
    host: Mapped[Optional["Host"]] = relationship(
        foreign_keys=[host_id]
    )
    incident: Mapped[Optional["Incident"]] = relationship(
        foreign_keys=[incident_id]
    )
    annotations: Mapped[list["EvidenceAnnotation"]] = relationship(
        back_populates="workspace",
        cascade="all, delete-orphan",
    )
