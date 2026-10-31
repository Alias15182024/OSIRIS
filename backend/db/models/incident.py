from __future__ import annotations

"""Incident model — security incident lifecycle and investigation record."""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
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
    from backend.db.models.incident_event import IncidentEvent
    from backend.db.models.incident_evidence import IncidentEvidence
    from backend.db.models.incident_history import IncidentHistory

VALID_INCIDENT_SEVERITIES = ("info", "low", "medium", "high", "critical")
VALID_INCIDENT_STATUSES = ("open", "investigating", "contained", "resolved", "closed")


class Incident(Base):
    """A security incident grouping correlated alerts, events, and evidence."""

    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_severity", "severity"),
        Index("ix_incidents_host_id", "host_id"),
        Index("ix_incidents_category", "category"),
        Index("ix_incidents_assigned_to_id", "assigned_to_id"),
        Index("ix_incidents_created_at", "created_at"),
        Index("ix_incidents_host_created", "host_id", "created_at"),
        Index("ix_incidents_host_status", "host_id", "status", "created_at"),
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="chk_incident_severity",
        ),
        CheckConstraint(
            "status IN ('open', 'investigating', 'contained', 'resolved', 'closed')",
            name="chk_incident_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    title: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default="medium"
    )
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="open"
    )
    category: Mapped[str] = mapped_column(
        String(100), nullable=False, default="general"
    )
    host_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True
    )
    created_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("app_users.id", ondelete="SET NULL"), nullable=True
    )
    assigned_to_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("app_users.id", ondelete="SET NULL"), nullable=True
    )
    first_observed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_observed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    contained_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    containment_summary: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolution_summary: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    closed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    closure_summary: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    host: Mapped[Optional["Host"]] = relationship(back_populates="incidents")
    created_by: Mapped[Optional["AppUser"]] = relationship(
        foreign_keys=[created_by_id]
    )
    assigned_to: Mapped[Optional["AppUser"]] = relationship(
        foreign_keys=[assigned_to_id]
    )
    events: Mapped[list["IncidentEvent"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentEvent.association_timestamp.asc()",
    )
    evidence: Mapped[list["IncidentEvidence"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentEvidence.created_at.asc()",
    )
    history: Mapped[list["IncidentHistory"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentHistory.created_at.desc()",
    )
