from __future__ import annotations

"""IncidentEvent model — association between incidents and forensic events."""

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
    from backend.db.models.event import Event
    from backend.db.models.incident import Incident


class IncidentEvent(Base):
    """Forensic link associating an event with a security incident."""

    __tablename__ = "incident_events"
    __table_args__ = (
        Index("ix_incident_events_incident_id", "incident_id"),
        Index("ix_incident_events_event_id", "event_id"),
        UniqueConstraint(
            "incident_id", "event_id", name="uq_incident_events_incident_event"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("events.id", ondelete="CASCADE"), nullable=False
    )
    relationship_role: Mapped[str] = mapped_column(
        "relationship", String(100), nullable=False, default="related"
    )
    association_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    investigation_notes: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )

    # Relationships
    incident: Mapped["Incident"] = relationship(back_populates="events")
    event: Mapped["Event"] = relationship()
