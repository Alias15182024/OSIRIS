from __future__ import annotations

"""IncidentHistory model — audit log of incident lifecycle and changes."""

import uuid
from datetime import datetime
from typing import Any, Optional, TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    JSON,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.app_user import AppUser
    from backend.db.models.incident import Incident

VALID_CHANGE_TYPES = (
    "incident_created",
    "incident_updated",
    "status_change",
    "severity_change",
    "assignment",
    "note_added",
    "evidence_added",
    "event_linked",
)


class IncidentHistory(Base):
    """Auditable historical change record for an incident."""

    __tablename__ = "incident_history"
    __table_args__ = (
        Index("ix_incident_history_incident_id", "incident_id"),
        Index("ix_incident_history_change_type", "change_type"),
        Index("ix_incident_history_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    change_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )
    from_status: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )
    to_status: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )
    from_severity: Mapped[Optional[str]] = mapped_column(
        String(20), nullable=True
    )
    to_severity: Mapped[Optional[str]] = mapped_column(
        String(20), nullable=True
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("app_users.id", ondelete="SET NULL"), nullable=True
    )
    notes: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    history_metadata: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON(none_as_null=True).with_variant(
            JSONB(none_as_null=True), "postgresql"
        ),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    # Relationships
    incident: Mapped["Incident"] = relationship(back_populates="history")
    user: Mapped[Optional["AppUser"]] = relationship()
