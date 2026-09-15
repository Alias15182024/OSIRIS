from __future__ import annotations

"""Event model — core OSIRIS event record.

This is the central Phase 1 table. Every observation collected by
OSIRIS is stored as an event after processing by the Event Processing Layer.

Identity semantics:
  - `id` (event_id):  Unique UUID assigned by the Event Processing Layer.
  - `process_id`:     OSIRIS internal historical process identity (FK → processes).
  - `pid` / `ppid`:   Source-level Linux identifiers, captured as observation
                      context. No FK — PIDs are reused and the event must
                      preserve context even if the process record disappears.
  - `uid`:            Preferred Linux user identity (source-level).
  - `username`:       Supplementary, resolved from uid by Event Processing Layer.
"""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.host import Host
    from backend.db.models.process import Process

# Valid severity levels enforced at the database level.
VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")


class Event(Base):
    """A single structured observation of system activity."""

    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_host_ts", "host_id", "timestamp"),
        Index("ix_events_event_type", "event_type"),
        Index("ix_events_source", "source"),
        Index("ix_events_severity", "severity"),
        Index("ix_events_process_id", "process_id"),
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="severity_valid",
        ),
        CheckConstraint(
            "pid IS NULL OR pid >= 0",
            name="pid_non_negative",
        ),
        CheckConstraint(
            "uid IS NULL OR uid >= 0",
            name="uid_non_negative",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hosts.id"), nullable=False
    )
    process_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("processes.id"), nullable=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        nullable=False
    )
    ingested_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )
    source: Mapped[str] = mapped_column(
        String(100), nullable=False
    )
    event_type: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    action: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default="info"
    )

    # Actor fields — source-level Linux identity
    uid: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    username: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )

    # Process context — source-level Linux identifiers (no FK)
    pid: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    ppid: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    command: Mapped[Optional[str]] = mapped_column(
        String(4096), nullable=True
    )

    # Object fields
    object_type: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    object_path: Mapped[Optional[str]] = mapped_column(
        String(4096), nullable=True
    )

    # Result fields
    success: Mapped[Optional[bool]] = mapped_column(
        Boolean, nullable=True
    )
    result: Mapped[Optional[str]] = mapped_column(
        String(1024), nullable=True
    )

    # Source-specific extensibility
    payload: Mapped[Optional[dict]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )

    # Relationships
    host: Mapped["Host"] = relationship(back_populates="events")
    process: Mapped[Optional["Process"]] = relationship(
        back_populates="events"
    )
