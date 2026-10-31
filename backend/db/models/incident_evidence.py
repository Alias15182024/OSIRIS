from __future__ import annotations

"""IncidentEvidence model — unified forensic evidence linking."""

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
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.app_user import AppUser
    from backend.db.models.detection import Detection
    from backend.db.models.event import Event
    from backend.db.models.file import File
    from backend.db.models.fim_deviation import FimDeviation
    from backend.db.models.incident import Incident
    from backend.db.models.process import Process
    from backend.db.models.snapshot import Snapshot
    from backend.db.models.user_session import UserSession

VALID_EVIDENCE_TYPES = (
    "detection",
    "event",
    "fim_deviation",
    "session",
    "snapshot",
    "process",
    "file",
    "custom",
)


class IncidentEvidence(Base):
    """Forensic evidence associated with a security incident."""

    __tablename__ = "incident_evidence"
    __table_args__ = (
        Index("ix_incident_evidence_incident_id", "incident_id"),
        Index("ix_incident_evidence_type", "evidence_type"),
        Index("ix_incident_evidence_source_id", "source_id"),
        Index("ix_incident_evidence_detection_id", "detection_id"),
        Index("ix_incident_evidence_fim_dev_id", "fim_deviation_id"),
        Index("ix_incident_evidence_event_id", "event_id"),
        Index("ix_incident_evidence_session_id", "session_id"),
        Index("ix_incident_evidence_snapshot_id", "snapshot_id"),
        Index("ix_incident_evidence_process_id", "process_id"),
        Index("ix_incident_evidence_file_id", "file_id"),
        Index("ix_incident_evidence_inc_type", "incident_id", "evidence_type"),
        UniqueConstraint(
            "incident_id",
            "evidence_type",
            "source_id",
            name="uq_incident_evidence_inc_type_src",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    evidence_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )
    source_id: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    title: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    provenance: Mapped[dict[str, Any]] = mapped_column(
        JSON(none_as_null=True).with_variant(
            JSONB(none_as_null=True), "postgresql"
        ),
        nullable=False,
        default=dict,
    )
    detection_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("detections.id", ondelete="SET NULL"), nullable=True
    )
    event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("events.id", ondelete="SET NULL"), nullable=True
    )
    fim_deviation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("fim_deviations.id", ondelete="SET NULL"), nullable=True
    )
    session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True
    )
    snapshot_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("snapshots.id", ondelete="SET NULL"), nullable=True
    )
    process_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("processes.id", ondelete="SET NULL"), nullable=True
    )
    file_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("files.id", ondelete="SET NULL"), nullable=True
    )
    created_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("app_users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    # Relationships
    incident: Mapped["Incident"] = relationship(back_populates="evidence")
    detection: Mapped[Optional["Detection"]] = relationship()
    event: Mapped[Optional["Event"]] = relationship()
    fim_deviation: Mapped[Optional["FimDeviation"]] = relationship()
    session: Mapped[Optional["UserSession"]] = relationship()
    snapshot: Mapped[Optional["Snapshot"]] = relationship()
    process: Mapped[Optional["Process"]] = relationship()
    file: Mapped[Optional["File"]] = relationship()
    created_by: Mapped[Optional["AppUser"]] = relationship(
        foreign_keys=[created_by_id]
    )
