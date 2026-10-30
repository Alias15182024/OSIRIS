from __future__ import annotations

"""Detection model — persistent security alerts generated from rule evaluations."""

import uuid
from datetime import datetime
from typing import Any, Optional, TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.app_user import AppUser
    from backend.db.models.detection_rule import DetectionRule
    from backend.db.models.event import Event
    from backend.db.models.fim_deviation import FimDeviation
    from backend.db.models.host import Host
    from backend.db.models.process import Process
    from backend.db.models.user_session import UserSession

VALID_DETECTION_SEVERITIES = ("info", "low", "medium", "high", "critical")
VALID_DETECTION_STATUSES = ("open", "acknowledged", "resolved", "closed")
VALID_NOTIFICATION_STATUSES = ("pending", "sent", "suppressed", "failed")


class Detection(Base):
    """A security detection/alert generated when observation matches a detection rule."""

    __tablename__ = "detections"
    __table_args__ = (
        Index("ix_detections_host_ts", "host_id", "timestamp"),
        Index("ix_detections_rule_id", "rule_id"),
        Index("ix_detections_severity", "severity"),
        Index("ix_detections_status", "status"),
        Index("ix_detections_category", "category"),
        Index("ix_detections_dedup_hash", "dedup_hash", unique=True),
        Index("ix_detections_fim_deviation_id", "fim_deviation_id"),
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="chk_detection_severity",
        ),
        CheckConstraint(
            "status IN ('open', 'acknowledged', 'resolved', 'closed')",
            name="chk_detection_status",
        ),
        CheckConstraint(
            "notification_status IN ('pending', 'sent', 'suppressed', 'failed')",
            name="chk_detection_notification_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False
    )
    rule_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("events.id", ondelete="SET NULL"), nullable=True
    )
    process_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("processes.id", ondelete="SET NULL"), nullable=True
    )
    session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True
    )
    fim_deviation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("fim_deviations.id", ondelete="SET NULL", use_alter=True), nullable=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        nullable=False
    )
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default="medium"
    )
    title: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    category: Mapped[str] = mapped_column(
        String(100), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="open"
    )
    notification_status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="pending"
    )
    matched_conditions: Mapped[dict[str, Any]] = mapped_column(
        JSON(none_as_null=True).with_variant(
            JSONB(none_as_null=True), "postgresql"
        ),
        nullable=False,
    )
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSON(none_as_null=True).with_variant(
            JSONB(none_as_null=True), "postgresql"
        ),
        nullable=False,
    )
    dedup_hash: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, unique=True
    )
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        nullable=True
    )
    acknowledged_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("app_users.id", ondelete="SET NULL"), nullable=True
    )

    # Relationships
    rule: Mapped["DetectionRule"] = relationship(back_populates="detections")
    host: Mapped["Host"] = relationship(back_populates="detections")
    event: Mapped[Optional["Event"]] = relationship()
    process: Mapped[Optional["Process"]] = relationship()
    session: Mapped[Optional["UserSession"]] = relationship()
    fim_deviation: Mapped[Optional["FimDeviation"]] = relationship(
        back_populates="detections",
        foreign_keys=[fim_deviation_id]
    )
    acknowledged_by: Mapped[Optional["AppUser"]] = relationship()
