from __future__ import annotations

"""Detection rule model — declarative security detection rules."""

import uuid
from datetime import datetime
from typing import Any, Optional, TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, Index, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.detection import Detection

VALID_RULE_SEVERITIES = ("info", "low", "medium", "high", "critical")
VALID_RULE_TYPES = ("single_event", "sequence")


class DetectionRule(Base):
    """Declarative security detection rule definition."""

    __tablename__ = "detection_rules"
    __table_args__ = (
        Index("ix_detection_rules_rule_id", "rule_id", unique=True),
        Index("ix_detection_rules_category", "category"),
        Index("ix_detection_rules_severity", "severity"),
        Index("ix_detection_rules_enabled", "enabled"),
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="chk_detection_rule_severity",
        ),
        CheckConstraint(
            "rule_type IN ('single_event', 'sequence')",
            name="chk_detection_rule_type",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    rule_id: Mapped[str] = mapped_column(
        String(100), nullable=False, unique=True
    )
    name: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    category: Mapped[str] = mapped_column(
        String(100), nullable=False
    )
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default="medium"
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )
    rule_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default="single_event"
    )
    conditions: Mapped[dict[str, Any]] = mapped_column(
        JSON(none_as_null=True).with_variant(
            JSONB(none_as_null=True), "postgresql"
        ),
        nullable=False,
    )
    sequence_conditions: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON(none_as_null=True).with_variant(
            JSONB(none_as_null=True), "postgresql"
        ),
        nullable=True,
    )
    time_window_seconds: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    rule_metadata: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON(none_as_null=True).with_variant(
            JSONB(none_as_null=True), "postgresql"
        ),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        nullable=True
    )

    # Relationships
    detections: Mapped[list["Detection"]] = relationship(
        back_populates="rule", cascade="all, delete-orphan"
    )
