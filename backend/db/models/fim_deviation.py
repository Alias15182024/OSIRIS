from __future__ import annotations

"""FIM Deviation model — detected integrity deviations against baselines."""

import uuid
from datetime import datetime
from typing import Any, Optional, TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    CheckConstraint,
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
    from backend.db.models.detection import Detection
    from backend.db.models.fim_baseline import FimBaseline
    from backend.db.models.fim_baseline_file import FimBaselineFile
    from backend.db.models.host import Host

VALID_DEVIATION_TYPES = (
    "new_file",
    "deleted_file",
    "modified_file",
    "permission_changed",
    "ownership_changed",
    "metadata_changed",
    "symlink_changed",
)

VALID_DEVIATION_SEVERITIES = ("info", "low", "medium", "high", "critical")


class FimDeviation(Base):
    """An observed filesystem integrity deviation compared to a trusted baseline."""

    __tablename__ = "fim_deviations"
    __table_args__ = (
        Index("ix_fim_deviations_host_id", "host_id"),
        Index("ix_fim_deviations_baseline_id", "baseline_id"),
        Index("ix_fim_deviations_host_path", "host_id", "file_path"),
        Index("ix_fim_deviations_type", "deviation_type"),
        Index("ix_fim_deviations_severity", "severity"),
        Index("ix_fim_deviations_detected_at", "detected_at"),
        Index("ix_fim_deviations_detection_id", "detection_id"),
        Index("ix_fim_deviations_host_detected", "host_id", "detected_at"),
        Index("ix_fim_deviations_host_severity", "host_id", "severity", "detected_at"),
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="chk_fim_deviation_severity",
        ),
        CheckConstraint(
            "deviation_type IN ('new_file', 'deleted_file', 'modified_file', 'permission_changed', 'ownership_changed', 'metadata_changed', 'symlink_changed')",
            name="chk_fim_deviation_type",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False
    )
    baseline_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("fim_baselines.id", ondelete="CASCADE"), nullable=False
    )
    baseline_file_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("fim_baseline_files.id", ondelete="SET NULL"), nullable=True
    )
    detection_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("detections.id", ondelete="SET NULL", use_alter=True), nullable=True
    )
    file_path: Mapped[str] = mapped_column(
        String(4096), nullable=False
    )
    file_type: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )
    deviation_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default="medium"
    )
    is_content_modified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    is_metadata_modified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    expected_values: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON(none_as_null=True).with_variant(
            JSONB(none_as_null=True), "postgresql"
        ),
        nullable=True,
    )
    observed_values: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON(none_as_null=True).with_variant(
            JSONB(none_as_null=True), "postgresql"
        ),
        nullable=True,
    )
    summary: Mapped[Optional[str]] = mapped_column(
        String(500), nullable=True
    )
    explanation: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    detected_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )

    # Relationships
    host: Mapped["Host"] = relationship(back_populates="fim_deviations")
    baseline: Mapped["FimBaseline"] = relationship(back_populates="deviations")
    baseline_file: Mapped[Optional["FimBaselineFile"]] = relationship(back_populates="deviations")
    detection: Mapped[Optional["Detection"]] = relationship(
        foreign_keys=[detection_id]
    )
    detections: Mapped[list["Detection"]] = relationship(
        back_populates="fim_deviation",
        foreign_keys="[Detection.fim_deviation_id]"
    )
