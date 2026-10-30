from __future__ import annotations

"""FIM Baseline model — filesystem snapshot baselines for monitored hosts."""

import uuid
from datetime import datetime
from typing import Any, Optional, TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
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
    from backend.db.models.fim_baseline_file import FimBaselineFile
    from backend.db.models.fim_deviation import FimDeviation
    from backend.db.models.host import Host

VALID_BASELINE_STATUSES = ("pending", "in_progress", "completed", "failed", "cancelled")


class FimBaseline(Base):
    """A host-scoped file integrity baseline representing trusted filesystem state."""

    __tablename__ = "fim_baselines"
    __table_args__ = (
        Index("ix_fim_baselines_host_id", "host_id"),
        Index("ix_fim_baselines_host_created", "host_id", "created_at"),
        Index("ix_fim_baselines_status", "status"),
        CheckConstraint(
            "status IN ('pending', 'in_progress', 'completed', 'failed', 'cancelled')",
            name="chk_fim_baseline_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="completed"
    )
    path_scope: Mapped[list[str]] = mapped_column(
        JSON(none_as_null=True).with_variant(
            JSONB(none_as_null=True), "postgresql"
        ),
        nullable=False,
    )
    include_patterns: Mapped[Optional[list[str]]] = mapped_column(
        JSON(none_as_null=True).with_variant(
            JSONB(none_as_null=True), "postgresql"
        ),
        nullable=True,
    )
    exclude_patterns: Mapped[Optional[list[str]]] = mapped_column(
        JSON(none_as_null=True).with_variant(
            JSONB(none_as_null=True), "postgresql"
        ),
        nullable=True,
    )
    total_files: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    total_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    scan_duration_ms: Mapped[Optional[int]] = mapped_column(
        BigInteger, nullable=True
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    baseline_metadata: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON(none_as_null=True).with_variant(
            JSONB(none_as_null=True), "postgresql"
        ),
        nullable=True,
    )
    baseline_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )

    # Relationships
    host: Mapped["Host"] = relationship(back_populates="fim_baselines")
    files: Mapped[list["FimBaselineFile"]] = relationship(
        back_populates="baseline", cascade="all, delete-orphan"
    )
    deviations: Mapped[list["FimDeviation"]] = relationship(
        back_populates="baseline", cascade="all, delete-orphan"
    )
