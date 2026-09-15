from __future__ import annotations

"""Resource snapshot model — point-in-time CPU/memory/disk metrics."""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import BigInteger, CheckConstraint, Float, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.host import Host


class ResourceSnapshot(Base):
    """A point-in-time snapshot of system resource usage."""

    __tablename__ = "resource_snapshots"
    __table_args__ = (
        Index("ix_resource_snapshots_host_ts", "host_id", "timestamp"),
        CheckConstraint(
            "cpu_percent IS NULL OR cpu_percent >= 0",
            name="cpu_percent_non_negative",
        ),
        CheckConstraint(
            "memory_percent IS NULL OR memory_percent >= 0",
            name="memory_percent_non_negative",
        ),
        CheckConstraint(
            "disk_usage_percent IS NULL OR disk_usage_percent >= 0",
            name="disk_usage_percent_non_negative",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hosts.id"), nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(
        nullable=False
    )
    cpu_percent: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )
    memory_total: Mapped[Optional[int]] = mapped_column(
        BigInteger, nullable=True
    )
    memory_used: Mapped[Optional[int]] = mapped_column(
        BigInteger, nullable=True
    )
    memory_percent: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )
    disk_read_bytes: Mapped[Optional[int]] = mapped_column(
        BigInteger, nullable=True
    )
    disk_write_bytes: Mapped[Optional[int]] = mapped_column(
        BigInteger, nullable=True
    )
    disk_usage_percent: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )

    # Relationships
    host: Mapped["Host"] = relationship(back_populates="resource_snapshots")
