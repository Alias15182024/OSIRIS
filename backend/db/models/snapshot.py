from __future__ import annotations

"""Snapshot model — point-in-time system-state snapshots."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Index, JSON, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.host import Host


class Snapshot(Base):
    """A point-in-time snapshot of system state."""

    __tablename__ = "snapshots"
    __table_args__ = (
        Index("ix_snapshots_host_ts", "host_id", "timestamp"),
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
    snapshot_type: Mapped[str] = mapped_column(
        String(100), nullable=False
    )
    data: Mapped[dict] = mapped_column(
        JSON(none_as_null=True).with_variant(
            JSONB(none_as_null=True), "postgresql"
        ),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )

    # Relationships
    host: Mapped["Host"] = relationship(back_populates="snapshots")
