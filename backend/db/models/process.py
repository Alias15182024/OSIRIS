from __future__ import annotations

"""Process model — observed process instances on a host.

The UUID `id` is the OSIRIS internal historical process identity.
`pid` and `ppid` are Linux source-level identifiers that can be reused.
"""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.event import Event
    from backend.db.models.host import Host
    from backend.db.models.linux_user import LinuxUser


class Process(Base):
    """A process instance observed on a monitored host.

    The UUID primary key (`id`) is the stable OSIRIS identity.
    The Linux `pid` is a source-level identifier subject to reuse.
    """

    __tablename__ = "processes"
    __table_args__ = (
        Index("ix_processes_host_pid_started", "host_id", "pid", "started_at"),
        CheckConstraint("pid >= 0", name="pid_non_negative"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hosts.id"), nullable=False
    )
    pid: Mapped[int] = mapped_column(
        Integer, nullable=False
    )
    ppid: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    command: Mapped[str] = mapped_column(
        String(4096), nullable=False
    )
    executable: Mapped[Optional[str]] = mapped_column(
        String(4096), nullable=True
    )
    linux_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("linux_users.id"), nullable=True
    )
    started_at: Mapped[datetime] = mapped_column(
        nullable=False
    )
    ended_at: Mapped[Optional[datetime]] = mapped_column(
        nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )

    # Relationships
    host: Mapped["Host"] = relationship(back_populates="processes")
    linux_user: Mapped[Optional["LinuxUser"]] = relationship(
        back_populates="processes"
    )
    events: Mapped[list["Event"]] = relationship(
        back_populates="process"
    )
