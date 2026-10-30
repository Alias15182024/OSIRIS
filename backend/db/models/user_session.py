from __future__ import annotations

"""User session model — user login sessions observed on a host."""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.host import Host
    from backend.db.models.linux_user import LinuxUser


class UserSession(Base):
    """A user login session observed on a monitored host."""

    __tablename__ = "sessions"
    __table_args__ = (
        Index("ix_sessions_host_started", "host_id", "started_at"),
        Index("ix_sessions_linux_user_id", "linux_user_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hosts.id"), nullable=False
    )
    linux_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("linux_users.id"), nullable=True
    )
    session_type: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )
    terminal: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    remote_host: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
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
    host: Mapped["Host"] = relationship(back_populates="sessions")
    linux_user: Mapped[Optional["LinuxUser"]] = relationship(
        back_populates="sessions"
    )
