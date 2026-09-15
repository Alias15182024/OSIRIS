from __future__ import annotations

"""Host model — monitored system identity."""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.event import Event
    from backend.db.models.file import File
    from backend.db.models.linux_user import LinuxUser
    from backend.db.models.process import Process
    from backend.db.models.resource_snapshot import ResourceSnapshot


class Host(Base):
    """A monitored Linux host."""

    __tablename__ = "hosts"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    hostname: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    os_info: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45), nullable=True  # IPv6 max length
    )
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        nullable=True
    )

    # Relationships
    linux_users: Mapped[list["LinuxUser"]] = relationship(
        back_populates="host"
    )
    processes: Mapped[list["Process"]] = relationship(
        back_populates="host"
    )
    files: Mapped[list["File"]] = relationship(
        back_populates="host"
    )
    resource_snapshots: Mapped[list["ResourceSnapshot"]] = relationship(
        back_populates="host"
    )
    events: Mapped[list["Event"]] = relationship(
        back_populates="host"
    )
