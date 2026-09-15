from __future__ import annotations

"""Linux user model — operating system user accounts observed on a host."""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.host import Host
    from backend.db.models.process import Process


class LinuxUser(Base):
    """A Linux user account observed on a monitored host.

    UID is the primary Linux identity within a host.
    Username is supplementary information that may change or be unresolvable.
    """

    __tablename__ = "linux_users"
    __table_args__ = (
        UniqueConstraint("host_id", "uid", name="uq_linux_users_host_id_uid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hosts.id"), nullable=False
    )
    uid: Mapped[int] = mapped_column(
        Integer, nullable=False
    )
    username: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        nullable=False
    )
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )

    # Relationships
    host: Mapped["Host"] = relationship(back_populates="linux_users")
    processes: Mapped[list["Process"]] = relationship(
        back_populates="linux_user"
    )
