from __future__ import annotations

"""File model — observed file references on a host."""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import BigInteger, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.host import Host


class File(Base):
    """A file observed on a monitored host.

    Files are identified by path within a host. Path is NOT globally unique
    because a file can be deleted and recreated at the same path.
    """

    __tablename__ = "files"
    __table_args__ = (
        Index("ix_files_host_path", "host_id", "path"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hosts.id"), nullable=False
    )
    path: Mapped[str] = mapped_column(
        String(4096), nullable=False
    )
    inode: Mapped[Optional[int]] = mapped_column(
        BigInteger, nullable=True
    )
    file_type: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
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
    host: Mapped["Host"] = relationship(back_populates="files")
