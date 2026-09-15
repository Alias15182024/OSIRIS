from __future__ import annotations

"""Application user model — OSIRIS platform user accounts.

This table stores authentication credentials for the OSIRIS web interface.
Passwords are NEVER stored in plaintext — only hashed values.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from backend.db.models.app_audit_log import AppAuditLog


class AppUser(Base):
    """An OSIRIS application user account."""

    __tablename__ = "app_users"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    username: Mapped[str] = mapped_column(
        String(150), nullable=False, unique=True
    )
    password_hash: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    display_name: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    role: Mapped[str] = mapped_column(
        String(50), nullable=False, default="viewer"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        nullable=True
    )

    # Relationships
    audit_logs: Mapped[list["AppAuditLog"]] = relationship(
        back_populates="user"
    )
