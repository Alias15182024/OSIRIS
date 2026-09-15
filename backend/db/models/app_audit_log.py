from __future__ import annotations

"""Application audit log model — log of important OSIRIS application actions.

This table records application-level actions (logins, config changes, etc.),
NOT raw Linux system events.
"""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.app_user import AppUser


class AppAuditLog(Base):
    """An audit log entry for an important OSIRIS application action."""

    __tablename__ = "app_audit_log"
    __table_args__ = (
        Index("ix_app_audit_log_user_id", "user_id"),
        Index("ix_app_audit_log_action", "action"),
        Index("ix_app_audit_log_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("app_users.id"), nullable=True
    )
    action: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    target_type: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    target_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        nullable=True
    )
    details: Mapped[Optional[dict]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )

    # Relationships
    user: Mapped[Optional["AppUser"]] = relationship(
        back_populates="audit_logs"
    )
