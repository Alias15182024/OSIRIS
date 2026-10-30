from __future__ import annotations

"""FIM Baseline File model — recorded file state within a baseline."""

import uuid
from datetime import datetime
from typing import Any, Optional, TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base, new_uuid, utcnow

if TYPE_CHECKING:
    from backend.db.models.fim_baseline import FimBaseline
    from backend.db.models.fim_deviation import FimDeviation
    from backend.db.models.host import Host


class FimBaselineFile(Base):
    """An individual file recorded in a file integrity baseline."""

    __tablename__ = "fim_baseline_files"
    __table_args__ = (
        Index("ix_fim_baseline_files_baseline_id", "baseline_id"),
        Index("ix_fim_baseline_files_host_path", "host_id", "file_path"),
        Index("ix_fim_baseline_files_sha256", "hash_sha256"),
        UniqueConstraint("baseline_id", "file_path", name="uq_fim_baseline_files_baseline_path"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=new_uuid
    )
    baseline_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("fim_baselines.id", ondelete="CASCADE"), nullable=False
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False
    )
    file_path: Mapped[str] = mapped_column(
        String(4096), nullable=False
    )
    file_name: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    file_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default="file"
    )
    hash_sha256: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    hash_sha1: Mapped[Optional[str]] = mapped_column(
        String(40), nullable=True
    )
    hash_md5: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    file_size: Mapped[Optional[int]] = mapped_column(
        BigInteger, nullable=True
    )
    permissions: Mapped[Optional[str]] = mapped_column(
        String(20), nullable=True
    )
    mode: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    owner_uid: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    owner_gid: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    owner_user: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    owner_group: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    mtime: Mapped[Optional[datetime]] = mapped_column(
        nullable=True
    )
    ctime: Mapped[Optional[datetime]] = mapped_column(
        nullable=True
    )
    inode: Mapped[Optional[int]] = mapped_column(
        BigInteger, nullable=True
    )
    device_id: Mapped[Optional[int]] = mapped_column(
        BigInteger, nullable=True
    )
    symlink_target: Mapped[Optional[str]] = mapped_column(
        String(4096), nullable=True
    )
    is_suid: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    is_sgid: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    is_executable: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    fingerprint_metadata: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON(none_as_null=True).with_variant(
            JSONB(none_as_null=True), "postgresql"
        ),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=utcnow
    )

    # Relationships
    baseline: Mapped["FimBaseline"] = relationship(back_populates="files")
    host: Mapped["Host"] = relationship()
    deviations: Mapped[list["FimDeviation"]] = relationship(
        back_populates="baseline_file"
    )
