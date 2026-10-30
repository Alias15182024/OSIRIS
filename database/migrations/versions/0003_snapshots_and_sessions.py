"""Add snapshots and sessions tables for Phase 2 Milestone 2.1

Revision ID: 0003_snapshots_and_sessions
Revises: 0002_normalize_file_types
Create Date: 2026-10-30

Phase 2 Milestone 2.1 tables:
  - snapshots (host_id, timestamp, snapshot_type, data JSON/JSONB, created_at)
  - sessions (host_id, linux_user_id, session_type, terminal, remote_host, started_at, ended_at, created_at)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0003_snapshots_and_sessions"
down_revision: Union[str, None] = "0002_normalize_file_types"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- snapshots ---
    op.create_table(
        "snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("snapshot_type", sa.String(length=100), nullable=False),
        sa.Column(
            "data",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            name=op.f("fk_snapshots_host_id_hosts"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_snapshots")),
    )
    op.create_index(
        "ix_snapshots_host_ts",
        "snapshots",
        ["host_id", "timestamp"],
    )

    # --- sessions ---
    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("linux_user_id", sa.Uuid(), nullable=True),
        sa.Column("session_type", sa.String(length=50), nullable=True),
        sa.Column("terminal", sa.String(length=255), nullable=True),
        sa.Column("remote_host", sa.String(length=255), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            name=op.f("fk_sessions_host_id_hosts"),
        ),
        sa.ForeignKeyConstraint(
            ["linux_user_id"],
            ["linux_users.id"],
            name=op.f("fk_sessions_linux_user_id_linux_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sessions")),
    )
    op.create_index(
        "ix_sessions_host_started",
        "sessions",
        ["host_id", "started_at"],
    )
    op.create_index(
        "ix_sessions_linux_user_id",
        "sessions",
        ["linux_user_id"],
    )


def downgrade() -> None:
    op.drop_table("sessions")
    op.drop_table("snapshots")
