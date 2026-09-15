"""Phase 1 schema — initial tables

Revision ID: 0001_phase1_schema
Revises:
Create Date: 2026-09-08

Creates all Phase 1 tables:
  - hosts
  - linux_users
  - processes
  - files
  - resource_snapshots
  - events
  - app_users
  - app_audit_log
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001_phase1_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- hosts ---
    op.create_table(
        "hosts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("os_info", sa.String(length=512), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_hosts")),
    )

    # --- linux_users ---
    op.create_table(
        "linux_users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("uid", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            name=op.f("fk_linux_users_host_id_hosts"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_linux_users")),
        sa.UniqueConstraint("host_id", "uid", name="uq_linux_users_host_id_uid"),
    )

    # --- app_users ---
    op.create_table(
        "app_users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=150), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("role", sa.String(length=50), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_app_users")),
        sa.UniqueConstraint("username", name=op.f("uq_app_users_username")),
    )

    # --- processes ---
    op.create_table(
        "processes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("ppid", sa.Integer(), nullable=True),
        sa.Column("command", sa.String(length=4096), nullable=False),
        sa.Column("executable", sa.String(length=4096), nullable=True),
        sa.Column("linux_user_id", sa.Uuid(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("pid >= 0", name=op.f("ck_processes_pid_non_negative")),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            name=op.f("fk_processes_host_id_hosts"),
        ),
        sa.ForeignKeyConstraint(
            ["linux_user_id"],
            ["linux_users.id"],
            name=op.f("fk_processes_linux_user_id_linux_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_processes")),
    )
    op.create_index(
        "ix_processes_host_pid_started",
        "processes",
        ["host_id", "pid", "started_at"],
    )

    # --- files ---
    op.create_table(
        "files",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("path", sa.String(length=4096), nullable=False),
        sa.Column("inode", sa.BigInteger(), nullable=True),
        sa.Column("file_type", sa.String(length=50), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            name=op.f("fk_files_host_id_hosts"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_files")),
    )
    op.create_index(
        "ix_files_host_path",
        "files",
        ["host_id", "path"],
    )

    # --- resource_snapshots ---
    op.create_table(
        "resource_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cpu_percent", sa.Float(), nullable=True),
        sa.Column("memory_total", sa.BigInteger(), nullable=True),
        sa.Column("memory_used", sa.BigInteger(), nullable=True),
        sa.Column("memory_percent", sa.Float(), nullable=True),
        sa.Column("disk_read_bytes", sa.BigInteger(), nullable=True),
        sa.Column("disk_write_bytes", sa.BigInteger(), nullable=True),
        sa.Column("disk_usage_percent", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "cpu_percent IS NULL OR cpu_percent >= 0",
            name=op.f("ck_resource_snapshots_cpu_percent_non_negative"),
        ),
        sa.CheckConstraint(
            "memory_percent IS NULL OR memory_percent >= 0",
            name=op.f("ck_resource_snapshots_memory_percent_non_negative"),
        ),
        sa.CheckConstraint(
            "disk_usage_percent IS NULL OR disk_usage_percent >= 0",
            name=op.f("ck_resource_snapshots_disk_usage_percent_non_negative"),
        ),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            name=op.f("fk_resource_snapshots_host_id_hosts"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_resource_snapshots")),
    )
    op.create_index(
        "ix_resource_snapshots_host_ts",
        "resource_snapshots",
        ["host_id", "timestamp"],
    )

    # --- events ---
    op.create_table(
        "events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("process_id", sa.Uuid(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("event_type", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("uid", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("ppid", sa.Integer(), nullable=True),
        sa.Column("command", sa.String(length=4096), nullable=True),
        sa.Column("object_type", sa.String(length=100), nullable=True),
        sa.Column("object_path", sa.String(length=4096), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=True),
        sa.Column("result", sa.String(length=1024), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name=op.f("ck_events_severity_valid"),
        ),
        sa.CheckConstraint(
            "pid IS NULL OR pid >= 0",
            name=op.f("ck_events_pid_non_negative"),
        ),
        sa.CheckConstraint(
            "uid IS NULL OR uid >= 0",
            name=op.f("ck_events_uid_non_negative"),
        ),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            name=op.f("fk_events_host_id_hosts"),
        ),
        sa.ForeignKeyConstraint(
            ["process_id"],
            ["processes.id"],
            name=op.f("fk_events_process_id_processes"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_events")),
    )
    op.create_index("ix_events_host_ts", "events", ["host_id", "timestamp"])
    op.create_index("ix_events_event_type", "events", ["event_type"])
    op.create_index("ix_events_source", "events", ["source"])
    op.create_index("ix_events_severity", "events", ["severity"])
    op.create_index("ix_events_process_id", "events", ["process_id"])

    # --- app_audit_log ---
    op.create_table(
        "app_audit_log",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("target_type", sa.String(length=100), nullable=True),
        sa.Column("target_id", sa.Uuid(), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["app_users.id"],
            name=op.f("fk_app_audit_log_user_id_app_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_app_audit_log")),
    )
    op.create_index("ix_app_audit_log_user_id", "app_audit_log", ["user_id"])
    op.create_index("ix_app_audit_log_action", "app_audit_log", ["action"])
    op.create_index("ix_app_audit_log_created_at", "app_audit_log", ["created_at"])


def downgrade() -> None:
    op.drop_table("app_audit_log")
    op.drop_table("events")
    op.drop_table("resource_snapshots")
    op.drop_table("files")
    op.drop_table("processes")
    op.drop_table("app_users")
    op.drop_table("linux_users")
    op.drop_table("hosts")
