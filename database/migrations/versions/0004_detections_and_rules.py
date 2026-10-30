"""Add detection_rules and detections tables for Phase 2 Milestone 2.4

Revision ID: 0004_detections_and_rules
Revises: 0003_snapshots_and_sessions
Create Date: 2026-10-30

Phase 2 Milestone 2.4 tables:
  - detection_rules (rule_id, name, description, category, severity, enabled, version,
                     rule_type, conditions, sequence_conditions, time_window_seconds,
                     rule_metadata, created_at, updated_at)
  - detections (rule_id, rule_version, host_id, event_id, process_id, session_id,
                timestamp, severity, title, description, category, status,
                notification_status, matched_conditions, evidence, dedup_hash,
                created_at, acknowledged_at, acknowledged_by_id)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0004_detections_and_rules"
down_revision: Union[str, None] = "0003_snapshots_and_sessions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- detection_rules ---
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("rule_type", sa.String(length=50), nullable=False, server_default="single_event"),
        sa.Column(
            "conditions",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "sequence_conditions",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("time_window_seconds", sa.Integer(), nullable=True),
        sa.Column(
            "rule_metadata",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_detection_rules")),
        sa.UniqueConstraint("rule_id", name=op.f("uq_detection_rules_rule_id")),
        sa.CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name=op.f("chk_detection_rule_severity"),
        ),
        sa.CheckConstraint(
            "rule_type IN ('single_event', 'sequence')",
            name=op.f("chk_detection_rule_type"),
        ),
    )
    op.create_index(
        "ix_detection_rules_rule_id",
        "detection_rules",
        ["rule_id"],
        unique=True,
    )
    op.create_index(
        "ix_detection_rules_category",
        "detection_rules",
        ["category"],
    )
    op.create_index(
        "ix_detection_rules_severity",
        "detection_rules",
        ["severity"],
    )
    op.create_index(
        "ix_detection_rules_enabled",
        "detection_rules",
        ["enabled"],
    )

    # --- detections ---
    op.create_table(
        "detections",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=True),
        sa.Column("process_id", sa.Uuid(), nullable=True),
        sa.Column("session_id", sa.Uuid(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="open"),
        sa.Column("notification_status", sa.String(length=50), nullable=False, server_default="pending"),
        sa.Column(
            "matched_conditions",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "evidence",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("dedup_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["detection_rules.id"],
            name=op.f("fk_detections_rule_id_detection_rules"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            name=op.f("fk_detections_host_id_hosts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["events.id"],
            name=op.f("fk_detections_event_id_events"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["process_id"],
            ["processes.id"],
            name=op.f("fk_detections_process_id_processes"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["sessions.id"],
            name=op.f("fk_detections_session_id_sessions"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["acknowledged_by_id"],
            ["app_users.id"],
            name=op.f("fk_detections_acknowledged_by_id_app_users"),
            ondelete="SET NULL",
        ),
        sa.CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name=op.f("chk_detection_severity"),
        ),
        sa.CheckConstraint(
            "status IN ('open', 'acknowledged', 'resolved', 'closed')",
            name=op.f("chk_detection_status"),
        ),
        sa.CheckConstraint(
            "notification_status IN ('pending', 'sent', 'suppressed', 'failed')",
            name=op.f("chk_detection_notification_status"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_detections")),
    )
    op.create_index(
        "ix_detections_host_ts",
        "detections",
        ["host_id", "timestamp"],
    )
    op.create_index(
        "ix_detections_rule_id",
        "detections",
        ["rule_id"],
    )
    op.create_index(
        "ix_detections_severity",
        "detections",
        ["severity"],
    )
    op.create_index(
        "ix_detections_status",
        "detections",
        ["status"],
    )
    op.create_index(
        "ix_detections_category",
        "detections",
        ["category"],
    )
    op.create_index(
        "ix_detections_dedup_hash",
        "detections",
        ["dedup_hash"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("detections")
    op.drop_table("detection_rules")
