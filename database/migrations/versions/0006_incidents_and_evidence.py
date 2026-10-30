"""Add incidents, incident_events, incident_evidence, and incident_history tables for Phase 2 Milestone 2.6

Revision ID: 0006_incidents_and_evidence
Revises: 0005_fim_baselines_deviations
Create Date: 2026-10-31

Phase 2 Milestone 2.6 tables:
  - incidents (id, title, description, severity, status, category, host_id,
               created_by_id, assigned_to_id, first_observed_at, last_observed_at,
               contained_at, containment_summary, resolved_at, resolution_summary,
               closed_at, closure_summary, created_at, updated_at)
  - incident_events (id, incident_id, event_id, relationship,
                     association_timestamp, investigation_notes)
  - incident_evidence (id, incident_id, evidence_type, source_id, title,
                      description, provenance, detection_id, event_id,
                      fim_deviation_id, session_id, snapshot_id, process_id,
                      file_id, created_by_id, created_at)
  - incident_history (id, incident_id, change_type, from_status, to_status,
                      from_severity, to_severity, user_id, notes,
                      history_metadata, created_at)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0006_incidents_and_evidence"
down_revision: Union[str, None] = "0005_fim_baselines_deviations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- incidents ---
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="medium"),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="open"),
        sa.Column("category", sa.String(length=100), nullable=False, server_default="general"),
        sa.Column("host_id", sa.Uuid(), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column("assigned_to_id", sa.Uuid(), nullable=True),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("contained_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("containment_summary", sa.Text(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution_summary", sa.Text(), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closure_summary", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="chk_incident_severity",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'investigating', 'contained', 'resolved', 'closed')",
            name="chk_incident_status",
        ),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_id"], ["app_users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["assigned_to_id"], ["app_users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_host_id", "incidents", ["host_id"])
    op.create_index("ix_incidents_category", "incidents", ["category"])
    op.create_index("ix_incidents_assigned_to_id", "incidents", ["assigned_to_id"])
    op.create_index("ix_incidents_created_at", "incidents", ["created_at"])

    # --- incident_events ---
    op.create_table(
        "incident_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("relationship", sa.String(length=100), nullable=False, server_default="related"),
        sa.Column("association_timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("investigation_notes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id", "event_id", name="uq_incident_events_incident_event"),
    )
    op.create_index("ix_incident_events_incident_id", "incident_events", ["incident_id"])
    op.create_index("ix_incident_events_event_id", "incident_events", ["event_id"])

    # --- incident_evidence ---
    op.create_table(
        "incident_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_type", sa.String(length=50), nullable=False),
        sa.Column("source_id", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "provenance",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("detection_id", sa.Uuid(), nullable=True),
        sa.Column("event_id", sa.Uuid(), nullable=True),
        sa.Column("fim_deviation_id", sa.Uuid(), nullable=True),
        sa.Column("session_id", sa.Uuid(), nullable=True),
        sa.Column("snapshot_id", sa.Uuid(), nullable=True),
        sa.Column("process_id", sa.Uuid(), nullable=True),
        sa.Column("file_id", sa.Uuid(), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["detection_id"], ["detections.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["fim_deviation_id"], ["fim_deviations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["snapshots.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["process_id"], ["processes.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["file_id"], ["files.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_id"], ["app_users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id", "evidence_type", "source_id", name="uq_incident_evidence_inc_type_src"),
    )
    op.create_index("ix_incident_evidence_incident_id", "incident_evidence", ["incident_id"])
    op.create_index("ix_incident_evidence_type", "incident_evidence", ["evidence_type"])
    op.create_index("ix_incident_evidence_source_id", "incident_evidence", ["source_id"])
    op.create_index("ix_incident_evidence_detection_id", "incident_evidence", ["detection_id"])
    op.create_index("ix_incident_evidence_fim_dev_id", "incident_evidence", ["fim_deviation_id"])
    op.create_index("ix_incident_evidence_event_id", "incident_evidence", ["event_id"])

    # --- incident_history ---
    op.create_table(
        "incident_history",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("change_type", sa.String(length=50), nullable=False),
        sa.Column("from_status", sa.String(length=50), nullable=True),
        sa.Column("to_status", sa.String(length=50), nullable=True),
        sa.Column("from_severity", sa.String(length=20), nullable=True),
        sa.Column("to_severity", sa.String(length=20), nullable=True),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "history_metadata",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["app_users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_incident_history_incident_id", "incident_history", ["incident_id"])
    op.create_index("ix_incident_history_change_type", "incident_history", ["change_type"])
    op.create_index("ix_incident_history_created_at", "incident_history", ["created_at"])


def downgrade() -> None:
    # Drop in reverse dependency order
    op.drop_index("ix_incident_history_created_at", table_name="incident_history")
    op.drop_index("ix_incident_history_change_type", table_name="incident_history")
    op.drop_index("ix_incident_history_incident_id", table_name="incident_history")
    op.drop_table("incident_history")

    op.drop_index("ix_incident_evidence_event_id", table_name="incident_evidence")
    op.drop_index("ix_incident_evidence_fim_dev_id", table_name="incident_evidence")
    op.drop_index("ix_incident_evidence_detection_id", table_name="incident_evidence")
    op.drop_index("ix_incident_evidence_source_id", table_name="incident_evidence")
    op.drop_index("ix_incident_evidence_type", table_name="incident_evidence")
    op.drop_index("ix_incident_evidence_incident_id", table_name="incident_evidence")
    op.drop_table("incident_evidence")

    op.drop_index("ix_incident_events_event_id", table_name="incident_events")
    op.drop_index("ix_incident_events_incident_id", table_name="incident_events")
    op.drop_table("incident_events")

    op.drop_index("ix_incidents_created_at", table_name="incidents")
    op.drop_index("ix_incidents_assigned_to_id", table_name="incidents")
    op.drop_index("ix_incidents_category", table_name="incidents")
    op.drop_index("ix_incidents_host_id", table_name="incidents")
    op.drop_index("ix_incidents_severity", table_name="incidents")
    op.drop_index("ix_incidents_status", table_name="incidents")
    op.drop_table("incidents")
