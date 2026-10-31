"""Add workspaces, evidence_tags, evidence_tag_associations, and evidence_annotations tables for Phase 2 Milestone 2.7

Revision ID: 0007_workspaces_and_annotations
Revises: 0006_incidents_and_evidence
Create Date: 2026-10-31

Phase 2 Milestone 2.7 tables:
  - workspaces (id, name, description, owner_id, host_id, incident_id,
                status, configuration, created_at, updated_at)
  - evidence_tags (id, name, description, color, category,
                   created_by_id, created_at)
  - evidence_tag_associations (id, tag_id, evidence_type, evidence_id,
                               host_id, created_by_id, created_at)
  - evidence_annotations (id, evidence_type, evidence_id, host_id,
                          workspace_id, author_id, annotation_text,
                          created_at, updated_at)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0007_workspaces_and_annotations"
down_revision: Union[str, None] = "0006_incidents_and_evidence"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- workspaces ---
    op.create_table(
        "workspaces",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("owner_id", sa.Uuid(), nullable=True),
        sa.Column("host_id", sa.Uuid(), nullable=True),
        sa.Column("incident_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="active"),
        sa.Column(
            "configuration",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('active', 'archived')",
            name="chk_workspace_status",
        ),
        sa.ForeignKeyConstraint(["owner_id"], ["app_users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_workspaces_owner_id", "workspaces", ["owner_id"])
    op.create_index("ix_workspaces_host_id", "workspaces", ["host_id"])
    op.create_index("ix_workspaces_incident_id", "workspaces", ["incident_id"])
    op.create_index("ix_workspaces_status", "workspaces", ["status"])
    op.create_index("ix_workspaces_created_at", "workspaces", ["created_at"])

    # --- evidence_tags ---
    op.create_table(
        "evidence_tags",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("color", sa.String(length=50), nullable=True),
        sa.Column("category", sa.String(length=50), nullable=False, server_default="general"),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(["created_by_id"], ["app_users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_evidence_tags_name"),
    )
    op.create_index("ix_evidence_tags_name", "evidence_tags", ["name"])
    op.create_index("ix_evidence_tags_category", "evidence_tags", ["category"])

    # --- evidence_tag_associations ---
    op.create_table(
        "evidence_tag_associations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tag_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_type", sa.String(length=50), nullable=False),
        sa.Column("evidence_id", sa.String(length=255), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(["tag_id"], ["evidence_tags.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_id"], ["app_users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tag_id", "evidence_type", "evidence_id", name="uq_evidence_tag_assoc"),
    )
    op.create_index("ix_evidence_tag_assoc_tag_id", "evidence_tag_associations", ["tag_id"])
    op.create_index(
        "ix_evidence_tag_assoc_target",
        "evidence_tag_associations",
        ["evidence_type", "evidence_id"],
    )
    op.create_index("ix_evidence_tag_assoc_host_id", "evidence_tag_associations", ["host_id"])

    # --- evidence_annotations ---
    op.create_table(
        "evidence_annotations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("evidence_type", sa.String(length=50), nullable=False),
        sa.Column("evidence_id", sa.String(length=255), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=True),
        sa.Column("workspace_id", sa.Uuid(), nullable=True),
        sa.Column("author_id", sa.Uuid(), nullable=True),
        sa.Column("annotation_text", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["author_id"], ["app_users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_evidence_annotations_target",
        "evidence_annotations",
        ["evidence_type", "evidence_id"],
    )
    op.create_index("ix_evidence_annotations_workspace_id", "evidence_annotations", ["workspace_id"])
    op.create_index("ix_evidence_annotations_author_id", "evidence_annotations", ["author_id"])
    op.create_index("ix_evidence_annotations_created_at", "evidence_annotations", ["created_at"])


def downgrade() -> None:
    # Drop in reverse dependency order
    op.drop_index("ix_evidence_annotations_created_at", table_name="evidence_annotations")
    op.drop_index("ix_evidence_annotations_author_id", table_name="evidence_annotations")
    op.drop_index("ix_evidence_annotations_workspace_id", table_name="evidence_annotations")
    op.drop_index("ix_evidence_annotations_target", table_name="evidence_annotations")
    op.drop_table("evidence_annotations")

    op.drop_index("ix_evidence_tag_assoc_host_id", table_name="evidence_tag_associations")
    op.drop_index("ix_evidence_tag_assoc_target", table_name="evidence_tag_associations")
    op.drop_index("ix_evidence_tag_assoc_tag_id", table_name="evidence_tag_associations")
    op.drop_table("evidence_tag_associations")

    op.drop_index("ix_evidence_tags_category", table_name="evidence_tags")
    op.drop_index("ix_evidence_tags_name", table_name="evidence_tags")
    op.drop_table("evidence_tags")

    op.drop_index("ix_workspaces_created_at", table_name="workspaces")
    op.drop_index("ix_workspaces_status", table_name="workspaces")
    op.drop_index("ix_workspaces_incident_id", table_name="workspaces")
    op.drop_index("ix_workspaces_host_id", table_name="workspaces")
    op.drop_index("ix_workspaces_owner_id", table_name="workspaces")
    op.drop_table("workspaces")
