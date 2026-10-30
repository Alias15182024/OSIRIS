"""Add FIM baselines, baseline files, and deviations tables for Phase 2 Milestone 2.5

Revision ID: 0005_fim_baselines_and_deviations
Revises: 0004_detections_and_rules
Create Date: 2026-10-30

Phase 2 Milestone 2.5 tables:
  - fim_baselines (host_id, version, status, path_scope, include_patterns,
                   exclude_patterns, total_files, total_bytes, scan_duration_ms,
                   error_message, baseline_metadata, baseline_at, completed_at, created_at)
  - fim_baseline_files (baseline_id, host_id, file_path, file_name, file_type,
                        hash_sha256, hash_sha1, hash_md5, file_size, permissions,
                        mode, owner_uid, owner_gid, owner_user, owner_group,
                        mtime, ctime, inode, device_id, symlink_target,
                        is_suid, is_sgid, is_executable, fingerprint_metadata, created_at)
  - fim_deviations (host_id, baseline_id, baseline_file_id, detection_id, file_path,
                    file_type, deviation_type, severity, is_content_modified,
                    is_metadata_modified, expected_values, observed_values, summary,
                    explanation, detected_at, created_at)
  - Alter detections table: add optional foreign key fim_deviation_id
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0005_fim_baselines_deviations"
down_revision: Union[str, None] = "0004_detections_and_rules"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- fim_baselines ---
    op.create_table(
        "fim_baselines",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="completed"),
        sa.Column(
            "path_scope",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "include_patterns",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column(
            "exclude_patterns",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("total_files", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("scan_duration_ms", sa.BigInteger(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "baseline_metadata",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("baseline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            name=op.f("fk_fim_baselines_host_id_hosts"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_fim_baselines")),
        sa.CheckConstraint(
            "status IN ('pending', 'in_progress', 'completed', 'failed', 'cancelled')",
            name=op.f("chk_fim_baseline_status"),
        ),
    )
    op.create_index(
        "ix_fim_baselines_host_id",
        "fim_baselines",
        ["host_id"],
    )
    op.create_index(
        "ix_fim_baselines_host_created",
        "fim_baselines",
        ["host_id", "created_at"],
    )
    op.create_index(
        "ix_fim_baselines_status",
        "fim_baselines",
        ["status"],
    )

    # --- fim_baseline_files ---
    op.create_table(
        "fim_baseline_files",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("baseline_id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("file_path", sa.String(length=4096), nullable=False),
        sa.Column("file_name", sa.String(length=255), nullable=True),
        sa.Column("file_type", sa.String(length=50), nullable=False, server_default="file"),
        sa.Column("hash_sha256", sa.String(length=64), nullable=True),
        sa.Column("hash_sha1", sa.String(length=40), nullable=True),
        sa.Column("hash_md5", sa.String(length=32), nullable=True),
        sa.Column("file_size", sa.BigInteger(), nullable=True),
        sa.Column("permissions", sa.String(length=20), nullable=True),
        sa.Column("mode", sa.Integer(), nullable=True),
        sa.Column("owner_uid", sa.Integer(), nullable=True),
        sa.Column("owner_gid", sa.Integer(), nullable=True),
        sa.Column("owner_user", sa.String(length=100), nullable=True),
        sa.Column("owner_group", sa.String(length=100), nullable=True),
        sa.Column("mtime", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ctime", sa.DateTime(timezone=True), nullable=True),
        sa.Column("inode", sa.BigInteger(), nullable=True),
        sa.Column("device_id", sa.BigInteger(), nullable=True),
        sa.Column("symlink_target", sa.String(length=4096), nullable=True),
        sa.Column("is_suid", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_sgid", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_executable", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "fingerprint_metadata",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["baseline_id"],
            ["fim_baselines.id"],
            name=op.f("fk_fim_baseline_files_baseline_id_fim_baselines"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            name=op.f("fk_fim_baseline_files_host_id_hosts"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_fim_baseline_files")),
        sa.UniqueConstraint("baseline_id", "file_path", name=op.f("uq_fim_baseline_files_baseline_path")),
    )
    op.create_index(
        "ix_fim_baseline_files_baseline_id",
        "fim_baseline_files",
        ["baseline_id"],
    )
    op.create_index(
        "ix_fim_baseline_files_host_path",
        "fim_baseline_files",
        ["host_id", "file_path"],
    )
    op.create_index(
        "ix_fim_baseline_files_sha256",
        "fim_baseline_files",
        ["hash_sha256"],
    )

    # --- fim_deviations ---
    op.create_table(
        "fim_deviations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("baseline_id", sa.Uuid(), nullable=False),
        sa.Column("baseline_file_id", sa.Uuid(), nullable=True),
        sa.Column("detection_id", sa.Uuid(), nullable=True),
        sa.Column("file_path", sa.String(length=4096), nullable=False),
        sa.Column("file_type", sa.String(length=50), nullable=True),
        sa.Column("deviation_type", sa.String(length=50), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="medium"),
        sa.Column("is_content_modified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_metadata_modified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "expected_values",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column(
            "observed_values",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("summary", sa.String(length=500), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            name=op.f("fk_fim_deviations_host_id_hosts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["baseline_id"],
            ["fim_baselines.id"],
            name=op.f("fk_fim_deviations_baseline_id_fim_baselines"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["baseline_file_id"],
            ["fim_baseline_files.id"],
            name=op.f("fk_fim_deviations_baseline_file_id_fim_baseline_files"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["detection_id"],
            ["detections.id"],
            name=op.f("fk_fim_deviations_detection_id_detections"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_fim_deviations")),
        sa.CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name=op.f("chk_fim_deviation_severity"),
        ),
        sa.CheckConstraint(
            "deviation_type IN ('new_file', 'deleted_file', 'modified_file', 'permission_changed', 'ownership_changed', 'metadata_changed', 'symlink_changed')",
            name=op.f("chk_fim_deviation_type"),
        ),
    )
    op.create_index(
        "ix_fim_deviations_host_id",
        "fim_deviations",
        ["host_id"],
    )
    op.create_index(
        "ix_fim_deviations_baseline_id",
        "fim_deviations",
        ["baseline_id"],
    )
    op.create_index(
        "ix_fim_deviations_host_path",
        "fim_deviations",
        ["host_id", "file_path"],
    )
    op.create_index(
        "ix_fim_deviations_type",
        "fim_deviations",
        ["deviation_type"],
    )
    op.create_index(
        "ix_fim_deviations_severity",
        "fim_deviations",
        ["severity"],
    )
    op.create_index(
        "ix_fim_deviations_detected_at",
        "fim_deviations",
        ["detected_at"],
    )
    op.create_index(
        "ix_fim_deviations_detection_id",
        "fim_deviations",
        ["detection_id"],
    )

    # --- detections table update (link to fim_deviations) ---
    with op.batch_alter_table("detections") as batch_op:
        batch_op.add_column(sa.Column("fim_deviation_id", sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            "fk_detections_fim_deviation_id_fim_deviations",
            "fim_deviations",
            ["fim_deviation_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            "ix_detections_fim_deviation_id",
            ["fim_deviation_id"],
        )


def downgrade() -> None:
    # --- drop foreign key and column from detections ---
    with op.batch_alter_table("detections") as batch_op:
        batch_op.drop_index("ix_detections_fim_deviation_id")
        batch_op.drop_constraint("fk_detections_fim_deviation_id_fim_deviations", type_="foreignkey")
        batch_op.drop_column("fim_deviation_id")

    op.drop_table("fim_deviations")
    op.drop_table("fim_baseline_files")
    op.drop_table("fim_baselines")
