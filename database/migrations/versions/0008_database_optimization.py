"""Database optimization: forensic indexes, investigation views, and integrity triggers.

Revision ID: 0008_database_optimization
Revises: 0007_workspaces_and_annotations
Create Date: 2026-10-31

Phase 2 Milestone 2.8 enhancements:
  - Justified compound and foreign-key indexes across events, processes, sessions,
    detections, incidents, evidence, FIM deviations, workspaces, and annotations.
  - Multi-table investigation database views:
      * view_active_detections
      * view_incident_summary
      * view_fim_deviation_details
      * view_process_lineage
      * view_session_overview
  - Dialect-aware database triggers:
      * Automatic updated_at timestamp updates
      * Immutable audit and forensic history protection
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0008_database_optimization"
down_revision: Union[str, None] = "0007_workspaces_and_annotations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# List of indexes to create: (index_name, table_name, columns, is_unique)
_INDEXES = [
    # Events table optimizations
    ("ix_events_host_uid", "events", ["host_id", "uid"], False),
    ("ix_events_host_pid", "events", ["host_id", "pid", "timestamp"], False),
    ("ix_events_host_event_type_ts", "events", ["host_id", "event_type", "timestamp"], False),

    # Processes table optimizations
    ("ix_processes_host_started", "processes", ["host_id", "started_at"], False),
    ("ix_processes_host_user", "processes", ["host_id", "linux_user_id"], False),
    ("ix_processes_host_ended", "processes", ["host_id", "ended_at"], False),

    # Sessions table optimizations
    ("ix_sessions_host_user_started", "sessions", ["host_id", "linux_user_id", "started_at"], False),
    ("ix_sessions_host_ended", "sessions", ["host_id", "ended_at"], False),

    # Detections table optimizations
    ("ix_detections_host_status_ts", "detections", ["host_id", "status", "timestamp"], False),

    # Incidents table optimizations
    ("ix_incidents_host_created", "incidents", ["host_id", "created_at"], False),
    ("ix_incidents_host_status", "incidents", ["host_id", "status", "created_at"], False),

    # Incident evidence table optimizations
    ("ix_incident_evidence_session_id", "incident_evidence", ["session_id"], False),
    ("ix_incident_evidence_snapshot_id", "incident_evidence", ["snapshot_id"], False),
    ("ix_incident_evidence_process_id", "incident_evidence", ["process_id"], False),
    ("ix_incident_evidence_file_id", "incident_evidence", ["file_id"], False),
    ("ix_incident_evidence_inc_type", "incident_evidence", ["incident_id", "evidence_type"], False),

    # Incident history table optimizations
    ("ix_incident_history_inc_created", "incident_history", ["incident_id", "created_at"], False),
    ("ix_incident_history_user_id", "incident_history", ["user_id"], False),

    # FIM deviations table optimizations
    ("ix_fim_deviations_host_detected", "fim_deviations", ["host_id", "detected_at"], False),
    ("ix_fim_deviations_host_severity", "fim_deviations", ["host_id", "severity", "detected_at"], False),

    # Workspaces table optimizations
    ("ix_workspaces_owner_status_created", "workspaces", ["owner_id", "status", "created_at"], False),

    # Evidence annotations and tag associations
    ("ix_evidence_annotations_host_id", "evidence_annotations", ["host_id"], False),
    ("ix_evidence_tag_assoc_host_tag", "evidence_tag_associations", ["host_id", "tag_id"], False),
]

# Database Views
_VIEWS = [
    (
        "view_active_detections",
        """
        CREATE VIEW view_active_detections AS
        SELECT
            d.id AS detection_id,
            d.rule_id,
            dr.rule_id AS rule_identifier,
            dr.name AS rule_name,
            dr.category,
            d.severity,
            d.title,
            d.description,
            d.host_id,
            h.hostname,
            h.ip_address,
            d.status,
            d.timestamp,
            d.event_id,
            d.process_id,
            d.session_id,
            d.fim_deviation_id,
            d.dedup_hash,
            d.acknowledged_at,
            d.acknowledged_by_id,
            d.created_at
        FROM detections d
        JOIN detection_rules dr ON d.rule_id = dr.id
        JOIN hosts h ON d.host_id = h.id
        WHERE d.status IN ('open', 'investigating')
        """,
    ),
    (
        "view_incident_summary",
        """
        CREATE VIEW view_incident_summary AS
        SELECT
            i.id AS incident_id,
            i.title,
            i.severity,
            i.status,
            i.category,
            i.host_id,
            h.hostname,
            i.assigned_to_id,
            u.username AS assigned_to_username,
            i.created_by_id,
            i.first_observed_at,
            i.last_observed_at,
            i.contained_at,
            i.resolved_at,
            i.closed_at,
            i.created_at,
            i.updated_at,
            (SELECT COUNT(*) FROM incident_evidence ie WHERE ie.incident_id = i.id) AS evidence_count,
            (SELECT COUNT(*) FROM incident_events iev WHERE iev.incident_id = i.id) AS event_count
        FROM incidents i
        LEFT JOIN hosts h ON i.host_id = h.id
        LEFT JOIN app_users u ON i.assigned_to_id = u.id
        """,
    ),
    (
        "view_fim_deviation_details",
        """
        CREATE VIEW view_fim_deviation_details AS
        SELECT
            fd.id AS deviation_id,
            fd.host_id,
            h.hostname,
            fd.baseline_id,
            fb.version AS baseline_version,
            fd.baseline_file_id,
            fd.file_path,
            fd.file_type,
            fd.deviation_type,
            fd.severity,
            fd.is_content_modified,
            fd.is_metadata_modified,
            fd.summary,
            fd.detected_at,
            fd.detection_id,
            fd.created_at,
            bf.hash_sha256 AS expected_hash_sha256,
            bf.permissions AS expected_permissions,
            bf.file_size AS expected_file_size
        FROM fim_deviations fd
        JOIN hosts h ON fd.host_id = h.id
        JOIN fim_baselines fb ON fd.baseline_id = fb.id
        LEFT JOIN fim_baseline_files bf ON fd.baseline_file_id = bf.id
        """,
    ),
    (
        "view_process_lineage",
        """
        CREATE VIEW view_process_lineage AS
        SELECT
            p.id AS process_id,
            p.host_id,
            h.hostname,
            p.pid,
            p.ppid,
            p.command,
            p.executable,
            p.linux_user_id,
            lu.uid,
            lu.username,
            p.started_at,
            p.ended_at,
            p.created_at,
            (
                SELECT par.command FROM processes par
                WHERE par.host_id = p.host_id
                  AND par.pid = p.ppid
                  AND par.started_at <= p.started_at
                  AND (par.ended_at IS NULL OR par.ended_at >= p.started_at)
                ORDER BY par.started_at DESC
                LIMIT 1
            ) AS parent_command,
            (
                SELECT par.executable FROM processes par
                WHERE par.host_id = p.host_id
                  AND par.pid = p.ppid
                  AND par.started_at <= p.started_at
                  AND (par.ended_at IS NULL OR par.ended_at >= p.started_at)
                ORDER BY par.started_at DESC
                LIMIT 1
            ) AS parent_executable
        FROM processes p
        JOIN hosts h ON p.host_id = h.id
        LEFT JOIN linux_users lu ON p.linux_user_id = lu.id
        """,
    ),
    (
        "view_session_overview",
        """
        CREATE VIEW view_session_overview AS
        SELECT
            s.id AS session_id,
            s.host_id,
            h.hostname,
            s.linux_user_id,
            lu.uid,
            lu.username,
            s.session_type,
            s.terminal,
            s.remote_host,
            s.started_at,
            s.ended_at,
            s.created_at
        FROM sessions s
        JOIN hosts h ON s.host_id = h.id
        LEFT JOIN linux_users lu ON s.linux_user_id = lu.id
        """,
    ),
]


def upgrade() -> None:
    # 1. Create optimized indexes
    for idx_name, tbl_name, cols, is_unique in _INDEXES:
        op.create_index(idx_name, tbl_name, cols, unique=is_unique)

    # 2. Create forensic views
    for _, view_sql in _VIEWS:
        op.execute(view_sql.strip())

    # 3. Create dialect-specific database triggers
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        # Timestamp update function and triggers
        op.execute("""
        CREATE OR REPLACE FUNCTION trg_set_updated_at()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """)

        for tbl in ("hosts", "incidents", "workspaces", "detection_rules", "evidence_annotations"):
            op.execute(f"""
            CREATE TRIGGER trg_{tbl}_updated_at
            BEFORE UPDATE ON {tbl}
            FOR EACH ROW
            EXECUTE FUNCTION trg_set_updated_at();
            """)

        # Immutability function and triggers
        op.execute("""
        CREATE OR REPLACE FUNCTION trg_prevent_history_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Forensic incident history records are immutable and cannot be modified or deleted.';
        END;
        $$ LANGUAGE plpgsql;
        """)

        op.execute("""
        CREATE TRIGGER trg_incident_history_immutable
        BEFORE UPDATE OR DELETE ON incident_history
        FOR EACH ROW
        EXECUTE FUNCTION trg_prevent_history_mutation();
        """)

        op.execute("""
        CREATE OR REPLACE FUNCTION trg_prevent_audit_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Audit log records are immutable and cannot be modified or deleted.';
        END;
        $$ LANGUAGE plpgsql;
        """)

        op.execute("""
        CREATE TRIGGER trg_app_audit_log_immutable
        BEFORE UPDATE OR DELETE ON app_audit_log
        FOR EACH ROW
        EXECUTE FUNCTION trg_prevent_audit_mutation();
        """)

    elif dialect == "sqlite":
        # SQLite AFTER UPDATE triggers for timestamp updates
        for tbl in ("hosts", "incidents", "workspaces", "detection_rules", "evidence_annotations"):
            op.execute(f"""
            CREATE TRIGGER trg_{tbl}_updated_at
            AFTER UPDATE ON {tbl}
            FOR EACH ROW
            WHEN (NEW.updated_at IS OLD.updated_at OR NEW.updated_at IS NULL)
            BEGIN
                UPDATE {tbl} SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END;
            """)

        # SQLite BEFORE UPDATE & BEFORE DELETE triggers for immutability protection
        op.execute("""
        CREATE TRIGGER trg_incident_history_immutable
        BEFORE UPDATE ON incident_history
        FOR EACH ROW
        BEGIN
            SELECT RAISE(ABORT, 'Forensic incident history records are immutable and cannot be updated.');
        END;
        """)

        op.execute("""
        CREATE TRIGGER trg_incident_history_no_delete
        BEFORE DELETE ON incident_history
        FOR EACH ROW
        BEGIN
            SELECT RAISE(ABORT, 'Forensic incident history records are immutable and cannot be deleted.');
        END;
        """)

        op.execute("""
        CREATE TRIGGER trg_app_audit_log_immutable
        BEFORE UPDATE ON app_audit_log
        FOR EACH ROW
        BEGIN
            SELECT RAISE(ABORT, 'Audit log records are immutable and cannot be updated.');
        END;
        """)

        op.execute("""
        CREATE TRIGGER trg_app_audit_log_no_delete
        BEFORE DELETE ON app_audit_log
        FOR EACH ROW
        BEGIN
            SELECT RAISE(ABORT, 'Audit log records are immutable and cannot be deleted.');
        END;
        """)


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    # 1. Drop triggers and functions
    if dialect == "postgresql":
        for tbl in ("hosts", "incidents", "workspaces", "detection_rules", "evidence_annotations"):
            op.execute(f"DROP TRIGGER IF EXISTS trg_{tbl}_updated_at ON {tbl};")

        op.execute("DROP TRIGGER IF EXISTS trg_incident_history_immutable ON incident_history;")
        op.execute("DROP TRIGGER IF EXISTS trg_app_audit_log_immutable ON app_audit_log;")

        op.execute("DROP FUNCTION IF EXISTS trg_set_updated_at() CASCADE;")
        op.execute("DROP FUNCTION IF EXISTS trg_prevent_history_mutation() CASCADE;")
        op.execute("DROP FUNCTION IF EXISTS trg_prevent_audit_mutation() CASCADE;")

    elif dialect == "sqlite":
        for tbl in ("hosts", "incidents", "workspaces", "detection_rules", "evidence_annotations"):
            op.execute(f"DROP TRIGGER IF EXISTS trg_{tbl}_updated_at;")

        op.execute("DROP TRIGGER IF EXISTS trg_incident_history_immutable;")
        op.execute("DROP TRIGGER IF EXISTS trg_incident_history_no_delete;")
        op.execute("DROP TRIGGER IF EXISTS trg_app_audit_log_immutable;")
        op.execute("DROP TRIGGER IF EXISTS trg_app_audit_log_no_delete;")

    # 2. Drop forensic views
    for view_name, _ in reversed(_VIEWS):
        op.execute(f"DROP VIEW IF EXISTS {view_name};")

    # 3. Drop indexes
    for idx_name, tbl_name, _, _ in reversed(_INDEXES):
        op.drop_index(idx_name, table_name=tbl_name)
