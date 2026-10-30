from __future__ import annotations

"""Isolated migration tests for Alembic schema and data migrations.

Tests verify migration 0002_normalize_file_types:
  - Upgrades from 0001_phase1_schema to 0002_normalize_file_types.
  - Normalizes legacy 'regular' and 'regular_file' values to 'file'.
  - Preserves 'directory', 'symlink', and any other custom/NULL/empty values.
  - Verifies downgrade behavior (safe no-op that avoids data corruption).
  - Verifies migration works cleanly on empty tables.
  - Verifies new records created as 'file' after migration are preserved upon downgrade.
  - Runs strictly against isolated/disposable databases (never against osiris_dev).
"""

import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles

from backend.config import settings

# Register SQLite compiler for JSONB so 0001_phase1_schema runs on SQLite
@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):  # type: ignore[no-untyped-def]
    return "JSON"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


_hosts_table = sa.table(
    "hosts",
    sa.column("id", sa.Uuid),
    sa.column("hostname", sa.String),
    sa.column("created_at", sa.DateTime(timezone=True)),
)

_files_table = sa.table(
    "files",
    sa.column("id", sa.Uuid),
    sa.column("host_id", sa.Uuid),
    sa.column("path", sa.String),
    sa.column("file_type", sa.String),
    sa.column("first_seen_at", sa.DateTime(timezone=True)),
    sa.column("created_at", sa.DateTime(timezone=True)),
)

_linux_users_table = sa.table(
    "linux_users",
    sa.column("id", sa.Uuid),
    sa.column("host_id", sa.Uuid),
    sa.column("uid", sa.Integer),
    sa.column("username", sa.String),
    sa.column("first_seen_at", sa.DateTime(timezone=True)),
    sa.column("created_at", sa.DateTime(timezone=True)),
)

_snapshots_table = sa.table(
    "snapshots",
    sa.column("id", sa.Uuid),
    sa.column("host_id", sa.Uuid),
    sa.column("timestamp", sa.DateTime(timezone=True)),
    sa.column("snapshot_type", sa.String),
    sa.column("data", sa.JSON),
    sa.column("created_at", sa.DateTime(timezone=True)),
)

_sessions_table = sa.table(
    "sessions",
    sa.column("id", sa.Uuid),
    sa.column("host_id", sa.Uuid),
    sa.column("linux_user_id", sa.Uuid),
    sa.column("session_type", sa.String),
    sa.column("terminal", sa.String),
    sa.column("remote_host", sa.String),
    sa.column("started_at", sa.DateTime(timezone=True)),
    sa.column("ended_at", sa.DateTime(timezone=True)),
    sa.column("created_at", sa.DateTime(timezone=True)),
)

_detection_rules_table = sa.table(
    "detection_rules",
    sa.column("id", sa.Uuid),
    sa.column("rule_id", sa.String),
    sa.column("name", sa.String),
    sa.column("description", sa.String),
    sa.column("category", sa.String),
    sa.column("severity", sa.String),
    sa.column("enabled", sa.Boolean),
    sa.column("version", sa.Integer),
    sa.column("rule_type", sa.String),
    sa.column("conditions", sa.JSON),
    sa.column("sequence_conditions", sa.JSON),
    sa.column("time_window_seconds", sa.Integer),
    sa.column("rule_metadata", sa.JSON),
    sa.column("created_at", sa.DateTime(timezone=True)),
    sa.column("updated_at", sa.DateTime(timezone=True)),
)

_detections_table = sa.table(
    "detections",
    sa.column("id", sa.Uuid),
    sa.column("rule_id", sa.Uuid),
    sa.column("rule_version", sa.Integer),
    sa.column("host_id", sa.Uuid),
    sa.column("event_id", sa.Uuid),
    sa.column("process_id", sa.Uuid),
    sa.column("session_id", sa.Uuid),
    sa.column("timestamp", sa.DateTime(timezone=True)),
    sa.column("severity", sa.String),
    sa.column("title", sa.String),
    sa.column("description", sa.String),
    sa.column("category", sa.String),
    sa.column("status", sa.String),
    sa.column("notification_status", sa.String),
    sa.column("matched_conditions", sa.JSON),
    sa.column("evidence", sa.JSON),
    sa.column("dedup_hash", sa.String),
    sa.column("created_at", sa.DateTime(timezone=True)),
    sa.column("acknowledged_at", sa.DateTime(timezone=True)),
    sa.column("acknowledged_by_id", sa.Uuid),
)


def _populate_test_files(engine: sa.Engine, host_id: uuid.UUID) -> dict[str, uuid.UUID]:
    """Insert test records with legacy, canonical, and edge-case file_types."""
    records = {
        "reg": (uuid.uuid4(), "/test/legacy_regular", "regular"),
        "reg_alt": (uuid.uuid4(), "/test/legacy_regular_file", "regular_file"),
        "canon_file": (uuid.uuid4(), "/test/canonical_file", "file"),
        "canon_dir": (uuid.uuid4(), "/test/canonical_dir", "directory"),
        "canon_sym": (uuid.uuid4(), "/test/canonical_symlink", "symlink"),
        "null_type": (uuid.uuid4(), "/test/null_type", None),
        "empty_type": (uuid.uuid4(), "/test/empty_type", ""),
        "custom_type": (uuid.uuid4(), "/test/custom_fifo", "fifo"),
        "mixed_case_reg": (uuid.uuid4(), "/test/mixed_case_reg", "Regular"),
        "upper_reg": (uuid.uuid4(), "/test/upper_reg", "REGULAR"),
        "similar_type": (uuid.uuid4(), "/test/similar_type", "regular_file_v2"),
    }

    now = _utcnow()
    with engine.begin() as conn:
        conn.execute(
            _hosts_table.insert().values(
                id=host_id,
                hostname="test-mig-host",
                created_at=now,
            )
        )

        for key, (file_id, path, file_type) in records.items():
            conn.execute(
                _files_table.insert().values(
                    id=file_id,
                    host_id=host_id,
                    path=path,
                    file_type=file_type,
                    first_seen_at=now,
                    created_at=now,
                )
            )

    return {k: v[0] for k, v in records.items()}


def _get_file_types(engine: sa.Engine, file_ids: dict[str, uuid.UUID]) -> dict[str, str | None]:
    """Retrieve current file_type values for test records."""
    result = {}
    with engine.connect() as conn:
        for key, file_id in file_ids.items():
            stmt = sa.select(_files_table.c.file_type).where(_files_table.c.id == file_id)
            val = conn.execute(stmt).scalar()
            result[key] = val
    return result


def _get_current_revision(engine: sa.Engine) -> str | None:
    """Read the current Alembic version from alembic_version table."""
    with engine.connect() as conn:
        return conn.execute(
            sa.text("SELECT version_num FROM alembic_version")
        ).scalar()


class TestNormalizeFileTypesMigrationSQLite:
    """Test 0002_normalize_file_types against an isolated SQLite database."""

    def test_upgrade_and_downgrade_normalization(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db_path = tmp_path / "disposable_test.db"
        db_url = f"sqlite:///{db_path}"

        monkeypatch.setenv("OSIRIS_DATABASE_URL", db_url)
        monkeypatch.setattr(settings, "database_url", db_url)

        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", db_url)

        # 1. Upgrade to initial schema (0001_phase1_schema)
        command.upgrade(alembic_cfg, "0001_phase1_schema")

        engine = sa.create_engine(db_url)
        assert _get_current_revision(engine) == "0001_phase1_schema"

        # 2. Seed test data containing legacy, canonical, and other values
        host_id = uuid.uuid4()
        file_ids = _populate_test_files(engine, host_id)

        initial_types = _get_file_types(engine, file_ids)
        assert initial_types["reg"] == "regular"
        assert initial_types["reg_alt"] == "regular_file"
        assert initial_types["canon_file"] == "file"
        assert initial_types["canon_dir"] == "directory"
        assert initial_types["canon_sym"] == "symlink"
        assert initial_types["null_type"] is None
        assert initial_types["empty_type"] == ""
        assert initial_types["custom_type"] == "fifo"
        assert initial_types["mixed_case_reg"] == "Regular"
        assert initial_types["upper_reg"] == "REGULAR"
        assert initial_types["similar_type"] == "regular_file_v2"

        # 3. Upgrade to 0002_normalize_file_types
        command.upgrade(alembic_cfg, "0002_normalize_file_types")
        assert _get_current_revision(engine) == "0002_normalize_file_types"

        # 4. Verify normalized file_type values
        updated_types = _get_file_types(engine, file_ids)
        assert updated_types["reg"] == "file", "regular should be converted to file"
        assert updated_types["reg_alt"] == "file", "regular_file should be converted to file"
        assert updated_types["canon_file"] == "file", "canonical file should remain file"
        assert updated_types["canon_dir"] == "directory", "directory must be preserved"
        assert updated_types["canon_sym"] == "symlink", "symlink must be preserved"
        assert updated_types["null_type"] is None, "NULL file_type must be preserved"
        assert updated_types["empty_type"] == "", "Empty string must be preserved"
        assert updated_types["custom_type"] == "fifo", "custom types must be preserved"
        assert updated_types["mixed_case_reg"] == "Regular", "exact match only"
        assert updated_types["upper_reg"] == "REGULAR", "exact match only"
        assert updated_types["similar_type"] == "regular_file_v2", "exact match only"

        # 5. Insert a newly created canonical 'file' record while on 0002
        new_file_id = uuid.uuid4()
        now = _utcnow()
        with engine.begin() as conn:
            conn.execute(
                _files_table.insert().values(
                    id=new_file_id,
                    host_id=host_id,
                    path="/test/newly_created_canonical_file",
                    file_type="file",
                    first_seen_at=now,
                    created_at=now,
                )
            )

        # 6. Downgrade back to 0001_phase1_schema
        command.downgrade(alembic_cfg, "0001_phase1_schema")
        assert _get_current_revision(engine) == "0001_phase1_schema"

        # 7. Verify downgrade behavior: safe no-op that does NOT indiscriminately
        # convert canonical 'file' records back to legacy values.
        downgraded_types = _get_file_types(engine, file_ids)
        assert downgraded_types["reg"] == "file", "downgrade must not revert file back to regular"
        assert downgraded_types["reg_alt"] == "file", "downgrade must not revert file back to regular_file"
        assert downgraded_types["canon_file"] == "file", "canonical file remains file"
        assert downgraded_types["canon_dir"] == "directory"
        assert downgraded_types["canon_sym"] == "symlink"
        assert downgraded_types["null_type"] is None
        assert downgraded_types["empty_type"] == ""
        assert downgraded_types["custom_type"] == "fifo"

        # Newly inserted canonical file must also remain untouched
        new_file_type = _get_file_types(engine, {"new": new_file_id})["new"]
        assert new_file_type == "file", "newly created canonical file must not be corrupted on downgrade"

        # 8. Test re-upgrade to 0002_normalize_file_types is idempotent
        command.upgrade(alembic_cfg, "0002_normalize_file_types")
        assert _get_current_revision(engine) == "0002_normalize_file_types"
        reupgraded_types = _get_file_types(engine, file_ids)
        assert reupgraded_types == updated_types

        engine.dispose()

    def test_empty_files_table_migration(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verify migration upgrade and downgrade succeed on an empty files table."""
        db_path = tmp_path / "empty_test.db"
        db_url = f"sqlite:///{db_path}"

        monkeypatch.setenv("OSIRIS_DATABASE_URL", db_url)
        monkeypatch.setattr(settings, "database_url", db_url)

        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", db_url)

        command.upgrade(alembic_cfg, "0001_phase1_schema")
        engine = sa.create_engine(db_url)
        assert _get_current_revision(engine) == "0001_phase1_schema"

        command.upgrade(alembic_cfg, "0002_normalize_file_types")
        assert _get_current_revision(engine) == "0002_normalize_file_types"

        command.downgrade(alembic_cfg, "0001_phase1_schema")
        assert _get_current_revision(engine) == "0001_phase1_schema"

        engine.dispose()


@pytest.fixture
def disposable_pg_url() -> Generator[str, None, None]:
    """Create a temporary disposable PostgreSQL database, yield its URL, and drop it after."""
    test_db_name = f"osiris_disp_mig_{uuid.uuid4().hex[:8]}"

    try:
        base_url = sa.engine.make_url(settings.database_url)
    except Exception:
        base_url = sa.engine.make_url("postgresql://localhost:5432/osiris_dev")

    if not base_url.drivername.startswith("postgresql"):
        base_url = sa.engine.make_url("postgresql://localhost:5432/osiris_dev")

    maintenance_url = base_url.set(database="postgres")
    disposable_url = base_url.set(database=test_db_name)

    # Attempt to create database via SQLAlchemy on maintenance db
    created_via_sa = False
    try:
        m_engine = sa.create_engine(str(maintenance_url), isolation_level="AUTOCOMMIT")
        with m_engine.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{test_db_name}"'))
        m_engine.dispose()
        created_via_sa = True
    except Exception as sa_err:
        # Fallback to createdb subprocess
        try:
            env = os.environ.copy()
            if base_url.password:
                env["PGPASSWORD"] = base_url.password
            cmd = ["createdb"]
            if base_url.host:
                cmd.extend(["-h", base_url.host])
            if base_url.port:
                cmd.extend(["-p", str(base_url.port)])
            if base_url.username:
                cmd.extend(["-U", base_url.username])
            cmd.append(test_db_name)
            res = subprocess.run(cmd, env=env, capture_output=True, text=True)
            if res.returncode != 0:
                pytest.skip(f"PostgreSQL not available for disposable db test: {sa_err}; {res.stderr}")
        except FileNotFoundError:
            pytest.skip(f"PostgreSQL not available for disposable db test: {sa_err}")

    try:
        yield str(disposable_url)
    finally:
        # Teardown: terminate active connections and drop the disposable database
        dropped = False
        try:
            m_engine = sa.create_engine(str(maintenance_url), isolation_level="AUTOCOMMIT")
            with m_engine.connect() as conn:
                conn.execute(
                    sa.text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname = :dbname AND pid <> pg_backend_pid()"
                    ),
                    {"dbname": test_db_name},
                )
                conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{test_db_name}"'))
            m_engine.dispose()
            dropped = True
        except Exception:
            pass

        if not dropped:
            try:
                env = os.environ.copy()
                if base_url.password:
                    env["PGPASSWORD"] = base_url.password
                cmd = ["dropdb", "--if-exists"]
                if base_url.host:
                    cmd.extend(["-h", base_url.host])
                if base_url.port:
                    cmd.extend(["-p", str(base_url.port)])
                if base_url.username:
                    cmd.extend(["-U", base_url.username])
                cmd.append(test_db_name)
                subprocess.run(cmd, env=env, capture_output=True)
            except Exception:
                pass


class TestNormalizeFileTypesMigrationPostgreSQL:
    """Test 0002_normalize_file_types against an isolated disposable PostgreSQL database."""

    def test_upgrade_and_downgrade_normalization_postgres(
        self, disposable_pg_url: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OSIRIS_DATABASE_URL", disposable_pg_url)
        monkeypatch.setattr(settings, "database_url", disposable_pg_url)

        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", disposable_pg_url)

        # 1. Upgrade to initial schema (0001_phase1_schema)
        command.upgrade(alembic_cfg, "0001_phase1_schema")

        engine = sa.create_engine(disposable_pg_url)
        assert _get_current_revision(engine) == "0001_phase1_schema"

        # 2. Seed test data containing legacy, canonical, and other values
        host_id = uuid.uuid4()
        file_ids = _populate_test_files(engine, host_id)

        initial_types = _get_file_types(engine, file_ids)
        assert initial_types["reg"] == "regular"
        assert initial_types["reg_alt"] == "regular_file"
        assert initial_types["canon_file"] == "file"
        assert initial_types["canon_dir"] == "directory"
        assert initial_types["canon_sym"] == "symlink"
        assert initial_types["null_type"] is None
        assert initial_types["empty_type"] == ""
        assert initial_types["custom_type"] == "fifo"
        assert initial_types["mixed_case_reg"] == "Regular"
        assert initial_types["upper_reg"] == "REGULAR"
        assert initial_types["similar_type"] == "regular_file_v2"

        # 3. Upgrade to 0002_normalize_file_types
        command.upgrade(alembic_cfg, "0002_normalize_file_types")
        assert _get_current_revision(engine) == "0002_normalize_file_types"

        # 4. Verify normalized file_type values
        updated_types = _get_file_types(engine, file_ids)
        assert updated_types["reg"] == "file", "regular should be converted to file"
        assert updated_types["reg_alt"] == "file", "regular_file should be converted to file"
        assert updated_types["canon_file"] == "file", "canonical file should remain file"
        assert updated_types["canon_dir"] == "directory", "directory must be preserved"
        assert updated_types["canon_sym"] == "symlink", "symlink must be preserved"
        assert updated_types["null_type"] is None, "NULL file_type must be preserved"
        assert updated_types["empty_type"] == "", "Empty string must be preserved"
        assert updated_types["custom_type"] == "fifo", "custom types must be preserved"
        assert updated_types["mixed_case_reg"] == "Regular", "exact match only"
        assert updated_types["upper_reg"] == "REGULAR", "exact match only"
        assert updated_types["similar_type"] == "regular_file_v2", "exact match only"

        # 5. Insert a newly created canonical 'file' record while on 0002
        new_file_id = uuid.uuid4()
        now = _utcnow()
        with engine.begin() as conn:
            conn.execute(
                _files_table.insert().values(
                    id=new_file_id,
                    host_id=host_id,
                    path="/test/newly_created_canonical_file",
                    file_type="file",
                    first_seen_at=now,
                    created_at=now,
                )
            )

        # 6. Downgrade back to 0001_phase1_schema
        command.downgrade(alembic_cfg, "0001_phase1_schema")
        assert _get_current_revision(engine) == "0001_phase1_schema"

        # 7. Verify downgrade behavior
        downgraded_types = _get_file_types(engine, file_ids)
        assert downgraded_types["reg"] == "file"
        assert downgraded_types["reg_alt"] == "file"
        assert downgraded_types["canon_file"] == "file"
        assert downgraded_types["canon_dir"] == "directory"
        assert downgraded_types["canon_sym"] == "symlink"
        assert downgraded_types["null_type"] is None
        assert downgraded_types["empty_type"] == ""
        assert downgraded_types["custom_type"] == "fifo"

        new_file_type = _get_file_types(engine, {"new": new_file_id})["new"]
        assert new_file_type == "file", "newly created canonical file must not be corrupted on downgrade"

        # 8. Test re-upgrade to 0002_normalize_file_types is idempotent
        command.upgrade(alembic_cfg, "0002_normalize_file_types")
        assert _get_current_revision(engine) == "0002_normalize_file_types"
        reupgraded_types = _get_file_types(engine, file_ids)
        assert reupgraded_types == updated_types

        engine.dispose()

    def test_empty_files_table_migration_postgres(
        self, disposable_pg_url: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verify migration upgrade and downgrade succeed on an empty files table in PostgreSQL."""
        monkeypatch.setenv("OSIRIS_DATABASE_URL", disposable_pg_url)
        monkeypatch.setattr(settings, "database_url", disposable_pg_url)

        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", disposable_pg_url)

        command.upgrade(alembic_cfg, "0001_phase1_schema")
        engine = sa.create_engine(disposable_pg_url)
        assert _get_current_revision(engine) == "0001_phase1_schema"

        command.upgrade(alembic_cfg, "0002_normalize_file_types")
        assert _get_current_revision(engine) == "0002_normalize_file_types"

        command.downgrade(alembic_cfg, "0001_phase1_schema")
        assert _get_current_revision(engine) == "0001_phase1_schema"

        engine.dispose()


class TestSnapshotsAndSessionsMigrationSQLite:
    """Test 0003_snapshots_and_sessions against an isolated SQLite database."""

    def test_upgrade_and_downgrade_snapshots_and_sessions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db_path = tmp_path / "disposable_snap_sess.db"
        db_url = f"sqlite:///{db_path}"

        monkeypatch.setenv("OSIRIS_DATABASE_URL", db_url)
        monkeypatch.setattr(settings, "database_url", db_url)

        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", db_url)

        # 1. Upgrade through 0002
        command.upgrade(alembic_cfg, "0002_normalize_file_types")
        engine = sa.create_engine(db_url)
        assert _get_current_revision(engine) == "0002_normalize_file_types"

        inspector = sa.inspect(engine)
        pre_tables = set(inspector.get_table_names())
        assert "snapshots" not in pre_tables
        assert "sessions" not in pre_tables

        # 2. Upgrade to 0003_snapshots_and_sessions
        command.upgrade(alembic_cfg, "0003_snapshots_and_sessions")
        assert _get_current_revision(engine) == "0003_snapshots_and_sessions"

        # 3. Verify schema structure
        inspector = sa.inspect(engine)
        post_tables = set(inspector.get_table_names())
        assert "snapshots" in post_tables
        assert "sessions" in post_tables

        snapshot_cols = {col["name"] for col in inspector.get_columns("snapshots")}
        expected_snap_cols = {"id", "host_id", "timestamp", "snapshot_type", "data", "created_at"}
        assert expected_snap_cols.issubset(snapshot_cols)

        session_cols = {col["name"] for col in inspector.get_columns("sessions")}
        expected_sess_cols = {
            "id", "host_id", "linux_user_id", "session_type",
            "terminal", "remote_host", "started_at", "ended_at", "created_at"
        }
        assert expected_sess_cols.issubset(session_cols)

        # Verify indexes
        snap_indexes = {ix["name"] for ix in inspector.get_indexes("snapshots")}
        assert "ix_snapshots_host_ts" in snap_indexes

        sess_indexes = {ix["name"] for ix in inspector.get_indexes("sessions")}
        assert "ix_sessions_host_started" in sess_indexes
        assert "ix_sessions_linux_user_id" in sess_indexes

        # 4. Insert data into snapshots and sessions
        now = _utcnow()
        host_id = uuid.uuid4()
        user_id = uuid.uuid4()
        snap_id = uuid.uuid4()
        sess_id = uuid.uuid4()
        sess_null_user_id = uuid.uuid4()

        payload_data = {"metrics": {"cpu": 15.4, "memory": 55.2}, "processes": [101, 102]}

        with engine.begin() as conn:
            conn.execute(
                _hosts_table.insert().values(
                    id=host_id,
                    hostname="snapshot-mig-host",
                    created_at=now,
                )
            )
            conn.execute(
                _linux_users_table.insert().values(
                    id=user_id,
                    host_id=host_id,
                    uid=1001,
                    username="snapuser",
                    first_seen_at=now,
                    created_at=now,
                )
            )
            conn.execute(
                _snapshots_table.insert().values(
                    id=snap_id,
                    host_id=host_id,
                    timestamp=now,
                    snapshot_type="system",
                    data=payload_data,
                    created_at=now,
                )
            )
            conn.execute(
                _sessions_table.insert().values(
                    id=sess_id,
                    host_id=host_id,
                    linux_user_id=user_id,
                    session_type="ssh",
                    terminal="pts/2",
                    remote_host="192.168.1.55",
                    started_at=now,
                    ended_at=now,
                    created_at=now,
                )
            )
            conn.execute(
                _sessions_table.insert().values(
                    id=sess_null_user_id,
                    host_id=host_id,
                    linux_user_id=None,
                    session_type=None,
                    terminal=None,
                    remote_host=None,
                    started_at=now,
                    ended_at=None,
                    created_at=now,
                )
            )

        # 5. Read back and verify persisted records
        with engine.connect() as conn:
            snap_row = conn.execute(
                sa.select(_snapshots_table).where(_snapshots_table.c.id == snap_id)
            ).one()
            assert snap_row.host_id == host_id
            assert snap_row.snapshot_type == "system"
            import json
            actual_data = snap_row.data if isinstance(snap_row.data, dict) else json.loads(snap_row.data)
            assert actual_data["metrics"]["cpu"] == 15.4

            sess_row = conn.execute(
                sa.select(_sessions_table).where(_sessions_table.c.id == sess_id)
            ).one()
            assert sess_row.host_id == host_id
            assert sess_row.linux_user_id == user_id
            assert sess_row.session_type == "ssh"
            assert sess_row.terminal == "pts/2"
            assert sess_row.remote_host == "192.168.1.55"

            null_sess_row = conn.execute(
                sa.select(_sessions_table).where(_sessions_table.c.id == sess_null_user_id)
            ).one()
            assert null_sess_row.linux_user_id is None
            assert null_sess_row.session_type is None
            assert null_sess_row.terminal is None
            assert null_sess_row.remote_host is None
            assert null_sess_row.ended_at is None

        # 6. Downgrade to 0002_normalize_file_types
        command.downgrade(alembic_cfg, "0002_normalize_file_types")
        assert _get_current_revision(engine) == "0002_normalize_file_types"

        inspector = sa.inspect(engine)
        down_tables = set(inspector.get_table_names())
        assert "snapshots" not in down_tables
        assert "sessions" not in down_tables
        assert "hosts" in down_tables

        # 7. Re-upgrade to 0003_snapshots_and_sessions is idempotent
        command.upgrade(alembic_cfg, "0003_snapshots_and_sessions")
        assert _get_current_revision(engine) == "0003_snapshots_and_sessions"

        inspector = sa.inspect(engine)
        reup_tables = set(inspector.get_table_names())
        assert "snapshots" in reup_tables
        assert "sessions" in reup_tables

        engine.dispose()

    def test_full_empty_cycle(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verify full upgrade and downgrade cycle from base to 0003 on empty DB."""
        db_path = tmp_path / "empty_full_cycle.db"
        db_url = f"sqlite:///{db_path}"

        monkeypatch.setenv("OSIRIS_DATABASE_URL", db_url)
        monkeypatch.setattr(settings, "database_url", db_url)

        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", db_url)

        command.upgrade(alembic_cfg, "0001_phase1_schema")
        engine = sa.create_engine(db_url)
        assert _get_current_revision(engine) == "0001_phase1_schema"

        command.upgrade(alembic_cfg, "0002_normalize_file_types")
        assert _get_current_revision(engine) == "0002_normalize_file_types"

        command.upgrade(alembic_cfg, "0003_snapshots_and_sessions")
        assert _get_current_revision(engine) == "0003_snapshots_and_sessions"

        command.upgrade(alembic_cfg, "0004_detections_and_rules")
        assert _get_current_revision(engine) == "0004_detections_and_rules"

        command.downgrade(alembic_cfg, "0003_snapshots_and_sessions")
        assert _get_current_revision(engine) == "0003_snapshots_and_sessions"

        command.downgrade(alembic_cfg, "0002_normalize_file_types")
        assert _get_current_revision(engine) == "0002_normalize_file_types"

        command.downgrade(alembic_cfg, "0001_phase1_schema")
        assert _get_current_revision(engine) == "0001_phase1_schema"

        command.downgrade(alembic_cfg, "base")
        assert _get_current_revision(engine) is None

        engine.dispose()


class TestSnapshotsAndSessionsMigrationPostgreSQL:
    """Test 0003_snapshots_and_sessions against an isolated disposable PostgreSQL database."""

    def test_upgrade_and_downgrade_snapshots_and_sessions_postgres(
        self, disposable_pg_url: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OSIRIS_DATABASE_URL", disposable_pg_url)
        monkeypatch.setattr(settings, "database_url", disposable_pg_url)

        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", disposable_pg_url)

        command.upgrade(alembic_cfg, "0002_normalize_file_types")
        engine = sa.create_engine(disposable_pg_url)
        assert _get_current_revision(engine) == "0002_normalize_file_types"

        # Upgrade to 0003
        command.upgrade(alembic_cfg, "0003_snapshots_and_sessions")
        assert _get_current_revision(engine) == "0003_snapshots_and_sessions"

        inspector = sa.inspect(engine)
        tables = set(inspector.get_table_names())
        assert "snapshots" in tables
        assert "sessions" in tables

        snapshot_cols = {col["name"] for col in inspector.get_columns("snapshots")}
        expected_snap_cols = {"id", "host_id", "timestamp", "snapshot_type", "data", "created_at"}
        assert expected_snap_cols.issubset(snapshot_cols)

        session_cols = {col["name"] for col in inspector.get_columns("sessions")}
        expected_sess_cols = {
            "id", "host_id", "linux_user_id", "session_type",
            "terminal", "remote_host", "started_at", "ended_at", "created_at"
        }
        assert expected_sess_cols.issubset(session_cols)

        # Verify indexes on PostgreSQL
        snap_indexes = {ix["name"] for ix in inspector.get_indexes("snapshots")}
        assert "ix_snapshots_host_ts" in snap_indexes

        sess_indexes = {ix["name"] for ix in inspector.get_indexes("sessions")}
        assert "ix_sessions_host_started" in sess_indexes
        assert "ix_sessions_linux_user_id" in sess_indexes

        # Insert and verify JSONB in snapshots and sessions
        now = _utcnow()
        host_id = uuid.uuid4()
        user_id = uuid.uuid4()
        snap_id = uuid.uuid4()
        sess_id = uuid.uuid4()
        sess_null_user_id = uuid.uuid4()

        with engine.begin() as conn:
            conn.execute(
                _hosts_table.insert().values(
                    id=host_id,
                    hostname="pg-snap-host",
                    created_at=now,
                )
            )
            conn.execute(
                _linux_users_table.insert().values(
                    id=user_id,
                    host_id=host_id,
                    uid=1002,
                    username="pguser",
                    first_seen_at=now,
                    created_at=now,
                )
            )
            conn.execute(
                _snapshots_table.insert().values(
                    id=snap_id,
                    host_id=host_id,
                    timestamp=now,
                    snapshot_type="system",
                    data={"nested": {"count": 100}},
                    created_at=now,
                )
            )
            conn.execute(
                _sessions_table.insert().values(
                    id=sess_id,
                    host_id=host_id,
                    linux_user_id=user_id,
                    session_type="tty",
                    terminal="tty1",
                    remote_host=None,
                    started_at=now,
                    ended_at=None,
                    created_at=now,
                )
            )
            conn.execute(
                _sessions_table.insert().values(
                    id=sess_null_user_id,
                    host_id=host_id,
                    linux_user_id=None,
                    session_type=None,
                    terminal=None,
                    remote_host=None,
                    started_at=now,
                    ended_at=None,
                    created_at=now,
                )
            )

        with engine.connect() as conn:
            snap_row = conn.execute(
                sa.select(_snapshots_table).where(_snapshots_table.c.id == snap_id)
            ).one()
            assert snap_row.data["nested"]["count"] == 100

            null_sess_row = conn.execute(
                sa.select(_sessions_table).where(_sessions_table.c.id == sess_null_user_id)
            ).one()
            assert null_sess_row.linux_user_id is None
            assert null_sess_row.session_type is None
            assert null_sess_row.terminal is None
            assert null_sess_row.remote_host is None
            assert null_sess_row.ended_at is None

        # Downgrade back to 0002
        command.downgrade(alembic_cfg, "0002_normalize_file_types")
        assert _get_current_revision(engine) == "0002_normalize_file_types"

        inspector = sa.inspect(engine)
        down_tables = set(inspector.get_table_names())
        assert "snapshots" not in down_tables
        assert "sessions" not in down_tables

        # Re-upgrade to 0003_snapshots_and_sessions
        command.upgrade(alembic_cfg, "0003_snapshots_and_sessions")
        assert _get_current_revision(engine) == "0003_snapshots_and_sessions"

        engine.dispose()


class TestDetectionsAndRulesMigrationSQLite:
    """Test 0004_detections_and_rules against an isolated SQLite database."""

    def test_upgrade_and_downgrade_detections_and_rules(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db_path = tmp_path / "disposable_detect.db"
        db_url = f"sqlite:///{db_path}"

        monkeypatch.setenv("OSIRIS_DATABASE_URL", db_url)
        monkeypatch.setattr(settings, "database_url", db_url)

        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", db_url)

        # 1. Upgrade through 0003
        command.upgrade(alembic_cfg, "0003_snapshots_and_sessions")
        engine = sa.create_engine(db_url)
        assert _get_current_revision(engine) == "0003_snapshots_and_sessions"

        inspector = sa.inspect(engine)
        pre_tables = set(inspector.get_table_names())
        assert "detection_rules" not in pre_tables
        assert "detections" not in pre_tables

        # 2. Upgrade to 0004_detections_and_rules
        command.upgrade(alembic_cfg, "0004_detections_and_rules")
        assert _get_current_revision(engine) == "0004_detections_and_rules"

        # 3. Verify schema structure
        inspector = sa.inspect(engine)
        post_tables = set(inspector.get_table_names())
        assert "detection_rules" in post_tables
        assert "detections" in post_tables

        rule_cols = {col["name"] for col in inspector.get_columns("detection_rules")}
        expected_rule_cols = {
            "id", "rule_id", "name", "description", "category", "severity",
            "enabled", "version", "rule_type", "conditions", "sequence_conditions",
            "time_window_seconds", "rule_metadata", "created_at", "updated_at"
        }
        assert expected_rule_cols.issubset(rule_cols)

        detection_cols = {col["name"] for col in inspector.get_columns("detections")}
        expected_detection_cols = {
            "id", "rule_id", "rule_version", "host_id", "event_id", "process_id",
            "session_id", "timestamp", "severity", "title", "description",
            "category", "status", "notification_status", "matched_conditions",
            "evidence", "dedup_hash", "created_at", "acknowledged_at", "acknowledged_by_id"
        }
        assert expected_detection_cols.issubset(detection_cols)

        # Verify indexes
        rule_indexes = {ix["name"] for ix in inspector.get_indexes("detection_rules")}
        assert "ix_detection_rules_rule_id" in rule_indexes
        assert "ix_detection_rules_category" in rule_indexes
        assert "ix_detection_rules_severity" in rule_indexes
        assert "ix_detection_rules_enabled" in rule_indexes

        detection_indexes = {ix["name"] for ix in inspector.get_indexes("detections")}
        assert "ix_detections_host_ts" in detection_indexes
        assert "ix_detections_rule_id" in detection_indexes
        assert "ix_detections_severity" in detection_indexes
        assert "ix_detections_status" in detection_indexes
        assert "ix_detections_category" in detection_indexes
        assert "ix_detections_dedup_hash" in detection_indexes

        # 4. Insert data into detection_rules and detections
        now = _utcnow()
        host_id = uuid.uuid4()
        rule_db_id = uuid.uuid4()
        detection_id = uuid.uuid4()

        conditions_data = {"all": [{"field": "command", "operator": "startswith", "value": "sudo "}]}
        evidence_data = {"triggering_events": [str(uuid.uuid4())], "summary": "sudo su executed"}
        matched_data = {"matched_field": "command", "value": "sudo su"}

        with engine.begin() as conn:
            conn.execute(
                _hosts_table.insert().values(
                    id=host_id,
                    hostname="detect-mig-host",
                    created_at=now,
                )
            )
            conn.execute(
                _detection_rules_table.insert().values(
                    id=rule_db_id,
                    rule_id="RULE-TEST-001",
                    name="Test Detection Rule",
                    description="Detects suspicious activity",
                    category="privilege_escalation",
                    severity="high",
                    enabled=True,
                    version=1,
                    rule_type="single_event",
                    conditions=conditions_data,
                    sequence_conditions=None,
                    time_window_seconds=None,
                    rule_metadata={"author": "Security Team"},
                    created_at=now,
                    updated_at=None,
                )
            )
            conn.execute(
                _detections_table.insert().values(
                    id=detection_id,
                    rule_id=rule_db_id,
                    rule_version=1,
                    host_id=host_id,
                    event_id=None,
                    process_id=None,
                    session_id=None,
                    timestamp=now,
                    severity="high",
                    title="Suspicious Sudo Execution",
                    description="User executed sudo su",
                    category="privilege_escalation",
                    status="open",
                    notification_status="pending",
                    matched_conditions=matched_data,
                    evidence=evidence_data,
                    dedup_hash="abc123hash",
                    created_at=now,
                    acknowledged_at=None,
                    acknowledged_by_id=None,
                )
            )

        # 5. Read back and verify persisted records
        import json
        with engine.connect() as conn:
            rule_row = conn.execute(
                sa.select(_detection_rules_table).where(_detection_rules_table.c.id == rule_db_id)
            ).one()
            assert rule_row.rule_id == "RULE-TEST-001"
            assert rule_row.severity == "high"
            raw_cond = rule_row.conditions if isinstance(rule_row.conditions, dict) else json.loads(rule_row.conditions)
            assert raw_cond["all"][0]["operator"] == "startswith"

            detect_row = conn.execute(
                sa.select(_detections_table).where(_detections_table.c.id == detection_id)
            ).one()
            assert detect_row.host_id == host_id
            assert detect_row.title == "Suspicious Sudo Execution"
            assert detect_row.status == "open"
            raw_ev = detect_row.evidence if isinstance(detect_row.evidence, dict) else json.loads(detect_row.evidence)
            assert raw_ev["summary"] == "sudo su executed"

        # 6. Downgrade to 0003_snapshots_and_sessions
        command.downgrade(alembic_cfg, "0003_snapshots_and_sessions")
        assert _get_current_revision(engine) == "0003_snapshots_and_sessions"

        inspector = sa.inspect(engine)
        down_tables = set(inspector.get_table_names())
        assert "detection_rules" not in down_tables
        assert "detections" not in down_tables
        assert "snapshots" in down_tables
        assert "sessions" in down_tables

        # 7. Re-upgrade to 0004_detections_and_rules is idempotent
        command.upgrade(alembic_cfg, "0004_detections_and_rules")
        assert _get_current_revision(engine) == "0004_detections_and_rules"

        inspector = sa.inspect(engine)
        reup_tables = set(inspector.get_table_names())
        assert "detection_rules" in reup_tables
        assert "detections" in reup_tables

        engine.dispose()


class TestDetectionsAndRulesMigrationPostgreSQL:
    """Test 0004_detections_and_rules against an isolated disposable PostgreSQL database."""

    def test_upgrade_and_downgrade_detections_and_rules_postgres(
        self, disposable_pg_url: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OSIRIS_DATABASE_URL", disposable_pg_url)
        monkeypatch.setattr(settings, "database_url", disposable_pg_url)

        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", disposable_pg_url)

        # 1. Upgrade through 0003
        command.upgrade(alembic_cfg, "0003_snapshots_and_sessions")
        engine = sa.create_engine(disposable_pg_url)
        assert _get_current_revision(engine) == "0003_snapshots_and_sessions"

        # 2. Upgrade to 0004_detections_and_rules
        command.upgrade(alembic_cfg, "0004_detections_and_rules")
        assert _get_current_revision(engine) == "0004_detections_and_rules"

        inspector = sa.inspect(engine)
        tables = set(inspector.get_table_names())
        assert "detection_rules" in tables
        assert "detections" in tables

        # Verify JSONB storage
        now = _utcnow()
        host_id = uuid.uuid4()
        rule_db_id = uuid.uuid4()
        detection_id = uuid.uuid4()

        with engine.begin() as conn:
            conn.execute(
                _hosts_table.insert().values(
                    id=host_id,
                    hostname="pg-detect-host",
                    created_at=now,
                )
            )
            conn.execute(
                _detection_rules_table.insert().values(
                    id=rule_db_id,
                    rule_id="PG-RULE-001",
                    name="PG Test Rule",
                    description="PG test description",
                    category="reconnaissance",
                    severity="critical",
                    enabled=True,
                    version=1,
                    rule_type="single_event",
                    conditions={"all": [{"field": "object_path", "operator": "==", "value": "/etc/shadow"}]},
                    sequence_conditions=None,
                    time_window_seconds=None,
                    rule_metadata={"tactics": ["TA0007"]},
                    created_at=now,
                    updated_at=None,
                )
            )
            conn.execute(
                _detections_table.insert().values(
                    id=detection_id,
                    rule_id=rule_db_id,
                    rule_version=1,
                    host_id=host_id,
                    event_id=None,
                    process_id=None,
                    session_id=None,
                    timestamp=now,
                    severity="critical",
                    title="Sensitive File Access",
                    description="/etc/shadow read detected",
                    category="reconnaissance",
                    status="open",
                    notification_status="pending",
                    matched_conditions={"object_path": "/etc/shadow"},
                    evidence={"file": "/etc/shadow", "user": "test"},
                    dedup_hash="pgdeduphash123",
                    created_at=now,
                    acknowledged_at=None,
                    acknowledged_by_id=None,
                )
            )

        with engine.connect() as conn:
            detect_row = conn.execute(
                sa.select(_detections_table).where(_detections_table.c.id == detection_id)
            ).one()
            assert detect_row.severity == "critical"
            assert detect_row.evidence["file"] == "/etc/shadow"

        # Downgrade back to 0003
        command.downgrade(alembic_cfg, "0003_snapshots_and_sessions")
        assert _get_current_revision(engine) == "0003_snapshots_and_sessions"

        inspector = sa.inspect(engine)
        down_tables = set(inspector.get_table_names())
        assert "detection_rules" not in down_tables
        assert "detections" not in down_tables

        # Re-upgrade to 0004
        command.upgrade(alembic_cfg, "0004_detections_and_rules")
        assert _get_current_revision(engine) == "0004_detections_and_rules"

        engine.dispose()
