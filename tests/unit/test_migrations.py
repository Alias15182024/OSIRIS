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

        # 8. Test re-upgrade to head is idempotent
        command.upgrade(alembic_cfg, "head")
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


class TestNormalizeFileTypesMigrationPostgreSQL:
    """Test 0002_normalize_file_types against an isolated disposable PostgreSQL database."""

    @pytest.fixture
    def disposable_pg_url(self) -> Generator[str, None, None]:
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

        # 8. Test re-upgrade to head is idempotent
        command.upgrade(alembic_cfg, "head")
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
