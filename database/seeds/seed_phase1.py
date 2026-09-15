"""Phase 1 seed data for OSIRIS development.

Inserts minimal, non-sensitive sample records for development and testing.
Run from the project root: python -m database.seeds.seed_phase1

Requires:
  - PostgreSQL database with Phase 1 schema applied (alembic upgrade head)
  - OSIRIS_DATABASE_URL environment variable set
"""

import sys
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from backend.db.session import SessionLocal
from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.app_user import AppUser
from backend.db.models.file import File
from backend.db.models.resource_snapshot import ResourceSnapshot


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Fixed UUIDs for reproducible seed data
HOST_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")
ROOT_USER_ID = uuid.UUID("00000000-0000-4000-8000-000000000010")
REGULAR_USER_ID = uuid.UUID("00000000-0000-4000-8000-000000000011")
SYSTEM_USER_ID = uuid.UUID("00000000-0000-4000-8000-000000000012")
SAMPLE_PROCESS_ID = uuid.UUID("00000000-0000-4000-8000-000000000020")
ADMIN_USER_ID = uuid.UUID("00000000-0000-4000-8000-000000000100")


def seed() -> None:
    """Insert Phase 1 seed data."""
    session = SessionLocal()
    try:
        # Check if seed data already exists
        existing = session.execute(
            select(Host).where(Host.id == HOST_ID)
        ).scalar_one_or_none()
        if existing:
            print("Seed data already exists. Skipping.")
            return

        now = utcnow()

        # --- Host ---
        host = Host(
            id=HOST_ID,
            hostname="osiris-dev-vm",
            os_info="Ubuntu 22.04 LTS",
            ip_address="192.168.56.10",
            created_at=now,
        )
        session.add(host)

        # --- Linux Users ---
        root_user = LinuxUser(
            id=ROOT_USER_ID,
            host_id=HOST_ID,
            uid=0,
            username="root",
            first_seen_at=now,
            created_at=now,
        )
        regular_user = LinuxUser(
            id=REGULAR_USER_ID,
            host_id=HOST_ID,
            uid=1000,
            username="student",
            first_seen_at=now,
            created_at=now,
        )
        system_user = LinuxUser(
            id=SYSTEM_USER_ID,
            host_id=HOST_ID,
            uid=65534,
            username="nobody",
            first_seen_at=now,
            created_at=now,
        )
        session.add_all([root_user, regular_user, system_user])

        # --- Sample Process ---
        sample_process = Process(
            id=SAMPLE_PROCESS_ID,
            host_id=HOST_ID,
            pid=1,
            ppid=0,
            command="/sbin/init",
            executable="/sbin/init",
            linux_user_id=ROOT_USER_ID,
            started_at=now,
            created_at=now,
        )
        session.add(sample_process)

        # --- Sample File ---
        sample_file = File(
            host_id=HOST_ID,
            path="/etc/passwd",
            file_type="regular",
            first_seen_at=now,
            created_at=now,
        )
        session.add(sample_file)

        # --- Sample Resource Snapshot ---
        sample_snapshot = ResourceSnapshot(
            host_id=HOST_ID,
            timestamp=now,
            cpu_percent=12.5,
            memory_total=8_589_934_592,  # 8 GB
            memory_used=2_147_483_648,   # 2 GB
            memory_percent=25.0,
            disk_read_bytes=1_048_576,
            disk_write_bytes=524_288,
            disk_usage_percent=45.0,
            created_at=now,
        )
        session.add(sample_snapshot)

        # --- Application User ---
        # Password hash is a placeholder — NOT a real password.
        # The authentication system (Milestone 1.5) will implement
        # proper password hashing. This value is a bcrypt hash of
        # the word 'changeme' for development seeding only.
        app_admin = AppUser(
            id=ADMIN_USER_ID,
            username="admin",
            password_hash="$2b$12$PLACEHOLDER_HASH_DO_NOT_USE_IN_PRODUCTION",
            display_name="OSIRIS Administrator",
            role="admin",
            is_active=True,
            created_at=now,
        )
        session.add(app_admin)

        session.commit()
        print("Phase 1 seed data inserted successfully.")
        print(f"  Host: {host.hostname} ({HOST_ID})")
        print(f"  Linux users: root, student, nobody")
        print(f"  Process: /sbin/init (PID 1)")
        print(f"  File: /etc/passwd")
        print(f"  Resource snapshot: 1 record")
        print(f"  App user: admin ({ADMIN_USER_ID})")

    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    seed()
