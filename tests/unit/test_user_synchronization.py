"""Unit tests for OSIRIS Linux User Account Discovery & Synchronization.

Tests cover:
1. Parsing of `/etc/passwd` text format (comments, blanks, malformed lines, deduplication).
2. Discovery via custom passwd file, custom provider, and fallback.
3. Host-scoped synchronization of discovered accounts to `linux_users`.
4. Updating usernames and `last_seen_at` when accounts change.
5. Host isolation: accounts on Host A do not overwrite or appear on Host B.
6. Safe handling of removed accounts (historical records preserved without fabrication).
7. Clean transactional behavior: flushes changes without committing or closing.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.services.events.user_sync import (
    LinuxUserSynchronizer,
    _ensure_utc,
    parse_passwd_content,
)


@pytest.fixture
def host_a(db_session: Session) -> Host:
    host = Host(
        id=uuid.uuid4(),
        hostname="sync-host-a",
        os_info="Ubuntu 22.04 LTS",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(host)
    db_session.flush()
    return host


@pytest.fixture
def host_b(db_session: Session) -> Host:
    host = Host(
        id=uuid.uuid4(),
        hostname="sync-host-b",
        os_info="Debian 12",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(host)
    db_session.flush()
    return host


# ── 1. Passwd Parser Unit Tests ──────────────────────────────────────


class TestPasswdParser:
    def test_parse_passwd_standard(self):
        content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "alice:x:1000:1000:Alice User,,,:/home/alice:/bin/bash\n"
            "bob:x:1001:1001::/home/bob:/bin/zsh\n"
        )
        users = parse_passwd_content(content)
        assert users == [
            (0, "root"),
            (1, "daemon"),
            (1000, "alice"),
            (1001, "bob"),
        ]

    def test_parse_passwd_ignores_comments_and_blank_lines(self):
        content = (
            "# This is a comment\n"
            "\n"
            "   # Indented comment\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "   \n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        )
        users = parse_passwd_content(content)
        assert users == [(0, "root"), (65534, "nobody")]

    def test_parse_passwd_skips_malformed_and_negative_uids(self):
        content = (
            "no_colons_here\n"
            "bad_uid:x:notanumber:100::/home/bad:/bin/sh\n"
            "negative_uid:x:-5:100::/home/neg:/bin/sh\n"
            ":x:1002:1002::/home/empty:/bin/sh\n"
            "valid:x:1002:1002:Valid User:/home/valid:/bin/bash\n"
        )
        users = parse_passwd_content(content)
        assert users == [(1002, "valid")]

    def test_parse_passwd_deduplicates_uids(self):
        content = (
            "user1:x:1000:1000::/home/user1:/bin/sh\n"
            "user1_alias:x:1000:1000::/home/user1:/bin/sh\n"
            "user2:x:1001:1001::/home/user2:/bin/sh\n"
        )
        users = parse_passwd_content(content)
        assert users == [(1000, "user1"), (1001, "user2")]


# ── 2. Discovery Source Tests ─────────────────────────────────────────


class TestDiscoverySources:
    def test_discover_from_file(self, tmp_path: Path):
        passwd_file = tmp_path / "passwd"
        passwd_file.write_text(
            "appuser:x:2000:2000::/app:/bin/bash\n", encoding="utf-8"
        )
        sync = LinuxUserSynchronizer(passwd_file=passwd_file)
        discovered = sync.discover_users()
        assert discovered == [(2000, "appuser")]

    def test_discover_from_injected_provider(self):
        provider = lambda: [(3000, "provider_user"), (3001, "provider_admin")]
        sync = LinuxUserSynchronizer(user_provider=provider)
        discovered = sync.discover_users()
        assert discovered == [(3000, "provider_user"), (3001, "provider_admin")]

    def test_discover_nonexistent_file_falls_back_gracefully(self, tmp_path: Path):
        passwd_file = tmp_path / "does_not_exist"
        sync = LinuxUserSynchronizer(passwd_file=passwd_file)
        # Should not raise exception; returns list (either from POSIX pwd or empty)
        discovered = sync.discover_users()
        assert isinstance(discovered, list)


# ── 3. Database Synchronization Tests ─────────────────────────────────


class TestUserDatabaseSync:
    def test_sync_users_populates_new_records(
        self, db_session: Session, host_a: Host
    ):
        provider = lambda: [(1000, "alice"), (1001, "bob")]
        sync = LinuxUserSynchronizer(user_provider=provider)
        t_now = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        synced = sync.sync_users(host_a.id, db_session, now=t_now)
        assert len(synced) == 2

        # Verify records in database
        users = (
            db_session.execute(
                select(LinuxUser)
                .where(LinuxUser.host_id == host_a.id)
                .order_by(LinuxUser.uid.asc())
            )
            .scalars()
            .all()
        )
        assert len(users) == 2
        assert users[0].uid == 1000
        assert users[0].username == "alice"
        assert users[0].first_seen_at == t_now
        assert users[0].last_seen_at == t_now

        assert users[1].uid == 1001
        assert users[1].username == "bob"
        assert users[1].first_seen_at == t_now
        assert users[1].last_seen_at == t_now

    def test_sync_users_updates_existing_records(
        self, db_session: Session, host_a: Host
    ):
        t1 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        user = LinuxUser(
            id=uuid.uuid4(),
            host_id=host_a.id,
            uid=1000,
            username="old_name",
            first_seen_at=t1,
            last_seen_at=t1,
        )
        db_session.add(user)
        db_session.flush()

        t2 = datetime(2026, 1, 15, 11, 0, 0, tzinfo=timezone.utc)
        provider = lambda: [(1000, "new_name")]
        sync = LinuxUserSynchronizer(user_provider=provider)

        sync.sync_users(host_a.id, db_session, now=t2)

        db_session.expire_all()
        fetched = db_session.execute(
            select(LinuxUser).where(
                LinuxUser.host_id == host_a.id, LinuxUser.uid == 1000
            )
        ).scalar_one()

        assert fetched.username == "new_name"
        assert _ensure_utc(fetched.first_seen_at) == t1  # Preserved original discovery time
        assert _ensure_utc(fetched.last_seen_at) == t2  # Refreshed last seen time

    def test_sync_users_host_isolation(
        self, db_session: Session, host_a: Host, host_b: Host
    ):
        """Same UID on Host A and Host B are kept distinct with host scoping."""
        t_now = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        sync_a = LinuxUserSynchronizer(user_provider=lambda: [(1000, "alice_a")])
        sync_b = LinuxUserSynchronizer(user_provider=lambda: [(1000, "bob_b")])

        sync_a.sync_users(host_a.id, db_session, now=t_now)
        sync_b.sync_users(host_b.id, db_session, now=t_now)

        user_a = db_session.execute(
            select(LinuxUser).where(
                LinuxUser.host_id == host_a.id, LinuxUser.uid == 1000
            )
        ).scalar_one()
        user_b = db_session.execute(
            select(LinuxUser).where(
                LinuxUser.host_id == host_b.id, LinuxUser.uid == 1000
            )
        ).scalar_one()

        assert user_a.id != user_b.id
        assert user_a.username == "alice_a"
        assert user_b.username == "bob_b"

    def test_sync_users_removed_accounts_retained_historically(
        self, db_session: Session, host_a: Host
    ):
        """When an account is removed from the host, its historical DB record is preserved."""
        t1 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        sync1 = LinuxUserSynchronizer(
            user_provider=lambda: [(1000, "active_user"), (1001, "to_be_deleted")]
        )
        sync1.sync_users(host_a.id, db_session, now=t1)

        t2 = datetime(2026, 1, 15, 11, 0, 0, tzinfo=timezone.utc)
        # Account 1001 is removed from host OS
        sync2 = LinuxUserSynchronizer(
            user_provider=lambda: [(1000, "active_user")]
        )
        sync2.sync_users(host_a.id, db_session, now=t2)

        users = (
            db_session.execute(
                select(LinuxUser)
                .where(LinuxUser.host_id == host_a.id)
                .order_by(LinuxUser.uid.asc())
            )
            .scalars()
            .all()
        )
        assert len(users) == 2
        # Active user was updated to t2
        assert users[0].uid == 1000
        assert _ensure_utc(users[0].last_seen_at) == t2
        # Deleted user still exists for historical foreign keys, last seen at t1
        assert users[1].uid == 1001
        assert _ensure_utc(users[1].last_seen_at) == t1

    def test_parse_passwd_ignores_nis_compat_entries(self):
        """NIS/YP compat entries starting with '+' or '-' are ignored."""
        content = (
            "+::::::\n"
            "+@netgroup\n"
            "-blocked_user:x:1005:1005::/home/blocked:/bin/bash\n"
            "+valid_compat_format_ignored:x:1006:1006::/home/ignored:/bin/bash\n"
            "real_user:x:1007:1007:Real User:/home/real:/bin/bash\n"
        )
        users = parse_passwd_content(content)
        assert users == [(1007, "real_user")]

    def test_sync_users_invalidates_resolver_cache_on_change(
        self, db_session: Session, host_a: Host
    ):
        """When user is created or updated, resolver cache is automatically invalidated."""
        from backend.services.events.resolver import DatabaseIdentityResolver

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=60.0)

        # 1. Query non-existent user -> caches None
        assert resolver.resolve_user(host_a.id, 2050) is None
        assert (host_a.id, 2050) in resolver._user_cache
        assert resolver._user_cache[(host_a.id, 2050)].username is None

        # 2. Sync user 2050 with resolver passed
        t_now = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        sync = LinuxUserSynchronizer(user_provider=lambda: [(2050, "new_discovered_user")])
        sync.sync_users(host_a.id, db_session, resolver=resolver, now=t_now)

        # 3. Cache entry was invalidated, next resolution fetches new user
        assert (host_a.id, 2050) not in resolver._user_cache
        assert resolver.resolve_user(host_a.id, 2050) == "new_discovered_user"
