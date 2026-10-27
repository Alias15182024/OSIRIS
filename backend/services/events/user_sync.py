"""Linux user account discovery and synchronization for OSIRIS.

Discovers operating system user accounts on the monitored host (from `/etc/passwd`
or POSIX account databases) and synchronizes them to the host-scoped `linux_users`
database table.

Follows the OSIRIS contract:
- Host-scoped: records belong strictly to the monitored host (`host_id`).
- Real OS account information: extracts genuine `(uid, username)` pairs.
- No fabricated identities: missing accounts remain unresolved (None).
- Safe handling of removed accounts: does not delete historical records.
- Transaction safety: flushes changes without committing or closing the session.
"""

from __future__ import annotations

import logging
import pwd
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.models.linux_user import LinuxUser

if TYPE_CHECKING:
    from backend.services.events.resolver import IdentityResolver

logger = logging.getLogger("osiris.services.events.user_sync")


def _ensure_uuid(val: uuid.UUID | str) -> uuid.UUID:
    """Coerce a UUID or string into a uuid.UUID instance."""
    if isinstance(val, uuid.UUID):
        return val
    return uuid.UUID(str(val))


def _ensure_utc(dt: datetime | None) -> datetime:
    """Ensure a datetime is timezone-aware UTC."""
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_passwd_content(content: str) -> list[tuple[int, str]]:
    """Parse the text content of a `/etc/passwd` file into (uid, username) pairs.

    Parameters
    ----------
    content:
        The raw text of the passwd file.

    Returns
    -------
    list[tuple[int, str]]
        List of valid, unique (uid, username) pairs.
    """
    users: list[tuple[int, str]] = []
    seen_uids: set[int] = set()

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "+", "-")):
            continue
        parts = line.split(":")
        if len(parts) >= 3:
            username = parts[0].strip()
            if not username or username.startswith(("+", "-")):
                continue
            uid_str = parts[2].strip()
            try:
                uid = int(uid_str)
            except ValueError:
                continue
            if uid >= 0 and uid not in seen_uids:
                users.append((uid, username))
                seen_uids.add(uid)

    return users


class LinuxUserSynchronizer:
    """Discovers host user accounts and synchronizes them to the `linux_users` table.

    Parameters
    ----------
    passwd_file:
        Optional path to `/etc/passwd` file. Defaults to `/etc/passwd`.
        If the file does not exist or cannot be read, falls back to `pwd.getpwall()`
        on POSIX systems.
    user_provider:
        Optional callable returning `list[tuple[int, str]]`. Injected for isolated
        unit testing without filesystem access.
    """

    def __init__(
        self,
        *,
        passwd_file: Path | str | None = "/etc/passwd",
        user_provider: Callable[[], list[tuple[int, str]]] | None = None,
    ) -> None:
        self.passwd_file = Path(passwd_file) if passwd_file is not None else None
        self.user_provider = user_provider

    def discover_users(self) -> list[tuple[int, str]]:
        """Discover OS accounts from the configured source.

        Returns
        -------
        list[tuple[int, str]]
            List of (uid, username) pairs.
        """
        if self.user_provider is not None:
            return self.user_provider()

        # Try reading passwd_file if specified and accessible
        if self.passwd_file is not None and self.passwd_file.is_file():
            try:
                content = self.passwd_file.read_text(
                    encoding="utf-8", errors="replace"
                )
                return parse_passwd_content(content)
            except (OSError, PermissionError) as exc:
                logger.warning(
                    "Could not read passwd file %s: %s", self.passwd_file, exc
                )

        # Fallback to standard library pwd module on POSIX systems
        if hasattr(pwd, "getpwall"):
            try:
                entries = pwd.getpwall()
                seen_uids: set[int] = set()
                users: list[tuple[int, str]] = []
                for entry in entries:
                    if (
                        entry.pw_uid >= 0
                        and entry.pw_name
                        and entry.pw_uid not in seen_uids
                    ):
                        users.append((entry.pw_uid, entry.pw_name))
                        seen_uids.add(entry.pw_uid)
                return users
            except Exception as exc:
                logger.warning("pwd.getpwall() failed: %s", exc)

        return []

    def sync_users(
        self,
        host_id: uuid.UUID | str,
        session: Session,
        *,
        resolver: IdentityResolver | None = None,
        now: datetime | None = None,
    ) -> list[LinuxUser]:
        """Synchronize discovered users to the `linux_users` table for `host_id`.

        Creates new `LinuxUser` rows for newly discovered accounts.
        Updates `username` (if changed) and `last_seen_at` for existing accounts.
        Flushes the session to make records available in the active transaction.

        Parameters
        ----------
        host_id:
            UUID of the monitored host.
        session:
            Active SQLAlchemy Session.
        resolver:
            Optional IdentityResolver instance to invalidate on user changes.
        now:
            Optional current timestamp. Defaults to UTC now.

        Returns
        -------
        list[LinuxUser]
            All active LinuxUser instances for this host.
        """
        host_uuid = _ensure_uuid(host_id)
        current_ts = _ensure_utc(now)

        discovered = self.discover_users()
        if not discovered:
            return []

        # Load existing users for this host
        stmt = select(LinuxUser).where(LinuxUser.host_id == host_uuid)
        existing_records = session.execute(stmt).scalars().all()
        existing_by_uid = {u.uid: u for u in existing_records}

        synced: list[LinuxUser] = []

        for uid, username in discovered:
            if uid in existing_by_uid:
                user = existing_by_uid[uid]
                if user.username != username:
                    user.username = username
                    if resolver is not None:
                        resolver.invalidate_user(host_uuid, uid)
                user.last_seen_at = current_ts
                synced.append(user)
            else:
                new_user = LinuxUser(
                    id=uuid.uuid4(),
                    host_id=host_uuid,
                    uid=uid,
                    username=username,
                    first_seen_at=current_ts,
                    last_seen_at=current_ts,
                    created_at=current_ts,
                )
                session.add(new_user)
                existing_by_uid[uid] = new_user
                synced.append(new_user)
                if resolver is not None:
                    resolver.invalidate_user(host_uuid, uid)

        session.flush()
        return synced
