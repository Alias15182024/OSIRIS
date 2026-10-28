"""Identity resolution for the OSIRIS Event Processing Layer.

Provides abstractions and implementations for resolving source-level
Linux identities into authoritative OSIRIS domain identities:
- UID → username (host-scoped lookup against ``linux_users``)
- PID → internal process UUID (host-scoped, time-bounded lookup against ``processes``)

Follows the OSIRIS event model contract:
- Collectors emit raw observations with source-level identifiers.
- The Event Processing Layer is the sole authority for identity resolution.
- Source-level ``uid``, ``pid``, and ``ppid`` are always preserved on events.
- Username is supplementary and null when unresolvable; no usernames are invented.
- Process resolution strictly enforces lifetime bounds:
  ``process.started_at <= event.timestamp`` and
  ``(process.ended_at IS NULL OR event.timestamp <= process.ended_at)``.
- Ambiguous or overlapping process matches resolve safely to None.
- Caching is time-aware and host-scoped to guarantee PID reuse safety.
"""

from __future__ import annotations

import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.services.events.schemas import NormalizedEvent

logger = logging.getLogger("osiris.services.events.resolver")


def resolve_host_uuid(host_id: uuid.UUID | str) -> uuid.UUID:
    """Resolve a host identifier to a canonical deterministic UUID.

    - If host_id is already a uuid.UUID instance, returns it directly.
    - If host_id is a valid UUID string (hexadecimal with or without hyphens),
      normalizes (whitespace-stripped) and returns the parsed uuid.UUID.
    - If host_id is a non-UUID hostname/string (e.g. 'osiris-dev-host'), derives
      a deterministic UUIDv5 using uuid.uuid5(uuid.NAMESPACE_DNS, host_str).
    """
    if isinstance(host_id, uuid.UUID):
        return host_id
    host_str = str(host_id).strip()
    try:
        return uuid.UUID(host_str)
    except (ValueError, AttributeError, TypeError):
        return uuid.uuid5(uuid.NAMESPACE_DNS, host_str)


# Canonical alias for internal identity resolution routines
_ensure_uuid = resolve_host_uuid


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Ensure a datetime is timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass
class _CachedUser:
    """Internal cached user record with monotonic creation timestamp."""

    username: str | None
    cached_at: float


@dataclass
class _CachedProcess:
    """Internal cached process lifetime record with monotonic creation timestamp."""

    id: uuid.UUID
    started_at: datetime
    ended_at: datetime | None
    cached_at: float

    def matches(self, ts: datetime, event_type: str | None = None) -> bool:
        """Check if an event timestamp falls within the cached lifetime bounds.

        Respects process start boundary (started_at <= ts) and termination boundary
        (ended_at is None or ts <= ended_at).
        For 'process.start' events, started_at cannot be strictly earlier than ts.
        For 'process.end' events, process must have started at or before ts.
        """
        if self.started_at > ts:
            return False
        if event_type == "process.start" and self.started_at < ts:
            return False
        if event_type == "process.end":
            if self.ended_at is not None:
                return self.ended_at == ts
            return False
        if self.ended_at is not None:
            return ts <= self.ended_at
        return True


class IdentityResolver(ABC):
    """Abstract base class for event identity resolution.

    Resolvers decouple identity lookup mechanisms from the core
    event-processing pipeline.
    """

    @abstractmethod
    def resolve_user(self, host_id: uuid.UUID | str, uid: int) -> str | None:
        """Resolve a host-scoped Linux UID to a username.

        Parameters
        ----------
        host_id:
            Identifier of the monitored host.
        uid:
            Linux user ID (>= 0).

        Returns
        -------
        str | None
            The resolved username, or None if unresolvable.
        """

    @abstractmethod
    def resolve_process(
        self,
        host_id: uuid.UUID | str,
        pid: int,
        timestamp: datetime,
        event_type: str | None = None,
    ) -> uuid.UUID | None:
        """Resolve a Linux PID to an OSIRIS internal process UUID.

        Parameters
        ----------
        host_id:
            Identifier of the monitored host.
        pid:
            Linux process ID (>= 0).
        timestamp:
            Event timestamp (UTC) for time-bounded lifecycle matching.
        event_type:
            Optional event type (e.g. 'process.start', 'process.end') for boundary disambiguation.

        Returns
        -------
        uuid.UUID | None
            The resolved internal process UUID, or None if unresolvable
            or ambiguous.
        """

    @abstractmethod
    def resolve_event(self, event: NormalizedEvent) -> NormalizedEvent:
        """Apply identity resolution to a normalized event.

        Parameters
        ----------
        event:
            A NormalizedEvent instance.

        Returns
        -------
        NormalizedEvent
            A new NormalizedEvent instance with resolved identities.
        """

    def clear_cache(self) -> None:
        """Clear all cached identity resolutions."""

    def invalidate_user(self, host_id: uuid.UUID | str, uid: int) -> None:
        """Invalidate cached user resolution for host_id and uid."""

    def invalidate_process(self, host_id: uuid.UUID | str, pid: int) -> None:
        """Invalidate cached process resolutions for host_id and pid."""


class NoOpIdentityResolver(IdentityResolver):
    """Safe no-op identity resolver for isolated unit tests.

    Leaves existing event attributes intact without database lookups.
    Preserves preset usernames and process IDs in pure unit tests.
    """

    def resolve_user(self, host_id: uuid.UUID | str, uid: int) -> str | None:
        return None

    def resolve_process(
        self,
        host_id: uuid.UUID | str,
        pid: int,
        timestamp: datetime,
        event_type: str | None = None,
    ) -> uuid.UUID | None:
        return None

    def resolve_event(self, event: NormalizedEvent) -> NormalizedEvent:
        return event


class DatabaseIdentityResolver(IdentityResolver):
    """PostgreSQL/SQLAlchemy database-backed identity resolver.

    Resolves UID to username using the host-scoped ``linux_users`` table,
    and resolves Linux PID to internal OSIRIS ``process_id`` using the
    ``processes`` table with strict time-bounded lifetime matching.

    Parameters
    ----------
    session:
        Active SQLAlchemy Session. Read-only queries are executed;
        the resolver never commits, flushes, or closes this session.
    cache_ttl:
        Time-to-live in seconds for cache entries (default: 60.0s).
        A value <= 0 disables caching.
    clock:
        Monotonic clock callable returning seconds as a float.
        Defaults to ``time.monotonic``. Can be overridden for testing.
    """

    def __init__(
        self,
        session: Session | None = None,
        *,
        cache_ttl: float = 60.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._session = session
        self._cache_ttl = cache_ttl
        self._clock = clock or time.monotonic

        # Cache structures
        # Key: (host_id, uid) -> _CachedUser
        self._user_cache: dict[tuple[uuid.UUID, int], _CachedUser] = {}
        # Key: (host_id, pid) -> list[_CachedProcess]
        self._process_cache: dict[tuple[uuid.UUID, int], list[_CachedProcess]] = {}

        # Telemetry counters
        self._user_cache_hits: int = 0
        self._user_cache_misses: int = 0
        self._process_cache_hits: int = 0
        self._process_cache_misses: int = 0

    @property
    def session(self) -> Session | None:
        """The active database session."""
        return self._session

    @session.setter
    def session(self, s: Session | None) -> None:
        """Update or bind the active database session."""
        self._session = s

    def set_session(self, session: Session | None) -> None:
        """Bind resolver to an active database session."""
        self._session = session

    @property
    def user_cache_hits(self) -> int:
        """Number of successful user cache hits."""
        return self._user_cache_hits

    @property
    def user_cache_misses(self) -> int:
        """Number of user cache misses."""
        return self._user_cache_misses

    @property
    def process_cache_hits(self) -> int:
        """Number of successful process cache hits."""
        return self._process_cache_hits

    @property
    def process_cache_misses(self) -> int:
        """Number of process cache misses."""
        return self._process_cache_misses

    def clear_cache(self) -> None:
        """Clear all cached entries and reset telemetry counters."""
        self._user_cache.clear()
        self._process_cache.clear()
        self._user_cache_hits = 0
        self._user_cache_misses = 0
        self._process_cache_hits = 0
        self._process_cache_misses = 0

    def invalidate_user(self, host_id: uuid.UUID | str, uid: int) -> None:
        """Invalidate cached user resolution for host_id and uid."""
        host_uuid = _ensure_uuid(host_id)
        self._user_cache.pop((host_uuid, uid), None)

    def invalidate_process(self, host_id: uuid.UUID | str, pid: int) -> None:
        """Invalidate cached process resolutions for host_id and pid."""
        host_uuid = _ensure_uuid(host_id)
        self._process_cache.pop((host_uuid, pid), None)

    def resolve_user(self, host_id: uuid.UUID | str, uid: int) -> str | None:
        """Resolve a host-scoped Linux UID to a username.

        Enforces:
        - Host scoping: only queries records where ``host_id == host_id``.
        - Username precedence: resolves username from ``linux_users``.
        - Safe null preservation: if not found or empty, returns None.
        - Safe handling of deleted/missing user records.
        - Caching with TTL and explicit invalidation.
        """
        if uid < 0:
            return None

        host_uuid = _ensure_uuid(host_id)
        key = (host_uuid, uid)
        now = self._clock()

        # Check cache if caching enabled
        if self._cache_ttl > 0 and key in self._user_cache:
            entry = self._user_cache[key]
            if now - entry.cached_at <= self._cache_ttl:
                self._user_cache_hits += 1
                return entry.username
            else:
                del self._user_cache[key]

        self._user_cache_misses += 1

        if self._session is None:
            return None

        # Query database: host-scoped uid
        stmt = select(LinuxUser.username).where(
            LinuxUser.host_id == host_uuid,
            LinuxUser.uid == uid,
        )
        row = self._session.execute(stmt).first()

        username: str | None = None
        if row is not None and row[0] is not None:
            stripped = row[0].strip()
            username = stripped if stripped else None

        if self._cache_ttl > 0:
            self._user_cache[key] = _CachedUser(username=username, cached_at=now)

        return username

    def resolve_process(
        self,
        host_id: uuid.UUID | str,
        pid: int,
        timestamp: datetime,
        event_type: str | None = None,
    ) -> uuid.UUID | None:
        """Resolve a Linux PID to an OSIRIS internal process UUID.

        Enforces:
        - Host scoping: only queries records where ``host_id == host_id``.
        - Lifetime conditions:
          ``process.started_at <= event.timestamp`` and
          ``(process.ended_at IS NULL OR event.timestamp <= process.ended_at)``.
        - Boundary handling: events exactly at ``started_at`` and ``ended_at`` match.
        - PID reuse safety: different process instances with the same PID
          are distinguished by time bounds.
        - Ambiguity handling: if multiple processes match (overlapping anomalies),
          returns None rather than arbitrarily selecting one.
        - Caching: caches process lifetimes; cache lookups always verify the event
          timestamp falls within the cached process's lifetime bounds.
        """
        if pid < 0:
            return None

        host_uuid = _ensure_uuid(host_id)
        ts = _ensure_utc(timestamp)
        if ts is None:
            return None

        key = (host_uuid, pid)
        now = self._clock()

        # Check cache if caching enabled
        if self._cache_ttl > 0 and key in self._process_cache:
            # Purge expired entries
            active = [
                p
                for p in self._process_cache[key]
                if now - p.cached_at <= self._cache_ttl
            ]

            # If event_type is "process.start", purge any cached processes for this PID
            # that started strictly before ts, because this PID is now being reused by a new process.
            if event_type == "process.start":
                active = [p for p in active if p.started_at >= ts]

            self._process_cache[key] = active

            # Find matching process lifetimes for this timestamp
            matches = [p for p in active if p.matches(ts, event_type)]

            if len(matches) == 1:
                self._process_cache_hits += 1
                return matches[0].id
            elif len(matches) > 1:
                # Disambiguate exact boundary by event_type
                if event_type == "process.start":
                    start_m = [p for p in matches if p.started_at == ts]
                    if len(start_m) == 1:
                        self._process_cache_hits += 1
                        return start_m[0].id
                elif event_type == "process.end":
                    end_m = [
                        p
                        for p in matches
                        if p.ended_at is not None and p.ended_at == ts
                    ]
                    if len(end_m) == 1:
                        self._process_cache_hits += 1
                        return end_m[0].id

                logger.warning(
                    "Ambiguous process resolution in cache for host %s, pid %s at %s (%d matches)",
                    host_uuid,
                    pid,
                    ts,
                    len(matches),
                )
                return None
            # If 0 matches in cache, fall through to query DB

        self._process_cache_misses += 1

        if self._session is None:
            return None

        # Query database with strict lifetime boundary conditions
        stmt = (
            select(Process.id, Process.started_at, Process.ended_at)
            .where(
                Process.host_id == host_uuid,
                Process.pid == pid,
                Process.started_at <= ts,
                or_(Process.ended_at.is_(None), ts <= Process.ended_at),
            )
            .order_by(Process.started_at.desc())
            .limit(3)
        )
        rows = self._session.execute(stmt).all()

        if not rows:
            return None

        def _record_cache_hit(
            proc_id: uuid.UUID, started: datetime, ended: datetime | None
        ) -> uuid.UUID:
            if self._cache_ttl > 0:
                s_utc = _ensure_utc(started)
                e_utc = _ensure_utc(ended)
                assert s_utc is not None
                cached_entry = _CachedProcess(
                    id=proc_id,
                    started_at=s_utc,
                    ended_at=e_utc,
                    cached_at=now,
                )
                existing = [
                    e
                    for e in self._process_cache.get(key, [])
                    if e.id != proc_id
                ]
                existing.append(cached_entry)
                self._process_cache[key] = existing
            return proc_id

        if len(rows) == 1:
            proc_id, started_at, ended_at = rows[0]
            return _record_cache_hit(proc_id, started_at, ended_at)

        elif len(rows) > 1:
            # Check if disambiguated by event_type (exact boundary resolution)
            if event_type == "process.start":
                start_matches = [
                    r for r in rows if _ensure_utc(r[1]) == ts
                ]
                if len(start_matches) == 1:
                    proc_id, started_at, ended_at = start_matches[0]
                    return _record_cache_hit(proc_id, started_at, ended_at)

            elif event_type == "process.end":
                end_matches = [
                    r for r in rows if r[2] is not None and _ensure_utc(r[2]) == ts
                ]
                if len(end_matches) == 1:
                    proc_id, started_at, ended_at = end_matches[0]
                    return _record_cache_hit(proc_id, started_at, ended_at)

            logger.warning(
                "Ambiguous process resolution in database for host %s, pid %s at %s (%d matches)",
                host_uuid,
                pid,
                ts,
                len(rows),
            )
            return None

    def resolve_event(self, event: NormalizedEvent) -> NormalizedEvent:
        """Apply authoritative database identity resolution to a normalized event.

        Resolves:
        - UID → username (if uid is present)
        - PID + timestamp → process_id (if pid is present)

        Leaves source-level ``pid`` and ``ppid`` intact.
        """
        updates: dict[str, Any] = {}

        if event.uid is not None:
            updates["username"] = self.resolve_user(event.host_id, event.uid)

        if event.pid is not None:
            updates["process_id"] = self.resolve_process(
                event.host_id,
                event.pid,
                event.timestamp,
                event_type=event.event_type,
            )

        if updates:
            return event.model_copy(update=updates)
        return event
