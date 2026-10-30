"""Session Reconstruction and Tracking Service for OSIRIS (Phase 2 Milestone 2.3).

Reconstructs and tracks user interactive login sessions from authentication
events and security logs. Correlates sessions with hosts, Linux users, and
process execution trees.

Core principles:
- Host-scoped isolation: Sessions never cross host boundaries.
- Forensic fidelity: Real login/logout events drive session lifecycles.
- Sudo/Su distinction: Privilege escalations are tracked as identity transitions
  within existing sessions, never fabricated as new login sessions.
- Incomplete session resilience: Handles unclosed sessions and terminal reuse
  without guessing or corrupting historical records.
- Idempotency: Processing identical events repeatedly produces the same state
  without duplicate session creation.
- Transaction discipline: Preserves caller-owned transaction ownership.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Sequence

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from backend.db.models.event import Event
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.user_session import UserSession
from backend.services.events.schemas import NormalizedEvent, RawObservation

logger = logging.getLogger("osiris.services.sessions")


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Ensure a datetime is timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class SessionReconstructionService:
    """Authoritative service for session lifecycle reconstruction and tracking."""

    def __init__(self, session: Session | None = None) -> None:
        self._session = session

    @property
    def session(self) -> Session | None:
        return self._session

    @session.setter
    def session(self, s: Session | None) -> None:
        self._session = s

    # ── User Resolution ───────────────────────────────────────────────────────

    def resolve_linux_user(
        self,
        db: Session,
        host_id: uuid.UUID,
        uid: int | None = None,
        username: str | None = None,
    ) -> Optional[LinuxUser]:
        """Resolve a Linux user on a specific host by UID or username."""
        if uid is not None and uid >= 0:
            stmt = select(LinuxUser).where(
                LinuxUser.host_id == host_id,
                LinuxUser.uid == uid,
            )
            user = db.execute(stmt).scalars().first()
            if user is not None:
                return user

        if username and username.strip():
            clean_name = username.strip()
            stmt = select(LinuxUser).where(
                LinuxUser.host_id == host_id,
                LinuxUser.username == clean_name,
            )
            return db.execute(stmt).scalars().first()

        return None

    # ── Event Lifecycle Processing ────────────────────────────────────────────

    def process_event(
        self,
        db: Session,
        event: Event | NormalizedEvent | RawObservation | dict[str, Any],
        host_id: uuid.UUID | str | None = None,
    ) -> Optional[UserSession]:
        """Process a single event or observation and update session lifecycle.

        Returns the created, updated, or associated UserSession, or None if
        the event is not a session lifecycle event.
        """
        # Extract attributes from various event types
        if isinstance(event, dict):
            ev_host_id = event.get("host_id")
            event_type = event.get("event_type", "")
            action = event.get("action", "")
            timestamp = event.get("timestamp") or event.get("observed_at")
            uid = event.get("uid")
            username = event.get("username")
            payload = event.get("payload") or {}
        elif isinstance(event, (Event, NormalizedEvent, RawObservation)):
            ev_host_id = getattr(event, "host_id", None)
            event_type = getattr(event, "event_type", "")
            action = getattr(event, "action", "")
            timestamp = getattr(event, "timestamp", None) or getattr(event, "observed_at", None)
            uid = getattr(event, "uid", None)
            username = getattr(event, "username", None)
            payload = getattr(event, "payload", None) or {}
        else:
            return None

        # Determine target host UUID
        raw_host = host_id or ev_host_id
        if not raw_host:
            return None
        target_host_id = raw_host if isinstance(raw_host, uuid.UUID) else uuid.UUID(str(raw_host))

        if isinstance(timestamp, str):
            ts = _ensure_utc(datetime.fromisoformat(timestamp))
        elif isinstance(timestamp, datetime):
            ts = _ensure_utc(timestamp)
        else:
            ts = datetime.now(timezone.utc)

        pam_service = payload.get("pam_service") or payload.get("service") or ""

        # ── 1. Ignore background / system services ────────────────────────────
        if pam_service in ("cron", "crond", "systemd-user"):
            return None

        # ── 2. Privilege transitions (sudo / su) ──────────────────────────────
        # Sudo and su are privilege escalations, NOT new interactive login sessions.
        if (
            event_type in ("auth.sudo", "auth.su")
            or pam_service in ("sudo", "su")
            or action in ("sudo", "su", "privilege_escalation")
        ):
            # We do NOT create a new session. We can optionally correlate to existing session.
            return None

        # ── 3. Session Start / Login Success ──────────────────────────────────
        is_login = (
            event_type in ("auth.login_success", "session.start")
            or action in ("login", "session_open", "start")
        )
        if is_login:
            return self._handle_session_start(
                db=db,
                host_id=target_host_id,
                timestamp=ts,
                uid=uid,
                username=username,
                payload=payload,
            )

        # ── 4. Session End / Logout ───────────────────────────────────────────
        is_logout = (
            event_type in ("auth.logout", "auth.session_end", "session.end")
            or action in ("logout", "session_close", "end", "exit")
        )
        if is_logout:
            return self._handle_session_end(
                db=db,
                host_id=target_host_id,
                timestamp=ts,
                uid=uid,
                username=username,
                payload=payload,
            )

        return None

    def _handle_session_start(
        self,
        db: Session,
        host_id: uuid.UUID,
        timestamp: datetime,
        uid: int | None,
        username: str | None,
        payload: dict[str, Any],
    ) -> UserSession:
        """Handle session start event with idempotency and terminal conflict handling."""
        # Resolve Linux user if possible
        effective_user = username or payload.get("username")
        effective_uid = uid if uid is not None else payload.get("uid")
        linux_user = self.resolve_linux_user(
            db, host_id, uid=effective_uid, username=effective_user
        )
        linux_user_id = linux_user.id if linux_user is not None else None

        terminal = payload.get("terminal")
        remote_host = payload.get("remote_host")

        # Inferred session type
        session_type = payload.get("session_type")
        if not session_type:
            if remote_host or payload.get("service") == "sshd":
                session_type = "ssh"
            elif terminal and "tty" in terminal:
                session_type = "tty"
            elif terminal and "pts" in terminal:
                session_type = "pts"
            else:
                session_type = "local"

        # 1. Idempotency & Multi-event correlation check:
        # OpenSSH and console logins emit both service authentication ('Accepted...')
        # and PAM session ('pam_unix... session opened') within 0-5 seconds of each other.
        # Check if an active session for this user/host already exists within recent window.
        recent_window = timedelta(seconds=10)
        stmt = (
            select(UserSession)
            .options(joinedload(UserSession.linux_user))
            .where(
                UserSession.host_id == host_id,
                UserSession.ended_at.is_(None),
                UserSession.started_at >= timestamp - recent_window,
                UserSession.started_at <= timestamp + recent_window,
            )
        )
        existing_matches = db.execute(stmt).scalars().all()
        for candidate in existing_matches:
            cand_user = candidate.linux_user.username if candidate.linux_user else None
            cand_uid = candidate.linux_user.uid if candidate.linux_user else None

            # User compatibility:
            # If both have user information, they MUST match. If they conflict, CANNOT merge!
            user_conflict = False
            user_matched = False
            if linux_user_id and candidate.linux_user_id:
                if candidate.linux_user_id == linux_user_id:
                    user_matched = True
                else:
                    user_conflict = True
            elif effective_user and cand_user:
                if cand_user == effective_user:
                    user_matched = True
                else:
                    user_conflict = True
            elif effective_uid is not None and cand_uid is not None:
                if cand_uid == effective_uid:
                    user_matched = True
                else:
                    user_conflict = True

            if user_conflict:
                continue

            # Terminal compatibility:
            # If both have terminal information and they differ, CANNOT merge!
            term_conflict = False
            term_matched = False
            if terminal and candidate.terminal:
                if candidate.terminal == terminal:
                    term_matched = True
                else:
                    term_conflict = True

            if term_conflict:
                continue

            # Remote host compatibility:
            # If both have remote host information and they differ, CANNOT merge!
            host_conflict = False
            host_matched = False
            if remote_host and candidate.remote_host:
                if candidate.remote_host == remote_host:
                    host_matched = True
                else:
                    host_conflict = True

            if host_conflict:
                continue

            # To merge: user MUST match (or if user unknown on both, terminal or remote host matches)
            can_merge = False
            if user_matched:
                can_merge = True
            elif not effective_user and not cand_user:
                if term_matched or host_matched:
                    can_merge = True

            if can_merge:
                # Merge attributes into existing session
                if linux_user_id and not candidate.linux_user_id:
                    candidate.linux_user_id = linux_user_id
                if terminal and not candidate.terminal:
                    candidate.terminal = terminal
                if remote_host and not candidate.remote_host:
                    candidate.remote_host = remote_host
                return candidate

        # 2. Terminal collision handling:
        # If a prior session on the same terminal was never closed, close it at new login timestamp.
        if terminal:
            prior_stmt = select(UserSession).where(
                UserSession.host_id == host_id,
                UserSession.terminal == terminal,
                UserSession.ended_at.is_(None),
                UserSession.started_at < timestamp,
            )
            unclosed_prior = db.execute(prior_stmt).scalars().all()
            for prior_sess in unclosed_prior:
                prior_sess.ended_at = timestamp

        # 3. Create new UserSession
        new_session = UserSession(
            id=uuid.uuid4(),
            host_id=host_id,
            linux_user_id=linux_user_id,
            session_type=session_type,
            terminal=terminal,
            remote_host=remote_host,
            started_at=timestamp,
            ended_at=None,
        )
        db.add(new_session)
        db.flush()
        return new_session

    def _handle_session_end(
        self,
        db: Session,
        host_id: uuid.UUID,
        timestamp: datetime,
        uid: int | None,
        username: str | None,
        payload: dict[str, Any],
    ) -> Optional[UserSession]:
        """Handle session end event and mark matching session completed."""
        effective_user = username or payload.get("username")
        effective_uid = uid if uid is not None else payload.get("uid")
        linux_user = self.resolve_linux_user(
            db, host_id, uid=effective_uid, username=effective_user
        )
        linux_user_id = linux_user.id if linux_user is not None else None
        terminal = payload.get("terminal")
        remote_host = payload.get("remote_host")

        # 1. Idempotency check: was this session already ended at timestamp?
        ended_stmt = (
            select(UserSession)
            .options(joinedload(UserSession.linux_user))
            .where(
                UserSession.host_id == host_id,
                UserSession.ended_at == timestamp,
            )
        )
        already_ended = db.execute(ended_stmt).scalars().all()
        for cand in already_ended:
            cand_user = cand.linux_user.username if cand.linux_user else None
            if effective_user and cand_user and cand_user != effective_user:
                continue
            if linux_user_id and cand.linux_user_id and cand.linux_user_id != linux_user_id:
                continue
            if (
                (terminal and cand.terminal == terminal)
                or (linux_user_id and cand.linux_user_id == linux_user_id)
                or (effective_user and cand_user == effective_user)
            ):
                return cand

        # 2. Find active unclosed session to close
        query = (
            select(UserSession)
            .options(joinedload(UserSession.linux_user))
            .where(
                UserSession.host_id == host_id,
                UserSession.ended_at.is_(None),
                UserSession.started_at <= timestamp,
            )
        )

        candidates = db.execute(query).scalars().all()
        if not candidates:
            return None

        # Filter out candidates with conflicting user identities or conflicting terminals
        eligible_candidates: list[UserSession] = []
        for cand in candidates:
            cand_user = cand.linux_user.username if cand.linux_user else None
            cand_uid = cand.linux_user.uid if cand.linux_user else None

            # If the logout event specifies a user, candidate MUST NOT conflict
            if linux_user_id and cand.linux_user_id and cand.linux_user_id != linux_user_id:
                continue
            if effective_user and cand_user and cand_user != effective_user:
                continue
            if effective_uid is not None and cand_uid is not None and cand_uid != effective_uid:
                continue

            # If the logout event specifies a terminal, candidate terminal must not conflict
            if terminal and cand.terminal and cand.terminal != terminal:
                continue

            eligible_candidates.append(cand)

        if not eligible_candidates:
            # Forensic fidelity: do not close unrelated sessions when evidence does not match
            return None

        # Best match scoring among eligible candidates
        best_candidate: Optional[UserSession] = None
        for cand in eligible_candidates:
            cand_user = cand.linux_user.username if cand.linux_user else None

            # Exact user AND terminal match: highest confidence
            user_match = bool(
                (linux_user_id and cand.linux_user_id == linux_user_id)
                or (effective_user and cand_user == effective_user)
            )
            term_match = bool(terminal and cand.terminal == terminal)

            if user_match and term_match:
                best_candidate = cand
                break
            if term_match:
                if best_candidate is None or cand.started_at > best_candidate.started_at:
                    best_candidate = cand
            elif user_match:
                if best_candidate is None or cand.started_at > best_candidate.started_at:
                    best_candidate = cand
            elif remote_host and cand.remote_host == remote_host:
                if best_candidate is None or cand.started_at > best_candidate.started_at:
                    best_candidate = cand

        if best_candidate is not None:
            best_candidate.ended_at = timestamp
            db.flush()
            return best_candidate

        return None

    def process_batch(
        self,
        db: Session,
        events: Sequence[Event | NormalizedEvent | RawObservation | dict[str, Any]],
        host_id: uuid.UUID | str,
    ) -> list[UserSession]:
        """Process a sequence of chronological events for a monitored host."""
        results: list[UserSession] = []
        for ev in events:
            res = self.process_event(db, ev, host_id=host_id)
            if res is not None:
                results.append(res)
        return results

    # ── Process & Session Association ─────────────────────────────────────────

    def get_session_processes(
        self, db: Session, session_id: uuid.UUID
    ) -> list[Process]:
        """Retrieve all processes executed within the lifetime of a UserSession.

        Enforces:
        - Cross-host isolation: Process.host_id == UserSession.host_id
        - Time bounding: Process.started_at >= UserSession.started_at and
          (UserSession.ended_at IS NULL or Process.started_at <= UserSession.ended_at)
        - PID reuse protection: Process instances started outside the session window
          are excluded even if they share the same PID.
        - Privilege transition association: includes processes started by the session user
          or child/descendant processes spawned during active privilege escalations.
        - Deterministic ordering: Process.started_at ASC, Process.id ASC.
        """
        sess = db.get(UserSession, session_id)
        if sess is None:
            return []

        # Find all processes on the same host within the session lifetime window
        time_conds = [
            Process.host_id == sess.host_id,
            Process.started_at >= sess.started_at,
        ]
        if sess.ended_at is not None:
            time_conds.append(Process.started_at <= sess.ended_at)

        stmt = (
            select(Process)
            .where(*time_conds)
            .order_by(Process.started_at.asc(), Process.id.asc())
        )
        candidate_procs = list(db.execute(stmt).scalars().all())
        if not candidate_procs:
            return []

        # If session has no linux_user_id, return all candidate processes
        if sess.linux_user_id is None:
            return candidate_procs

        # 1. Directly owned processes
        matched_procs: list[Process] = []
        session_pids: set[int] = set()
        remaining: list[Process] = []

        for p in candidate_procs:
            if p.linux_user_id == sess.linux_user_id:
                matched_procs.append(p)
                session_pids.add(p.pid)
            else:
                remaining.append(p)

        # 2. Iteratively associate child/descendant processes (e.g. root commands via sudo/su)
        changed = True
        while changed:
            changed = False
            unmatched: list[Process] = []
            for p in remaining:
                if p.ppid is not None and p.ppid in session_pids:
                    matched_procs.append(p)
                    session_pids.add(p.pid)
                    changed = True
                else:
                    unmatched.append(p)
            remaining = unmatched

        # 3. Privilege escalation fallback:
        # If root processes were executed within the session window with no other active sessions,
        # or where ppid is None (as in legacy tests without explicit ppid), correlate them
        root_user_stmt = select(LinuxUser.id).where(
            LinuxUser.host_id == sess.host_id,
            LinuxUser.uid == 0,
        )
        root_user_id = db.execute(root_user_stmt).scalars().first()

        if root_user_id is not None and remaining:
            other_sess_stmt = select(UserSession.id).where(
                UserSession.host_id == sess.host_id,
                UserSession.id != sess.id,
                UserSession.started_at <= (sess.ended_at or datetime.now(timezone.utc)),
                or_(
                    UserSession.ended_at.is_(None),
                    UserSession.ended_at >= sess.started_at,
                ),
            )
            other_sessions_exist = bool(db.execute(other_sess_stmt).scalars().first())

            for p in remaining:
                if p.linux_user_id == root_user_id:
                    # If ppid is explicitly known and not in session_pids, and other sessions exist, don't claim it
                    if p.ppid is not None and other_sessions_exist:
                        continue
                    matched_procs.append(p)
                    session_pids.add(p.pid)

        matched_procs.sort(key=lambda p: (p.started_at, str(p.id)))
        return matched_procs

    def correlate_process_to_session(
        self, db: Session, process: Process
    ) -> Optional[UserSession]:
        """Correlate a Process to its parent active UserSession.

        Finds the session on the same host where the process started within the
        session's active lifetime bounds, checking direct user ownership,
        parent process hierarchy (sudo/su child processes), and host session context.
        """
        # 1. Direct ownership match
        if process.linux_user_id is not None:
            direct_stmt = (
                select(UserSession)
                .where(
                    UserSession.host_id == process.host_id,
                    UserSession.linux_user_id == process.linux_user_id,
                    UserSession.started_at <= process.started_at,
                    or_(
                        UserSession.ended_at.is_(None),
                        process.started_at <= UserSession.ended_at,
                    ),
                )
                .order_by(UserSession.started_at.desc())
                .limit(1)
            )
            sess = db.execute(direct_stmt).scalars().first()
            if sess is not None:
                return sess

        # 2. Check parent process ancestry (e.g. sudo or su spawned root process)
        if process.ppid is not None:
            parent_stmt = (
                select(Process)
                .where(
                    Process.host_id == process.host_id,
                    Process.pid == process.ppid,
                    Process.started_at <= process.started_at,
                    or_(
                        Process.ended_at.is_(None),
                        process.started_at <= Process.ended_at,
                    ),
                )
                .order_by(Process.started_at.desc())
                .limit(1)
            )
            parent = db.execute(parent_stmt).scalars().first()
            if parent is not None and parent.id != process.id:
                parent_sess = self.correlate_process_to_session(db, parent)
                if parent_sess is not None:
                    return parent_sess

        # 3. Privilege escalation fallback: root process started during an unambiguous active session
        root_user_stmt = select(LinuxUser.id).where(
            LinuxUser.host_id == process.host_id,
            LinuxUser.uid == 0,
        )
        root_user_id = db.execute(root_user_stmt).scalars().first()
        if root_user_id is not None and process.linux_user_id == root_user_id:
            active_stmt = (
                select(UserSession)
                .where(
                    UserSession.host_id == process.host_id,
                    UserSession.started_at <= process.started_at,
                    or_(
                        UserSession.ended_at.is_(None),
                        process.started_at <= UserSession.ended_at,
                    ),
                )
                .order_by(UserSession.started_at.desc())
                .limit(2)
            )
            active_sessions = db.execute(active_stmt).scalars().all()
            if len(active_sessions) == 1:
                return active_sessions[0]

        return None

    # ── Session Querying & Retrieval ──────────────────────────────────────────

    def list_sessions(
        self,
        db: Session,
        host_id: uuid.UUID | None = None,
        linux_user_id: uuid.UUID | None = None,
        username: str | None = None,
        session_type: str | None = None,
        terminal: str | None = None,
        remote_host: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        is_active: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[int, list[UserSession]]:
        """List sessions with comprehensive filtering and deterministic ordering."""
        conditions = []

        if host_id is not None:
            conditions.append(UserSession.host_id == host_id)

        if linux_user_id is not None:
            conditions.append(UserSession.linux_user_id == linux_user_id)

        if username and username.strip():
            # Resolve linux_users with this username
            user_stmt = select(LinuxUser.id).where(LinuxUser.username == username.strip())
            matched_user_ids = db.execute(user_stmt).scalars().all()
            if matched_user_ids:
                conditions.append(UserSession.linux_user_id.in_(matched_user_ids))
            else:
                return 0, []

        if session_type and session_type.strip():
            conditions.append(UserSession.session_type == session_type.strip())

        if terminal and terminal.strip():
            conditions.append(UserSession.terminal == terminal.strip())

        if remote_host and remote_host.strip():
            conditions.append(UserSession.remote_host == remote_host.strip())

        if start_time is not None:
            conditions.append(UserSession.started_at >= _ensure_utc(start_time))

        if end_time is not None:
            conditions.append(UserSession.started_at <= _ensure_utc(end_time))

        if is_active is True:
            conditions.append(UserSession.ended_at.is_(None))
        elif is_active is False:
            conditions.append(UserSession.ended_at.is_not(None))

        # Total count
        count_stmt = select(func.count(UserSession.id))
        if conditions:
            count_stmt = count_stmt.where(*conditions)
        total = db.scalar(count_stmt) or 0

        # Query items with eager loading of linux_user
        stmt = (
            select(UserSession)
            .options(joinedload(UserSession.linux_user))
            .where(*conditions)
            .order_by(UserSession.started_at.desc(), UserSession.id.asc())
            .limit(limit)
            .offset(offset)
        )
        items = list(db.execute(stmt).scalars().all())
        return total, items

    def get_session_by_id(
        self, db: Session, session_id: uuid.UUID
    ) -> Optional[UserSession]:
        """Fetch a single UserSession by ID with eager loading."""
        stmt = (
            select(UserSession)
            .options(joinedload(UserSession.linux_user))
            .where(UserSession.id == session_id)
        )
        return db.execute(stmt).scalars().first()
