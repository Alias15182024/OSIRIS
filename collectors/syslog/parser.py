"""Syslog and authentication log parsing for OSIRIS (Phase 2 Milestone 2.3).

Parses Linux authentication and system logs (e.g. `/var/log/auth.log`,
`/var/log/secure`, `/var/log/syslog`, or systemd journal logs) into
structured observation dictionaries suitable for the OSIRIS Event Processing
Layer.

Supported log formats:
- RFC 3164 (traditional syslog): ``Mmm dd hh:mm:ss hostname program[pid]: msg``
- RFC 5424 / ISO 8601: ``YYYY-MM-DDTHH:MM:SS[.ffffff][+HH:MM|Z] hostname program[pid]: msg``

Supported event categories:
- SSH authentication & session lifecycle (sshd)
- Local console logins & sessions (login, getty)
- Sudo command execution & privilege elevation (sudo)
- Su identity transitions (su)
- PAM session transitions (pam_unix for sshd, login, sudo, su, systemd-user)
- Systemd logind session lifecycle (systemd-logind)
- Fallback generic security/system events (syslog.event)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

# Month names mapping for RFC 3164 syslog dates
MONTH_NAMES = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Regex for RFC 5424 / ISO 8601 timestamp at beginning of line
ISO_TS_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(\S+)\s+"  # hostname
    r"([^:\s\[]+)(?:\[(\d+)\])?:\s+"  # program[pid]:
    r"(.*)$"  # message
)

# Regex for RFC 3164 timestamp at beginning of line
RFC3164_TS_PATTERN = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"  # hostname
    r"([^:\s\[]+)(?:\[(\d+)\])?:\s+"  # program[pid]:
    r"(.*)$"  # message
)

# Alternative line format without hostname (some local log formats)
RFC3164_NO_HOST_PATTERN = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"([^:\s\[]+)(?:\[(\d+)\])?:\s+"  # program[pid]:
    r"(.*)$"  # message
)

# --- Pattern matchers for specific authentication actions ---

# SSH Accepted
# e.g.: "Accepted publickey for alice from 192.168.1.50 port 54321 ssh2: RSA SHA256:..."
# e.g.: "Accepted password for bob from 10.0.0.1 port 43210 ssh2"
SSH_ACCEPTED_RE = re.compile(
    r"^Accepted\s+(?P<auth_method>\S+)\s+for\s+(?P<username>\S+)\s+from\s+(?P<remote_host>\S+)\s+port\s+(?P<port>\d+)(?:\s+(?P<protocol>\S+)(?::\s+(?P<key_info>.*))?)?"
)

# SSH Failed password
# e.g.: "Failed password for invalid user admin from 192.168.1.99 port 43210 ssh2"
# e.g.: "Failed password for alice from 192.168.1.99 port 43210 ssh2"
SSH_FAILED_RE = re.compile(
    r"^Failed\s+(?P<auth_method>\S+)\s+for\s+(?:invalid\s+user\s+)?(?P<username>\S+)\s+from\s+(?P<remote_host>\S+)\s+port\s+(?P<port>\d+)"
)

# SSH Invalid user
# e.g.: "Invalid user test from 192.168.1.99 port 43210"
SSH_INVALID_USER_RE = re.compile(
    r"^Invalid\s+user\s+(?P<username>\S+)\s+from\s+(?P<remote_host>\S+)\s+port\s+(?P<port>\d+)"
)

# PAM session opened
# e.g.: "pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)"
# e.g.: "pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)"
# e.g.: "pam_unix(login:session): session opened for user bob(uid=1001) by LOGIN(uid=0)"
PAM_SESSION_OPENED_RE = re.compile(
    r"^pam_unix\((?P<service>[^:]+):session\):\s+session\s+opened\s+for\s+user\s+(?P<username>\S+?)(?:\(uid=(?P<uid>\d+)\))?(?:\s+by\s+(?P<by_user>\S*?)(?:\(uid=(?P<by_uid>\d+)\))?)?$"
)

# PAM session closed
# e.g.: "pam_unix(sshd:session): session closed for user alice"
# e.g.: "pam_unix(sudo:session): session closed for user root(uid=0)"
PAM_SESSION_CLOSED_RE = re.compile(
    r"^pam_unix\((?P<service>[^:]+):session\):\s+session\s+closed\s+for\s+user\s+(?P<username>\S+?)(?:\(uid=(?P<uid>\d+)\))?$"
)

# Sudo command execution
# e.g.: "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
# e.g.: "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; GROUP=root ; COMMAND=/bin/bash"
SUDO_COMMAND_RE = re.compile(
    r"^\s*(?P<source_user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>[^;]+?)\s*;\s*USER=(?P<target_user>\S+)\s*;.*?\bCOMMAND=(?P<command>.*)$"
)

# Su identity switch
# e.g.: "(to root) alice on pts/0"
# e.g.: "Successful su for root by alice"
# e.g.: "+ pts/0 alice:root"
# e.g.: "FAILED SU (to root) alice on pts/0"
SU_TO_RE = re.compile(
    r"^\(to\s+(?P<target_user>\S+)\)\s+(?P<source_user>\S+)\s+on\s+(?P<tty>\S+)"
)
SU_SUCCESS_RE = re.compile(
    r"^Successful\s+su\s+for\s+(?P<target_user>\S+)\s+by\s+(?P<source_user>\S+)"
)
SU_PLUS_RE = re.compile(
    r"^\+\s+(?P<tty>\S+)\s+(?P<source_user>\S+):(?P<target_user>\S+)"
)
SU_FAILED_RE = re.compile(
    r"^FAILED\s+SU\s+\(to\s+(?P<target_user>\S+)\)\s+(?P<source_user>\S+)\s+on\s+(?P<tty>\S+)"
)

# Login console
# e.g.: "Accepted password for bob on tty1"
# e.g.: "FAILED LOGIN (1) on '/dev/tty1' FOR 'unknown', Authentication failure"
LOGIN_ACCEPTED_RE = re.compile(
    r"^Accepted\s+(?P<auth_method>\S+)\s+for\s+(?P<username>\S+)\s+on\s+(?P<tty>\S+)"
)
LOGIN_FAILED_RE = re.compile(
    r"^FAILED\s+LOGIN\s+\(\d+\)\s+on\s+'(?P<tty>[^']+)'\s+FOR\s+'(?P<username>[^']*)'"
)

# Systemd logind
# e.g.: "New session 42 of user alice."
# e.g.: "Removed session 42."
SYSTEMD_NEW_SESSION_RE = re.compile(
    r"^New\s+session\s+(?P<session_id>[^\s.]+)\s+of\s+user\s+(?P<username>[^\s.]+)\.?$"
)
SYSTEMD_REMOVED_SESSION_RE = re.compile(
    r"^Removed\s+session\s+(?P<session_id>[^\s.]+)\.?$"
)


@dataclass
class ParsedLogRecord:
    """Structured representation of a parsed syslog / authentication log line."""

    timestamp: datetime
    hostname: Optional[str]
    program: str
    pid: Optional[int]
    raw_message: str
    event_type: str
    action: str
    severity: str
    username: Optional[str] = None
    uid: Optional[int] = None
    terminal: Optional[str] = None
    remote_host: Optional[str] = None
    session_type: Optional[str] = None
    success: Optional[bool] = None
    target_user: Optional[str] = None
    source_user: Optional[str] = None
    command: Optional[str] = None
    payload: dict[str, Any] = field(default_factory=dict)

    def to_observation_dict(self, host_id: str) -> dict[str, Any]:
        """Convert to a dictionary matching the RawObservation schema."""
        out_payload = dict(self.payload)
        out_payload["raw_message"] = self.raw_message
        out_payload["program"] = self.program
        if self.hostname:
            out_payload["hostname"] = self.hostname
        if self.terminal:
            out_payload["terminal"] = self.terminal
        if self.remote_host:
            out_payload["remote_host"] = self.remote_host
        if self.session_type:
            out_payload["session_type"] = self.session_type
        if self.target_user:
            out_payload["target_user"] = self.target_user
        if self.source_user:
            out_payload["source_user"] = self.source_user
        if self.command:
            out_payload["command"] = self.command

        return {
            "source": "syslog",
            "host_id": host_id,
            "event_type": self.event_type,
            "action": self.action,
            "severity": self.severity,
            "observed_at": self.timestamp.isoformat(),
            "uid": self.uid,
            "username": self.username,
            "pid": self.pid,
            "command": self.command,
            "success": self.success,
            "payload": out_payload,
        }


class SyslogParser:
    """Parser for syslog and authentication log lines."""

    def __init__(self, default_year: int | None = None) -> None:
        self.default_year = (
            default_year
            if default_year is not None
            else datetime.now(timezone.utc).year
        )

    def parse_timestamp_rfc3164(
        self, ts_str: str, reference_dt: datetime | None = None
    ) -> datetime:
        """Parse RFC 3164 timestamp ('Oct 30 14:22:01') into a UTC datetime.

        Infers the year using the reference datetime (default: current UTC time).
        Handles year rollover around New Year's Eve (e.g. December logs read in January).
        """
        ref = reference_dt or datetime.now(timezone.utc)
        parts = ts_str.split()
        if len(parts) != 3:
            raise ValueError(f"Invalid RFC 3164 timestamp: {ts_str!r}")

        month_str, day_str, time_str = parts
        month = MONTH_NAMES.get(month_str)
        if month is None:
            raise ValueError(f"Unknown month {month_str!r} in timestamp {ts_str!r}")

        day = int(day_str)
        h, m, s = (int(x) for x in time_str.split(":"))

        year = self.default_year or ref.year
        # Handle New Year's rollover: if ref is January and log is December, log was previous year
        if ref.month == 1 and month == 12:
            year -= 1
        # If ref is December and log is January, log is next year
        elif ref.month == 12 and month == 1:
            year += 1

        return datetime(year, month, day, h, m, s, tzinfo=timezone.utc)

    def parse_timestamp_iso(self, ts_str: str) -> datetime:
        """Parse RFC 5424 / ISO 8601 timestamp string into a UTC datetime."""
        clean_ts = ts_str.strip().replace(" ", "T")
        # Normalize colon in timezone offset if needed (e.g., +00:00 vs +0000)
        dt = datetime.fromisoformat(clean_ts)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def parse_line(
        self, line: str, reference_dt: datetime | None = None
    ) -> Optional[ParsedLogRecord]:
        """Parse a single syslog log line.

        Returns None if the line is empty or purely whitespace.
        For valid lines, extracts timestamp, program, pid, and message,
        then classifies into specialized authentication/session events.
        """
        raw = line.strip()
        if not raw:
            return None

        # 1. Try ISO 8601 format
        match = ISO_TS_PATTERN.match(raw)
        if match:
            ts_str, hostname, program, pid_str, msg = match.groups()
            try:
                ts = self.parse_timestamp_iso(ts_str)
            except Exception:
                ts = reference_dt or datetime.now(timezone.utc)
            pid = int(pid_str) if pid_str else None
            return self._classify_message(ts, hostname, program, pid, msg)

        # 2. Try RFC 3164 with hostname
        match = RFC3164_TS_PATTERN.match(raw)
        if match:
            ts_str, hostname, program, pid_str, msg = match.groups()
            try:
                ts = self.parse_timestamp_rfc3164(ts_str, reference_dt)
            except Exception:
                ts = reference_dt or datetime.now(timezone.utc)
            pid = int(pid_str) if pid_str else None
            return self._classify_message(ts, hostname, program, pid, msg)

        # 3. Try RFC 3164 without hostname
        match = RFC3164_NO_HOST_PATTERN.match(raw)
        if match:
            ts_str, program, pid_str, msg = match.groups()
            try:
                ts = self.parse_timestamp_rfc3164(ts_str, reference_dt)
            except Exception:
                ts = reference_dt or datetime.now(timezone.utc)
            pid = int(pid_str) if pid_str else None
            return self._classify_message(ts, None, program, pid, msg)

        # 4. Fallback: line without recognizable syslog header
        now = reference_dt or datetime.now(timezone.utc)
        return ParsedLogRecord(
            timestamp=now,
            hostname=None,
            program="syslog",
            pid=None,
            raw_message=raw,
            event_type="syslog.event",
            action="syslog",
            severity="info",
            payload={"raw_line": raw},
        )

    def _classify_message(
        self,
        ts: datetime,
        hostname: Optional[str],
        program: str,
        pid: Optional[int],
        msg: str,
    ) -> ParsedLogRecord:
        """Classify message payload into specialized authentication or security events."""
        prog = program.lower()

        # ── SSHD Events ───────────────────────────────────────────────────────
        if prog == "sshd":
            # SSH Accepted
            m = SSH_ACCEPTED_RE.match(msg)
            if m:
                groups = m.groupdict()
                username = groups["username"]
                remote_host = groups["remote_host"]
                auth_method = groups["auth_method"]
                port = int(groups["port"]) if groups.get("port") else None
                return ParsedLogRecord(
                    timestamp=ts,
                    hostname=hostname,
                    program=program,
                    pid=pid,
                    raw_message=msg,
                    event_type="auth.login_success",
                    action="login",
                    severity="info",
                    username=username,
                    remote_host=remote_host,
                    session_type="ssh",
                    success=True,
                    payload={
                        "auth_method": auth_method,
                        "port": port,
                        "service": "sshd",
                    },
                )

            # SSH Failed password
            m = SSH_FAILED_RE.match(msg)
            if m:
                groups = m.groupdict()
                username = groups["username"]
                remote_host = groups["remote_host"]
                auth_method = groups["auth_method"]
                port = int(groups["port"]) if groups.get("port") else None
                return ParsedLogRecord(
                    timestamp=ts,
                    hostname=hostname,
                    program=program,
                    pid=pid,
                    raw_message=msg,
                    event_type="auth.login_failure",
                    action="failed_login",
                    severity="medium",
                    username=username,
                    remote_host=remote_host,
                    session_type="ssh",
                    success=False,
                    payload={
                        "auth_method": auth_method,
                        "port": port,
                        "service": "sshd",
                    },
                )

            # SSH Invalid user
            m = SSH_INVALID_USER_RE.match(msg)
            if m:
                groups = m.groupdict()
                username = groups["username"]
                remote_host = groups["remote_host"]
                port = int(groups["port"]) if groups.get("port") else None
                return ParsedLogRecord(
                    timestamp=ts,
                    hostname=hostname,
                    program=program,
                    pid=pid,
                    raw_message=msg,
                    event_type="auth.login_failure",
                    action="failed_login",
                    severity="medium",
                    username=username,
                    remote_host=remote_host,
                    session_type="ssh",
                    success=False,
                    payload={
                        "port": port,
                        "reason": "invalid_user",
                        "service": "sshd",
                    },
                )

        # ── PAM Unix Sessions (sshd, sudo, su, login, systemd-user) ───────────
        m = PAM_SESSION_OPENED_RE.match(msg)
        if m:
            groups = m.groupdict()
            service = groups["service"]
            username = groups["username"]
            uid = int(groups["uid"]) if groups.get("uid") is not None else None
            by_user = groups.get("by_user") or None
            by_uid = int(groups["by_uid"]) if groups.get("by_uid") is not None else None

            # Distinguish privilege elevation (sudo/su) vs interactive login session (sshd/login)
            if service in ("sudo", "su"):
                event_type = f"auth.{service}"
                action = "privilege_escalation"
                severity = "low"
                return ParsedLogRecord(
                    timestamp=ts,
                    hostname=hostname,
                    program=program,
                    pid=pid,
                    raw_message=msg,
                    event_type=event_type,
                    action=action,
                    severity=severity,
                    username=by_user or username,
                    uid=by_uid if by_uid is not None else uid,
                    target_user=username,
                    source_user=by_user,
                    success=True,
                    payload={
                        "pam_service": service,
                        "target_uid": uid,
                        "source_uid": by_uid,
                        "session_lifecycle": "opened",
                    },
                )

            # Interactive login session open
            session_type = "ssh" if service == "sshd" else ("tty" if service == "login" else "local")
            return ParsedLogRecord(
                timestamp=ts,
                hostname=hostname,
                program=program,
                pid=pid,
                raw_message=msg,
                event_type="auth.login_success",
                action="session_open",
                severity="info",
                username=username,
                uid=uid,
                session_type=session_type,
                success=True,
                payload={
                    "pam_service": service,
                    "opened_by": by_user,
                    "session_lifecycle": "opened",
                },
            )

        m = PAM_SESSION_CLOSED_RE.match(msg)
        if m:
            groups = m.groupdict()
            service = groups["service"]
            username = groups["username"]
            uid = int(groups["uid"]) if groups.get("uid") is not None else None

            if service in ("sudo", "su"):
                return ParsedLogRecord(
                    timestamp=ts,
                    hostname=hostname,
                    program=program,
                    pid=pid,
                    raw_message=msg,
                    event_type=f"auth.{service}",
                    action="session_close",
                    severity="info",
                    username=username,
                    uid=uid,
                    target_user=username,
                    success=True,
                    payload={
                        "pam_service": service,
                        "session_lifecycle": "closed",
                    },
                )

            return ParsedLogRecord(
                timestamp=ts,
                hostname=hostname,
                program=program,
                pid=pid,
                raw_message=msg,
                event_type="auth.logout",
                action="session_close",
                severity="info",
                username=username,
                uid=uid,
                success=True,
                payload={
                    "pam_service": service,
                    "session_lifecycle": "closed",
                },
            )

        # ── Sudo Command Execution ────────────────────────────────────────────
        if prog == "sudo":
            m = SUDO_COMMAND_RE.match(msg)
            if m:
                groups = m.groupdict()
                src_user = groups["source_user"]
                tty = groups["tty"]
                pwd = groups["pwd"]
                target_user = groups["target_user"]
                command = groups["command"]
                return ParsedLogRecord(
                    timestamp=ts,
                    hostname=hostname,
                    program=program,
                    pid=pid,
                    raw_message=msg,
                    event_type="auth.sudo",
                    action="sudo",
                    severity="low",
                    username=src_user,
                    terminal=tty,
                    target_user=target_user,
                    source_user=src_user,
                    command=command,
                    success=True,
                    payload={
                        "pwd": pwd,
                        "terminal": tty,
                        "target_user": target_user,
                        "source_user": src_user,
                        "command": command,
                    },
                )

        # ── Su Transitions ────────────────────────────────────────────────────
        if prog == "su":
            m = SU_TO_RE.match(msg)
            if m:
                groups = m.groupdict()
                target_user = groups["target_user"]
                source_user = groups["source_user"]
                tty = groups["tty"]
                return ParsedLogRecord(
                    timestamp=ts,
                    hostname=hostname,
                    program=program,
                    pid=pid,
                    raw_message=msg,
                    event_type="auth.su",
                    action="su",
                    severity="info",
                    username=source_user,
                    terminal=tty,
                    target_user=target_user,
                    source_user=source_user,
                    success=True,
                    payload={"terminal": tty},
                )

            m = SU_SUCCESS_RE.match(msg)
            if m:
                groups = m.groupdict()
                target_user = groups["target_user"]
                source_user = groups["source_user"]
                return ParsedLogRecord(
                    timestamp=ts,
                    hostname=hostname,
                    program=program,
                    pid=pid,
                    raw_message=msg,
                    event_type="auth.su",
                    action="su",
                    severity="info",
                    username=source_user,
                    target_user=target_user,
                    source_user=source_user,
                    success=True,
                    payload={"target_user": target_user, "source_user": source_user},
                )

            m = SU_PLUS_RE.match(msg)
            if m:
                groups = m.groupdict()
                tty = groups["tty"]
                source_user = groups["source_user"]
                target_user = groups["target_user"]
                return ParsedLogRecord(
                    timestamp=ts,
                    hostname=hostname,
                    program=program,
                    pid=pid,
                    raw_message=msg,
                    event_type="auth.su",
                    action="su",
                    severity="info",
                    username=source_user,
                    terminal=tty,
                    target_user=target_user,
                    source_user=source_user,
                    success=True,
                    payload={"terminal": tty},
                )

            m = SU_FAILED_RE.match(msg)
            if m:
                groups = m.groupdict()
                target_user = groups["target_user"]
                source_user = groups["source_user"]
                tty = groups["tty"]
                return ParsedLogRecord(
                    timestamp=ts,
                    hostname=hostname,
                    program=program,
                    pid=pid,
                    raw_message=msg,
                    event_type="auth.su",
                    action="su_failure",
                    severity="medium",
                    username=source_user,
                    terminal=tty,
                    target_user=target_user,
                    source_user=source_user,
                    success=False,
                    payload={"terminal": tty},
                )

        # ── Local Login Console ───────────────────────────────────────────────
        if prog == "login":
            m = LOGIN_ACCEPTED_RE.match(msg)
            if m:
                groups = m.groupdict()
                username = groups["username"]
                tty = groups["tty"]
                auth_method = groups["auth_method"]
                return ParsedLogRecord(
                    timestamp=ts,
                    hostname=hostname,
                    program=program,
                    pid=pid,
                    raw_message=msg,
                    event_type="auth.login_success",
                    action="login",
                    severity="info",
                    username=username,
                    terminal=tty,
                    session_type="tty",
                    success=True,
                    payload={"auth_method": auth_method, "terminal": tty},
                )

            m = LOGIN_FAILED_RE.match(msg)
            if m:
                groups = m.groupdict()
                username = groups["username"]
                tty = groups["tty"]
                return ParsedLogRecord(
                    timestamp=ts,
                    hostname=hostname,
                    program=program,
                    pid=pid,
                    raw_message=msg,
                    event_type="auth.login_failure",
                    action="failed_login",
                    severity="medium",
                    username=username if username != "unknown" else None,
                    terminal=tty,
                    session_type="tty",
                    success=False,
                    payload={"terminal": tty},
                )

        # ── Systemd Logind ────────────────────────────────────────────────────
        if prog == "systemd-logind":
            m = SYSTEMD_NEW_SESSION_RE.match(msg)
            if m:
                groups = m.groupdict()
                session_id = groups["session_id"]
                username = groups["username"]
                return ParsedLogRecord(
                    timestamp=ts,
                    hostname=hostname,
                    program=program,
                    pid=pid,
                    raw_message=msg,
                    event_type="auth.login_success",
                    action="login",
                    severity="info",
                    username=username,
                    success=True,
                    payload={"systemd_session_id": session_id},
                )

            m = SYSTEMD_REMOVED_SESSION_RE.match(msg)
            if m:
                groups = m.groupdict()
                session_id = groups["session_id"]
                return ParsedLogRecord(
                    timestamp=ts,
                    hostname=hostname,
                    program=program,
                    pid=pid,
                    raw_message=msg,
                    event_type="auth.logout",
                    action="logout",
                    severity="info",
                    success=True,
                    payload={"systemd_session_id": session_id},
                )

        # ── Generic Syslog Event Fallback ─────────────────────────────────────
        return ParsedLogRecord(
            timestamp=ts,
            hostname=hostname,
            program=program,
            pid=pid,
            raw_message=msg,
            event_type="syslog.event",
            action="syslog",
            severity="info",
            payload={"message": msg},
        )
