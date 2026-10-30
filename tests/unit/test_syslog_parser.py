"""Unit tests for OSIRIS Syslog & Authentication Log Parser (Phase 2 Milestone 2.3)."""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from collectors.syslog.parser import ParsedLogRecord, SyslogParser


class TestSyslogParserTimestamps:
    """Test timestamp extraction and RFC compliance."""

    def test_rfc3164_timestamp_parsing(self) -> None:
        parser = SyslogParser(default_year=2026)
        ref = datetime(2026, 10, 30, 15, 0, 0, tzinfo=timezone.utc)
        dt = parser.parse_timestamp_rfc3164("Oct 30 14:22:01", ref)
        assert dt == datetime(2026, 10, 30, 14, 22, 1, tzinfo=timezone.utc)

    def test_rfc3164_new_year_rollover(self) -> None:
        """Reading December log in January implies previous year."""
        parser = SyslogParser(default_year=2026)
        jan_ref = datetime(2026, 1, 2, 10, 0, 0, tzinfo=timezone.utc)
        dt = parser.parse_timestamp_rfc3164("Dec 31 23:59:59", jan_ref)
        assert dt == datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

    def test_rfc3164_invalid_month_raises(self) -> None:
        parser = SyslogParser(default_year=2026)
        with pytest.raises(ValueError, match="Unknown month"):
            parser.parse_timestamp_rfc3164("Foo 12 10:00:00")

    def test_rfc3164_invalid_format_raises(self) -> None:
        parser = SyslogParser(default_year=2026)
        with pytest.raises(ValueError, match="Invalid RFC 3164 timestamp"):
            parser.parse_timestamp_rfc3164("Oct 12")

    def test_iso8601_timestamp_parsing(self) -> None:
        parser = SyslogParser()
        dt1 = parser.parse_timestamp_iso("2026-10-30T14:22:01.123456+00:00")
        assert dt1 == datetime(2026, 10, 30, 14, 22, 1, 123456, tzinfo=timezone.utc)

        dt2 = parser.parse_timestamp_iso("2026-10-30T14:22:01Z")
        assert dt2 == datetime(2026, 10, 30, 14, 22, 1, tzinfo=timezone.utc)

        dt3 = parser.parse_timestamp_iso("2026-10-30T16:22:01+02:00")
        assert dt3 == datetime(2026, 10, 30, 14, 22, 1, tzinfo=timezone.utc)


class TestSshdLogParsing:
    """Test OpenSSH authentication and session records."""

    def test_sshd_accepted_publickey(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:22:01 myhost sshd[12345]: Accepted publickey for alice from 192.168.1.50 port 54321 ssh2: RSA SHA256:abc123xyz"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.login_success"
        assert record.action == "login"
        assert record.severity == "info"
        assert record.username == "alice"
        assert record.remote_host == "192.168.1.50"
        assert record.session_type == "ssh"
        assert record.pid == 12345
        assert record.success is True
        assert record.payload.get("auth_method") == "publickey"
        assert record.payload.get("port") == 54321

    def test_sshd_accepted_password(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "2026-10-30T14:22:01.000Z myhost sshd[2222]: Accepted password for bob from 10.0.0.1 port 43210 ssh2"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.login_success"
        assert record.action == "login"
        assert record.username == "bob"
        assert record.remote_host == "10.0.0.1"
        assert record.session_type == "ssh"
        assert record.success is True
        assert record.payload.get("auth_method") == "password"

    def test_sshd_failed_password(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:22:01 myhost sshd[12345]: Failed password for alice from 192.168.1.99 port 43210 ssh2"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.login_failure"
        assert record.action == "failed_login"
        assert record.severity == "medium"
        assert record.username == "alice"
        assert record.remote_host == "192.168.1.99"
        assert record.success is False

    def test_sshd_failed_password_invalid_user(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:22:01 myhost sshd[12345]: Failed password for invalid user admin from 192.168.1.99 port 43210 ssh2"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.login_failure"
        assert record.action == "failed_login"
        assert record.username == "admin"
        assert record.remote_host == "192.168.1.99"
        assert record.success is False

    def test_sshd_invalid_user(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:22:01 myhost sshd[12345]: Invalid user hacker from 192.168.1.99 port 43210"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.login_failure"
        assert record.username == "hacker"
        assert record.remote_host == "192.168.1.99"
        assert record.payload.get("reason") == "invalid_user"


class TestPamLogParsing:
    """Test PAM session open and close records."""

    def test_pam_sshd_session_opened(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:22:01 myhost sshd[12345]: pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.login_success"
        assert record.action == "session_open"
        assert record.username == "alice"
        assert record.uid == 1000
        assert record.session_type == "ssh"
        assert record.success is True

    def test_pam_sshd_session_closed(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:35:00 myhost sshd[12345]: pam_unix(sshd:session): session closed for user alice"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.logout"
        assert record.action == "session_close"
        assert record.username == "alice"

    def test_pam_login_console_session_opened(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:22:01 myhost login[1111]: pam_unix(login:session): session opened for user bob(uid=1001) by LOGIN(uid=0)"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.login_success"
        assert record.action == "session_open"
        assert record.username == "bob"
        assert record.uid == 1001
        assert record.session_type == "tty"

    def test_pam_sudo_session_opened_is_privilege_escalation(self) -> None:
        """PAM sudo session opened must be recognized as privilege escalation, not a new login."""
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:23:05 myhost sudo[5432]: pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.sudo"
        assert record.action == "privilege_escalation"
        assert record.target_user == "root"
        assert record.source_user == "alice"
        assert record.username == "alice"
        assert record.uid == 1000
        assert record.payload.get("target_uid") == 0


class TestSudoAndSuLogParsing:
    """Test sudo execution and su identity transitions."""

    def test_sudo_command_execution(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:23:00 myhost sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.sudo"
        assert record.action == "sudo"
        assert record.username == "alice"
        assert record.target_user == "root"
        assert record.terminal == "pts/0"
        assert record.command == "/usr/bin/cat /etc/shadow"
        assert record.payload.get("pwd") == "/home/alice"

    def test_su_to_user_on_tty(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:24:00 myhost su[9876]: (to root) alice on pts/0"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.su"
        assert record.action == "su"
        assert record.username == "alice"
        assert record.target_user == "root"
        assert record.terminal == "pts/0"
        assert record.success is True

    def test_su_successful(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:24:00 myhost su[9876]: Successful su for root by alice"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.su"
        assert record.action == "su"
        assert record.username == "alice"
        assert record.target_user == "root"

    def test_su_failed(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:24:00 myhost su[9876]: FAILED SU (to root) alice on pts/0"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.su"
        assert record.action == "su_failure"
        assert record.severity == "medium"
        assert record.success is False


class TestConsoleLoginLogParsing:
    """Test local console logins and failures."""

    def test_local_login_accepted(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:22:05 myhost login[1111]: Accepted password for bob on tty1"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.login_success"
        assert record.action == "login"
        assert record.username == "bob"
        assert record.terminal == "tty1"
        assert record.session_type == "tty"
        assert record.success is True

    def test_local_login_failed(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:22:05 myhost login[1111]: FAILED LOGIN (1) on '/dev/tty1' FOR 'unknown', Authentication failure"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.login_failure"
        assert record.action == "failed_login"
        assert record.terminal == "/dev/tty1"
        assert record.success is False


class TestSystemdLogindParsing:
    """Test systemd-logind session lifecycle."""

    def test_systemd_new_session(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:22:01 myhost systemd-logind[678]: New session 42 of user alice."
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.login_success"
        assert record.action == "login"
        assert record.username == "alice"
        assert record.payload.get("systemd_session_id") == "42"

    def test_systemd_removed_session(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:35:00 myhost systemd-logind[678]: Removed session 42."
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.logout"
        assert record.action == "logout"
        assert record.payload.get("systemd_session_id") == "42"


class TestSyslogParserEdgeCases:
    """Test malformed, empty, and generic syslog fallback lines."""

    def test_empty_line_returns_none(self) -> None:
        parser = SyslogParser()
        assert parser.parse_line("") is None
        assert parser.parse_line("   \n\t") is None

    def test_generic_syslog_fallback(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:22:01 myhost kernel: [12345.678] USB disconnect, device number 2"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "syslog.event"
        assert record.action == "syslog"
        assert record.program == "kernel"

    def test_unstructured_line_fallback(self) -> None:
        parser = SyslogParser()
        line = "Unexpected crash dump string without syslog header"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "syslog.event"
        assert record.program == "syslog"

    def test_to_observation_dict(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:22:01 myhost sshd[12345]: Accepted publickey for alice from 192.168.1.50 port 54321 ssh2: RSA"
        record = parser.parse_line(line)
        assert record is not None
        obs = record.to_observation_dict("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        assert obs["source"] == "syslog"
        assert obs["host_id"] == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        assert obs["event_type"] == "auth.login_success"
        assert obs["username"] == "alice"
        assert obs["payload"]["remote_host"] == "192.168.1.50"
        assert "raw_message" in obs["payload"]

    def test_iso8601_timestamp_without_offset(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "2026-10-30T14:22:01 myhost sshd[12345]: Accepted password for alice from 192.168.1.50 port 54321 ssh2"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.login_success"
        assert record.username == "alice"
        assert record.timestamp == datetime(2026, 10, 30, 14, 22, 1, tzinfo=timezone.utc)

    def test_sudo_command_execution_with_group_and_env(self) -> None:
        parser = SyslogParser(default_year=2026)
        line = "Oct 30 14:23:00 myhost sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; GROUP=root ; COMMAND=/bin/bash"
        record = parser.parse_line(line)
        assert record is not None
        assert record.event_type == "auth.sudo"
        assert record.action == "sudo"
        assert record.username == "alice"
        assert record.target_user == "root"
        assert record.terminal == "pts/0"
        assert record.command == "/bin/bash"
