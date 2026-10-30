"""Unit tests for OSIRIS Syslog Collector & Checkpoint Management (Phase 2 Milestone 2.3)."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
import pytest

from collectors.syslog.checkpoint import CheckpointManager, LogCursor
from collectors.syslog.collector import SyslogCollector


class TestLogCursorAndCheckpoint:
    """Test cursor serialization and checkpoint manager operations."""

    def test_cursor_to_and_from_dict(self) -> None:
        cursor = LogCursor(
            path="/var/log/auth.log",
            inode=12345,
            device=6789,
            offset=1024,
            lines_read=42,
            last_read_at="2026-10-30T14:22:01Z",
        )
        d = cursor.to_dict()
        restored = LogCursor.from_dict(d)
        assert restored.path == "/var/log/auth.log"
        assert restored.inode == 12345
        assert restored.device == 6789
        assert restored.offset == 1024
        assert restored.lines_read == 42
        assert restored.last_read_at == "2026-10-30T14:22:01Z"

    def test_checkpoint_save_and_load(self, tmp_path: Path) -> None:
        ckpt_file = tmp_path / "syslog.checkpoint"
        mgr = CheckpointManager(checkpoint_file=ckpt_file)
        mgr.cursor = LogCursor(path="/var/log/auth.log", offset=512, lines_read=10)
        mgr.save()

        assert ckpt_file.is_file()

        mgr2 = CheckpointManager(checkpoint_file=ckpt_file)
        assert mgr2.cursor is not None
        assert mgr2.cursor.offset == 512
        assert mgr2.cursor.lines_read == 10

    def test_incremental_line_reading(self, tmp_path: Path) -> None:
        log_file = tmp_path / "auth.log"
        log_file.write_text("line 1\nline 2\n")

        mgr = CheckpointManager()
        lines = list(mgr.read_new_lines(log_file))
        assert lines == ["line 1\n", "line 2\n"]
        assert mgr.cursor is not None
        assert mgr.cursor.offset == log_file.stat().st_size
        assert mgr.cursor.lines_read == 2

        # Second read without new lines returns nothing
        lines2 = list(mgr.read_new_lines(log_file))
        assert lines2 == []
        assert mgr.cursor.lines_read == 2

        # Append new line
        with open(log_file, "a") as f:
            f.write("line 3\n")

        lines3 = list(mgr.read_new_lines(log_file))
        assert lines3 == ["line 3\n"]
        assert mgr.cursor.lines_read == 3

    def test_log_truncation_detection(self, tmp_path: Path) -> None:
        log_file = tmp_path / "auth.log"
        log_file.write_text("a very long initial line that takes up space\n")

        mgr = CheckpointManager()
        list(mgr.read_new_lines(log_file))
        old_offset = mgr.cursor.offset
        assert old_offset > 10

        # Truncate file (simulate copytruncate)
        log_file.write_text("short\n")

        lines = list(mgr.read_new_lines(log_file))
        assert lines == ["short\n"]
        assert mgr.cursor.offset == log_file.stat().st_size

    def test_log_rotation_handling(self, tmp_path: Path) -> None:
        log_file = tmp_path / "auth.log"
        log_file.write_text("line 1\nline 2\n")

        mgr = CheckpointManager()
        list(mgr.read_new_lines(log_file))
        assert mgr.cursor.lines_read == 2

        # Simulate logrotate: append line 3 to active, rename to auth.log.1, create new auth.log
        with open(log_file, "a") as f:
            f.write("line 3 (in old log)\n")

        rotated_file = tmp_path / "auth.log.1"
        os.rename(log_file, rotated_file)

        # Create new active log
        log_file.write_text("new log line 1\n")

        # Reading from log_file should first drain line 3 from auth.log.1, then read new log line 1
        lines = list(mgr.read_new_lines(log_file))
        assert "line 3 (in old log)\n" in lines
        assert "new log line 1\n" in lines
        assert mgr.cursor.lines_read == 4


class TestSyslogCollectorLifecycle:
    """Test SyslogCollector conformance with BaseCollector interface."""

    def test_source_name(self) -> None:
        collector = SyslogCollector(host_id=uuid.uuid4())
        assert collector.get_source_name() == "syslog"

    def test_collect_from_mock_log(self, tmp_path: Path) -> None:
        log_file = tmp_path / "auth.log"
        log_file.write_text(
            "Oct 30 14:22:01 myhost sshd[12345]: Accepted publickey for alice from 192.168.1.50 port 54321 ssh2: RSA\n"
            "Oct 30 14:23:00 myhost sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls\n"
        )
        collector = SyslogCollector(
            host_id=uuid.uuid4(),
            log_path=log_file,
            default_year=2026,
        )

        raw = collector.collect()
        assert len(raw) == 2
        assert "sshd[12345]" in raw[0]["raw_line"]
        assert "sudo:" in raw[1]["raw_line"]

        # Parse test
        parsed1 = collector.parse(raw[0])
        assert parsed1["event_type"] == "auth.login_success"
        assert parsed1["username"] == "alice"

        parsed2 = collector.parse(raw[1])
        assert parsed2["event_type"] == "auth.sudo"
        assert parsed2["command"] == "/bin/ls"

    def test_collect_observations(self, tmp_path: Path) -> None:
        host_id = uuid.uuid4()
        log_file = tmp_path / "auth.log"
        log_file.write_text(
            "Oct 30 14:22:01 myhost sshd[12345]: Accepted publickey for alice from 192.168.1.50 port 54321 ssh2: RSA\n"
            "Oct 30 14:25:00 myhost sshd[12345]: pam_unix(sshd:session): session closed for user alice\n"
        )
        collector = SyslogCollector(
            host_id=host_id,
            log_path=log_file,
            default_year=2026,
        )

        observations = collector.collect_observations()
        assert len(observations) == 2
        assert observations[0].host_id == host_id
        assert observations[0].source == "syslog"
        assert observations[0].event_type == "auth.login_success"
        assert observations[0].username == "alice"

        assert observations[1].event_type == "auth.logout"
        assert observations[1].action == "session_close"

    def test_missing_file_handled_gracefully(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "nonexistent.log"
        collector = SyslogCollector(
            host_id=uuid.uuid4(),
            log_path=nonexistent,
        )
        raw = collector.collect()
        assert raw == []
        obs = collector.collect_observations()
        assert obs == []

    def test_unreadable_file_handled_gracefully(self, tmp_path: Path) -> None:
        log_file = tmp_path / "restricted.log"
        log_file.write_text("secret log\n")
        # Remove read permissions
        log_file.chmod(0o000)

        collector = SyslogCollector(
            host_id=uuid.uuid4(),
            log_path=log_file,
        )
        raw = collector.collect()
        assert raw == []
        assert collector.last_error is not None
        assert "permission denied" in collector.last_error

        # Restore permissions for cleanup
        log_file.chmod(0o644)

    def test_syslog_collector_persists_checkpoint_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "auth.log"
        ckpt_file = tmp_path / "auth.ckpt"
        log_file.write_text("Oct 30 14:00:00 myhost login[123]: Accepted password for bob on tty1\n")

        mgr = CheckpointManager(checkpoint_file=ckpt_file)
        collector = SyslogCollector(
            host_id=uuid.uuid4(),
            log_path=log_file,
            checkpoint_manager=mgr,
        )
        items = collector.collect()
        assert len(items) == 1
        assert ckpt_file.is_file()

        # Re-instantiating with the checkpoint file starts from previous offset
        mgr2 = CheckpointManager(checkpoint_file=ckpt_file)
        collector2 = SyslogCollector(
            host_id=uuid.uuid4(),
            log_path=log_file,
            checkpoint_manager=mgr2,
        )
        items2 = collector2.collect()
        assert len(items2) == 0

    def test_checkpoint_manager_buffers_incomplete_line(self, tmp_path: Path) -> None:
        log_file = tmp_path / "auth.log"
        log_file.write_text("Oct 30 14:00:00 myhost partial line with no newline")

        mgr = CheckpointManager()
        lines = list(mgr.read_new_lines(log_file))
        assert len(lines) == 0
        assert mgr.cursor.offset == 0

        # Complete the line
        with open(log_file, "a") as f:
            f.write("\n")

        lines2 = list(mgr.read_new_lines(log_file))
        assert len(lines2) == 1
        assert "partial line with no newline" in lines2[0]

    def test_log_rotation_dateext_discovery(self, tmp_path: Path) -> None:
        log_file = tmp_path / "secure"
        log_file.write_text("line 1\nline 2\n")

        mgr = CheckpointManager()
        list(mgr.read_new_lines(log_file))
        assert mgr.cursor.lines_read == 2

        # Rotate to secure-20261030 (standard RHEL/CentOS dateext format)
        with open(log_file, "a") as f:
            f.write("line 3 in rotated log\n")

        rotated = tmp_path / "secure-20261030"
        os.rename(log_file, rotated)
        log_file.write_text("new line 1\n")

        lines = list(mgr.read_new_lines(log_file))
        assert "line 3 in rotated log\n" in lines
        assert "new line 1\n" in lines
        assert mgr.cursor.lines_read == 4
