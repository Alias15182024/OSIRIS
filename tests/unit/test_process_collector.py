"""Unit tests for the OSIRIS Linux Process Collector.

Tests run on any operating system (including macOS) using temporary
mock `/proc` filesystem fixtures.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from backend.services.events.processor import EventProcessor
from backend.services.events.schemas import NormalizedEvent, RawObservation
from collectors.process import (
    PlatformError,
    ProcessCollector,
    parse_cmdline,
    parse_stat,
    parse_status,
    read_process_info,
)

TEST_HOST_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")


def create_mock_proc_entry(
    proc_dir: Path,
    pid: int,
    comm: str = "test-proc",
    ppid: int = 1,
    state: str = "S",
    starttime: int = 12345,
    cmdline: str | None = "/usr/bin/test-proc --daemon",
    uid: int | None = 1000,
    exe: str | None = "/usr/bin/test-proc",
) -> Path:
    """Create a mock /proc/<pid> directory with realistic file contents."""
    pid_dir = proc_dir / str(pid)
    pid_dir.mkdir(parents=True, exist_ok=True)

    # 1. /proc/<pid>/stat
    stat_content = (
        f"{pid} ({comm}) {state} {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {starttime} 0 0 0\n"
    )
    (pid_dir / "stat").write_text(stat_content, encoding="utf-8")

    # 2. /proc/<pid>/cmdline
    if cmdline is not None:
        cmd_bytes = b"\x00".join(cmdline.encode("utf-8").split()) + b"\x00"
        (pid_dir / "cmdline").write_bytes(cmd_bytes)

    # 3. /proc/<pid>/status
    if uid is not None:
        status_content = (
            f"Name:\t{comm}\n"
            f"State:\t{state} (sleeping)\n"
            f"Tgid:\t{pid}\n"
            f"Pid:\t{pid}\n"
            f"PPid:\t{ppid}\n"
            f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
            f"Gid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
        )
        (pid_dir / "status").write_text(status_content, encoding="utf-8")

    # 4. /proc/<pid>/exe (symlink)
    if exe is not None:
        exe_path = pid_dir / "exe"
        if not exe_path.exists():
            try:
                exe_path.symlink_to(exe)
            except OSError:
                pass

    return pid_dir


# ========================================================================
# 1. PARSER UNIT TESTS
# ========================================================================


class TestParserFunctions:

    def test_parse_stat_standard(self):
        stat = "1234 (bash) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 54321 123456\n"
        data = parse_stat(stat)
        assert data["pid"] == 1234
        assert data["comm"] == "bash"
        assert data["state"] == "S"
        assert data["ppid"] == 1
        assert data["starttime"] == 54321

    def test_parse_stat_with_spaces_and_parentheses_in_comm(self):
        stat = "5678 (Web Content (1)) S 5000 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 99999 0\n"
        data = parse_stat(stat)
        assert data["pid"] == 5678
        assert data["comm"] == "Web Content (1)"
        assert data["state"] == "S"
        assert data["ppid"] == 5000
        assert data["starttime"] == 99999

    def test_parse_stat_malformed_raises(self):
        with pytest.raises(ValueError, match="Malformed"):
            parse_stat("no parens here at all")

    def test_parse_stat_invalid_pid_raises(self):
        with pytest.raises(ValueError, match="Invalid PID"):
            parse_stat("not_a_num (comm) S 1")

    def test_parse_stat_invalid_ppid_raises(self):
        with pytest.raises(ValueError, match="Invalid PPID"):
            parse_stat("123 (comm) S not_a_ppid")

    def test_parse_cmdline_multiple_args(self):
        raw = b"python3\x00-m\x00osiris\x00--port\x008000\x00"
        cmd = parse_cmdline(raw)
        assert cmd == "python3 -m osiris --port 8000"

    def test_parse_cmdline_empty(self):
        assert parse_cmdline(b"") is None
        assert parse_cmdline(b"\x00\x00") is None

    def test_parse_status_extracts_uid(self):
        status = "Name:\tbash\nPid:\t123\nUid:\t1000\t1000\t0\t0\nGid:\t1000\n"
        data = parse_status(status)
        assert data["uid"] == 1000
        assert data["euid"] == 1000

    def test_parse_status_missing_uid(self):
        status = "Name:\tbash\nPid:\t123\n"
        data = parse_status(status)
        assert data["uid"] is None


# ========================================================================
# 2. COLLECTOR UNIT TESTS (MOCKED /PROC)
# ========================================================================


class TestProcessCollector:

    @pytest.fixture
    def mock_proc(self, tmp_path: Path) -> Path:
        """Create a mock /proc root with system directories and processes."""
        proc = tmp_path / "proc"
        proc.mkdir()

        # Non-numeric directories to ensure they are ignored
        (proc / "sys").mkdir()
        (proc / "net").mkdir()
        (proc / "cpuinfo").write_text("processor: 0\n", encoding="utf-8")

        # Standard process entries
        create_mock_proc_entry(
            proc,
            pid=1,
            comm="systemd",
            ppid=0,
            state="S",
            starttime=1,
            cmdline="/sbin/init",
            uid=0,
            exe="/usr/lib/systemd/systemd",
        )
        create_mock_proc_entry(
            proc,
            pid=1001,
            comm="python3",
            ppid=1,
            state="R",
            starttime=5000,
            cmdline="/usr/bin/python3 -m server",
            uid=1000,
            exe="/usr/bin/python3",
        )
        return proc

    def test_discover_valid_processes(self, mock_proc: Path):
        collector = ProcessCollector(TEST_HOST_ID, proc_dir=mock_proc)
        raw_list = collector.collect()
        pids = {p["pid"] for p in raw_list}
        assert pids == {1, 1001}

    def test_metadata_fields_parsed_correctly(self, mock_proc: Path):
        collector = ProcessCollector(TEST_HOST_ID, proc_dir=mock_proc)
        raw_list = collector.collect()
        by_pid = {p["pid"]: p for p in raw_list}

        p1 = by_pid[1]
        assert p1["comm"] == "systemd"
        assert p1["ppid"] == 0
        assert p1["uid"] == 0
        assert p1["command"] == "/sbin/init"
        assert p1["starttime"] == 1
        assert p1["executable"] == "/usr/lib/systemd/systemd"

        p1001 = by_pid[1001]
        assert p1001["comm"] == "python3"
        assert p1001["ppid"] == 1
        assert p1001["uid"] == 1000
        assert p1001["command"] == "/usr/bin/python3 -m server"
        assert p1001["starttime"] == 5000

    def test_produces_valid_raw_observations(self, mock_proc: Path):
        collector = ProcessCollector(TEST_HOST_ID, proc_dir=mock_proc)
        observations = collector.collect_observations(diff=False)

        assert len(observations) == 2
        for obs in observations:
            assert isinstance(obs, RawObservation)
            assert obs.source == "proc"
            assert obs.host_id == TEST_HOST_ID
            assert obs.event_type == "process.start"
            assert obs.action == "start"
            assert obs.observed_at is not None
            # Invariant: process_id is not set by collector
            assert obs.process_id is None

    def test_lifecycle_start_and_end_observations(self, mock_proc: Path):
        """Test differential polling: new process starts, then exits."""
        collector = ProcessCollector(TEST_HOST_ID, proc_dir=mock_proc)

        # Cycle 1: Discovers PIDs 1 and 1001
        cycle1 = collector.collect_observations(diff=True)
        assert len(cycle1) == 2
        assert all(o.event_type == "process.start" for o in cycle1)
        assert {o.pid for o in cycle1} == {1, 1001}

        # Cycle 2: No changes -> 0 observations
        cycle2 = collector.collect_observations(diff=True)
        assert len(cycle2) == 0

        # Cycle 3: Add PID 2000 (new process), remove PID 1001 (exited process)
        create_mock_proc_entry(
            mock_proc, pid=2000, comm="worker", ppid=1001, starttime=9000
        )
        import shutil

        shutil.rmtree(mock_proc / "1001")

        cycle3 = collector.collect_observations(diff=True)
        assert len(cycle3) == 2

        start_obs = [o for o in cycle3 if o.event_type == "process.start"]
        end_obs = [o for o in cycle3 if o.event_type == "process.end"]

        assert len(start_obs) == 1
        assert start_obs[0].pid == 2000
        assert start_obs[0].action == "start"

        assert len(end_obs) == 1
        assert end_obs[0].pid == 1001
        assert end_obs[0].action == "exit"
        # Context preserved from memory
        assert end_obs[0].command == "/usr/bin/python3 -m server"
        assert end_obs[0].uid == 1000

    def test_pid_reuse_handled_gracefully(self, mock_proc: Path):
        """A reused PID with different starttime triggers exit of old and start of new."""
        import shutil

        collector = ProcessCollector(TEST_HOST_ID, proc_dir=mock_proc)
        collector.collect_observations(diff=True)

        # Delete PID 1001 (starttime=5000), recreate PID 1001 (starttime=99999, comm=curl)
        shutil.rmtree(mock_proc / "1001")
        create_mock_proc_entry(
            mock_proc,
            pid=1001,
            comm="curl",
            starttime=99999,
            cmdline="curl https://example.com",
            uid=1000,
        )

        cycle2 = collector.collect_observations(diff=True)
        assert len(cycle2) == 2

        end_obs = [o for o in cycle2 if o.event_type == "process.end"][0]
        start_obs = [o for o in cycle2 if o.event_type == "process.start"][0]

        assert end_obs.pid == 1001
        assert end_obs.command == "/usr/bin/python3 -m server"
        assert end_obs.payload["starttime"] == 5000

        assert start_obs.pid == 1001
        assert start_obs.command == "curl https://example.com"
        assert start_obs.payload["starttime"] == 99999

    def test_missing_optional_files_fallback(self, mock_proc: Path):
        """Process missing cmdline, status, and exe still collects via stat."""
        sparse_dir = mock_proc / "3000"
        sparse_dir.mkdir()
        (sparse_dir / "stat").write_text("3000 (kworker/0:0) S 2 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0\n")

        info = read_process_info(sparse_dir)
        assert info is not None
        assert info["pid"] == 3000
        assert info["comm"] == "kworker/0:0"
        assert info["command"] == "kworker/0:0"
        assert info["uid"] is None
        assert info["executable"] is None

    def test_empty_proc_returns_empty_list(self, tmp_path: Path):
        empty_proc = tmp_path / "empty_proc"
        empty_proc.mkdir()
        collector = ProcessCollector(TEST_HOST_ID, proc_dir=empty_proc)
        assert collector.collect() == []
        assert collector.collect_observations() == []

    def test_nonexistent_proc_dir_returns_empty_list(self, tmp_path: Path):
        no_proc = tmp_path / "does_not_exist"
        collector = ProcessCollector(TEST_HOST_ID, proc_dir=no_proc)
        assert collector.collect() == []

    def test_process_disappears_during_read(self, mock_proc: Path):
        """Simulate race condition: directory deleted just before reading stat."""
        ghost_dir = mock_proc / "4000"
        ghost_dir.mkdir()
        # No stat file exists (simulating exit)
        info = read_process_info(ghost_dir)
        assert info is None

    def test_permission_error_handled_gracefully(self, mock_proc: Path):
        """Simulate PermissionError on a process stat file."""
        with patch.object(Path, "read_text", side_effect=PermissionError("Denied")):
            info = read_process_info(mock_proc / "1")
            assert info is None


# ========================================================================
# 3. PLATFORM GUARD TESTS
# ========================================================================


class TestPlatformGuard:

    def test_default_proc_on_non_linux_raises_platform_error(self):
        """On non-Linux OS, default collection against /proc must raise PlatformError."""
        collector = ProcessCollector(TEST_HOST_ID, proc_dir="/proc")

        with patch("sys.platform", "darwin"):
            with pytest.raises(PlatformError, match="requires Linux /proc"):
                collector.collect()

        with patch("sys.platform", "win32"):
            with pytest.raises(PlatformError, match="requires Linux /proc"):
                collector.collect()


# ========================================================================
# 4. EVENT PROCESSING PIPELINE INTEGRATION
# ========================================================================


class TestEventProcessorIntegration:

    def test_collector_output_normalizes_through_event_processor(
        self, tmp_path: Path
    ):
        """Verify: ProcessCollector -> RawObservation -> EventProcessor -> NormalizedEvent."""
        proc = tmp_path / "proc"
        proc.mkdir()
        create_mock_proc_entry(
            proc,
            pid=777,
            comm="daemon",
            ppid=1,
            uid=1000,
            cmdline="/usr/sbin/daemon --config /etc/daemon.conf",
        )

        collector = ProcessCollector(TEST_HOST_ID, proc_dir=proc)
        raw_observations = collector.collect_observations(diff=False)

        assert len(raw_observations) == 1
        raw_obs = raw_observations[0]

        processor = EventProcessor()
        result = processor.process(raw_obs)

        assert result.success
        assert result.event is not None
        assert isinstance(result.event, NormalizedEvent)
        assert result.event.source == "proc"
        assert result.event.event_type == "process.start"
        assert result.event.action == "start"
        assert result.event.pid == 777
        assert result.event.ppid == 1
        assert result.event.uid == 1000
        assert result.event.command == "/usr/sbin/daemon --config /etc/daemon.conf"
        assert isinstance(result.event.id, uuid.UUID)
        assert result.event.timestamp.tzinfo is not None
