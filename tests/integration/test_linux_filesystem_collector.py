"""Live Linux integration tests for FilesystemCollector.

These tests execute directly against the Linux kernel inotify subsystem.
On non-Linux platforms (such as macOS development machines), these tests
are skipped cleanly.

Does NOT require PostgreSQL.
"""

from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path

import pytest

from backend.services.events.processor import EventProcessor
from backend.services.events.schemas import NormalizedEvent
from collectors.filesystem import FilesystemCollector

# Skip entire module on non-Linux platforms
pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Live FilesystemCollector integration tests require Linux inotify",
)

TEST_HOST_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")


class TestLiveLinuxFilesystemCollector:

    def test_live_linux_filesystem_lifecycle(self, tmp_path: Path):
        """Live collection on Linux captures file create, modify, rename, and delete."""
        watch_dir = tmp_path / "watched"
        watch_dir.mkdir()

        collector = FilesystemCollector(TEST_HOST_ID, watch_paths=[watch_dir])
        collector.start()

        try:
            # 1. Create a file
            target_file = watch_dir / "target.txt"
            target_file.write_text("initial version\n")

            # 2. Modify the file
            target_file.write_text("updated version with more data\n")

            # 3. Rename / move the file
            renamed_file = watch_dir / "renamed.txt"
            target_file.rename(renamed_file)

            # 4. Delete the file
            renamed_file.unlink()

            # Brief pause to allow kernel buffer flush
            time.sleep(0.05)

            # 5. Collect observations
            observations = collector.collect_observations()
            assert len(observations) > 0

            # 6. Verify expected actions using set-based assertions
            observed_actions = {obs.action for obs in observations}
            assert "create" in observed_actions
            assert "modify" in observed_actions
            assert "move" in observed_actions
            assert "delete" in observed_actions

            # Verify common invariant across all observations
            for obs in observations:
                assert obs.source == "fs"
                assert obs.host_id == TEST_HOST_ID
                assert obs.process_id is None  # Collector boundary preserved
                assert obs.observed_at is not None
                assert obs.payload.get("timestamp_source") == "collection_time"

            # Verify move observation payload has from_path and to_path
            move_obs = next(obs for obs in observations if obs.action == "move")
            assert move_obs.event_type == "filesystem.move"
            assert move_obs.payload is not None
            assert "from_path" in move_obs.payload
            assert "to_path" in move_obs.payload
            assert str(target_file) in move_obs.payload["from_path"]
            assert str(renamed_file) in move_obs.payload["to_path"]

            # 7. Verify all observations normalize through EventProcessor
            processor = EventProcessor()
            for obs in observations:
                res = processor.process(obs)
                assert res.success, f"Failed to normalize live observation: {res.errors}"
                assert isinstance(res.event, NormalizedEvent)
                assert res.event.source == "fs"
                assert res.event.timestamp.tzinfo is not None

        finally:
            collector.stop()
            collector.close()
