"""Unit tests for the OSIRIS Linux Filesystem Activity Collector.

Tests execute on any operating system (including macOS) using MockInotifyBackend
to provide deterministic, synthetic inotify events.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from backend.services.events.processor import EventProcessor
from backend.services.events.schemas import NormalizedEvent, RawObservation
from backend.services.events.validator import validate_raw_observation
from collectors.filesystem import (
    IN_ACCESS,
    IN_ATTRIB,
    IN_CREATE,
    IN_DELETE,
    IN_DELETE_SELF,
    IN_ISDIR,
    IN_MODIFY,
    IN_MOVE_SELF,
    IN_MOVED_FROM,
    IN_MOVED_TO,
    FilesystemCollector,
    InotifyEvent,
    MockInotifyBackend,
    PlatformError,
    determine_object_type,
    get_inode,
    map_action_and_event_type,
    parse_inotify_event,
    parse_move_pair,
)

TEST_HOST_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")


# ============================================================================
# 1. PARSER UNIT TESTS
# ============================================================================


class TestParserFunctions:

    def test_determine_object_type_with_mask_flag(self):
        assert determine_object_type(IN_ISDIR) == "directory"
        assert determine_object_type(IN_CREATE | IN_ISDIR) == "directory"
        assert determine_object_type(IN_CREATE) == "file"
        assert determine_object_type(IN_MODIFY) == "file"

    def test_determine_object_type_with_filesystem_inspection(self, tmp_path: Path):
        test_dir = tmp_path / "subdir"
        test_dir.mkdir()
        test_file = tmp_path / "file.txt"
        test_file.write_text("hello")

        # Even with mask=0, accessible directory resolves to "directory"
        assert determine_object_type(0, test_dir) == "directory"
        assert determine_object_type(0, test_file) == "file"

    def test_get_inode_real_file(self, tmp_path: Path):
        test_file = tmp_path / "file.txt"
        test_file.write_text("content")
        inode = get_inode(test_file)
        assert inode is not None
        assert isinstance(inode, int)
        assert inode > 0

    def test_get_inode_missing_or_none(self, tmp_path: Path):
        assert get_inode(None) is None
        assert get_inode(tmp_path / "nonexistent.txt") is None

    def test_map_action_and_event_type(self):
        assert map_action_and_event_type(IN_CREATE) == ("create", "filesystem.create")
        assert map_action_and_event_type(IN_MODIFY) == ("modify", "filesystem.modify")
        assert map_action_and_event_type(IN_ATTRIB) == ("modify", "filesystem.modify")
        assert map_action_and_event_type(IN_DELETE) == ("delete", "filesystem.delete")
        assert map_action_and_event_type(IN_DELETE_SELF) == ("delete", "filesystem.delete")
        assert map_action_and_event_type(IN_MOVED_FROM) == ("move", "filesystem.move")
        assert map_action_and_event_type(IN_MOVED_TO) == ("move", "filesystem.move")
        assert map_action_and_event_type(IN_MOVE_SELF) == ("move", "filesystem.move")
        assert map_action_and_event_type(IN_ACCESS) == ("unknown", "filesystem.unknown")

    def test_parse_inotify_event_structure(self, tmp_path: Path):
        file_path = tmp_path / "test.txt"
        file_path.write_text("sample")

        ev = InotifyEvent(
            wd=1,
            mask=IN_CREATE,
            cookie=0,
            name="test.txt",
            dir_path=tmp_path,
            full_path=file_path,
        )

        obs_dict = parse_inotify_event(ev, TEST_HOST_ID)

        assert obs_dict["source"] == "fs"
        assert obs_dict["host_id"] == TEST_HOST_ID
        assert obs_dict["event_type"] == "filesystem.create"
        assert obs_dict["action"] == "create"
        assert obs_dict["severity"] == "info"
        assert obs_dict["object_type"] == "file"
        assert obs_dict["object_path"] == str(file_path)
        assert obs_dict["payload"]["inode"] is not None
        assert obs_dict["payload"]["is_dir"] is False
        assert obs_dict["payload"]["name"] == "test.txt"
        assert obs_dict["payload"]["watch_path"] == str(tmp_path)
        assert obs_dict["payload"]["timestamp_source"] == "collection_time"


# ============================================================================
# 2. MOVE PAIRING TESTS
# ============================================================================


class TestMovePairing:

    def test_paired_move_produces_single_move_observation(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)

        old_file = tmp_path / "old.txt"
        new_file = tmp_path / "new.txt"
        new_file.write_text("data")

        # Inject paired move events with matching cookie
        backend.inject_event(
            wd=1,
            mask=IN_MOVED_FROM,
            cookie=42,
            name="old.txt",
            dir_path=tmp_path,
            full_path=old_file,
        )
        backend.inject_event(
            wd=1,
            mask=IN_MOVED_TO,
            cookie=42,
            name="new.txt",
            dir_path=tmp_path,
            full_path=new_file,
        )

        observations = collector.collect_observations()
        assert len(observations) == 1

        obs = observations[0]
        assert obs.source == "fs"
        assert obs.event_type == "filesystem.move"
        assert obs.action == "move"
        assert obs.object_path == str(new_file)
        assert obs.payload["from_path"] == str(old_file)
        assert obs.payload["to_path"] == str(new_file)
        assert obs.payload["cookie"] == 42
        assert obs.payload["inode"] is not None
        assert obs.payload["timestamp_source"] == "collection_time"

    def test_unpaired_move_from_emitted(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)

        old_file = tmp_path / "old.txt"
        backend.inject_event(
            wd=1,
            mask=IN_MOVED_FROM,
            cookie=99,
            name="old.txt",
            dir_path=tmp_path,
            full_path=old_file,
        )

        observations = collector.collect_observations()
        assert len(observations) == 1

        obs = observations[0]
        assert obs.source == "fs"
        assert obs.event_type == "filesystem.move"
        assert obs.action == "move"
        assert obs.payload["from_path"] == str(old_file)
        assert obs.payload["to_path"] is None
        assert obs.payload["timestamp_source"] == "collection_time"

    def test_unpaired_move_to_emitted(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)

        new_file = tmp_path / "new.txt"
        new_file.write_text("arrived")

        backend.inject_event(
            wd=1,
            mask=IN_MOVED_TO,
            cookie=88,
            name="new.txt",
            dir_path=tmp_path,
            full_path=new_file,
        )

        observations = collector.collect_observations()
        assert len(observations) == 1

        obs = observations[0]
        assert obs.source == "fs"
        assert obs.event_type == "filesystem.move"
        assert obs.action == "move"
        assert obs.payload["from_path"] is None
        assert obs.payload["to_path"] == str(new_file)
        assert obs.payload["timestamp_source"] == "collection_time"


# ============================================================================
# 3. RECURSIVE WATCH MANAGEMENT & DIRECTORY MOVES
# ============================================================================


class TestRecursiveWatchManagement:

    def test_directory_created_inside_recursive_watch(self, tmp_path: Path):
        backend = MockInotifyBackend()
        root = tmp_path / "root"
        root.mkdir()

        collector = FilesystemCollector(
            TEST_HOST_ID, watch_paths=[root], recursive=True, backend=backend
        )
        assert root.resolve() in collector._watches

        # Create new subdirectory on disk and inject inotify event
        sub = root / "new_sub"
        sub.mkdir()

        backend.inject_event(
            wd=1,
            mask=IN_CREATE | IN_ISDIR,
            name="new_sub",
            dir_path=root,
            full_path=sub,
        )

        collector.collect_observations()

        # The new subdirectory must have been automatically registered
        assert sub.resolve() in collector._watches
        assert backend.get_wd_for_path(sub) is not None

    def test_directory_moved_into_recursive_watch(self, tmp_path: Path):
        backend = MockInotifyBackend()
        root = tmp_path / "root"
        root.mkdir()

        collector = FilesystemCollector(
            TEST_HOST_ID, watch_paths=[root], recursive=True, backend=backend
        )

        # External directory moved into root
        imported = root / "imported_dir"
        imported.mkdir()
        nested = imported / "nested"
        nested.mkdir()

        backend.inject_event(
            wd=1,
            mask=IN_MOVED_TO | IN_ISDIR,
            name="imported_dir",
            dir_path=root,
            full_path=imported,
        )

        collector.collect_observations()

        # Both the imported directory and its nested subdirectory must be watched
        assert imported.resolve() in collector._watches
        assert nested.resolve() in collector._watches

    def test_watched_directory_renamed_updates_mappings(self, tmp_path: Path):
        backend = MockInotifyBackend()
        root = tmp_path / "root"
        root.mkdir()

        dir_a = root / "dirA"
        dir_a.mkdir()

        collector = FilesystemCollector(
            TEST_HOST_ID, watch_paths=[root], recursive=True, backend=backend
        )
        assert dir_a.resolve() in collector._watches
        dir_a_wd = collector._watches[dir_a.resolve()]

        # Rename dirA to dirB on disk
        dir_b = root / "dirB"
        dir_a.rename(dir_b)

        # Inject paired move events for directory
        backend.inject_event(
            wd=1,
            mask=IN_MOVED_FROM | IN_ISDIR,
            cookie=77,
            name="dirA",
            dir_path=root,
            full_path=dir_a,
        )
        backend.inject_event(
            wd=1,
            mask=IN_MOVED_TO | IN_ISDIR,
            cookie=77,
            name="dirB",
            dir_path=root,
            full_path=dir_b,
        )

        collector.collect_observations()

        # Stale dirA must be gone; dirB must be present with the same wd
        assert dir_a.resolve() not in collector._watches
        assert dir_b.resolve() in collector._watches
        assert collector._watches[dir_b.resolve()] == dir_a_wd

        # Backend path lookup must return dirB for this wd
        assert backend.get_path_for_wd(dir_a_wd) == dir_b.resolve()
        assert backend.get_wd_for_path(dir_a) is None
        assert backend.get_wd_for_path(dir_b) == dir_a_wd

    def test_subsequent_file_event_in_renamed_directory_resolves_to_new_path(
        self, tmp_path: Path
    ):
        backend = MockInotifyBackend()
        root = tmp_path / "root"
        root.mkdir()

        dir_a = root / "dirA"
        dir_a.mkdir()

        collector = FilesystemCollector(
            TEST_HOST_ID, watch_paths=[root], recursive=True, backend=backend
        )
        dir_wd = collector._watches[dir_a.resolve()]

        # Rename dirA to dirB
        dir_b = root / "dirB"
        dir_a.rename(dir_b)

        backend.inject_event(
            wd=1,
            mask=IN_MOVED_FROM | IN_ISDIR,
            cookie=55,
            name="dirA",
            dir_path=root,
            full_path=dir_a,
        )
        backend.inject_event(
            wd=1,
            mask=IN_MOVED_TO | IN_ISDIR,
            cookie=55,
            name="dirB",
            dir_path=root,
            full_path=dir_b,
        )

        # Process the rename
        collector.collect_observations()

        # Now simulate a subsequent file event inside dirB using the preserved wd
        file_b = dir_b / "subsequent.txt"
        file_b.write_text("content")

        # In real inotify, kernel emits event on dir_wd with name="subsequent.txt"
        # Since backend._wd_to_path was updated, dir_path is dir_b
        resolved_dir = backend.get_path_for_wd(dir_wd)
        assert resolved_dir == dir_b.resolve()

        backend.inject_event(
            wd=dir_wd,
            mask=IN_CREATE,
            name="subsequent.txt",
            dir_path=resolved_dir,
            full_path=file_b,
        )

        obs_list = collector.collect_observations()
        assert len(obs_list) == 1
        obs = obs_list[0]

        assert obs.object_path == str(file_b.resolve())
        assert str(dir_a.resolve()) not in obs.object_path

    def test_watched_directory_moved_out_cleans_up_mappings(self, tmp_path: Path):
        backend = MockInotifyBackend()
        root = tmp_path / "root"
        root.mkdir()

        dir_out = root / "leaving"
        dir_out.mkdir()
        child = dir_out / "child"
        child.mkdir()

        collector = FilesystemCollector(
            TEST_HOST_ID, watch_paths=[root], recursive=True, backend=backend
        )
        assert dir_out.resolve() in collector._watches
        assert child.resolve() in collector._watches

        # Simulate moving out (unpaired IN_MOVED_FROM)
        backend.inject_event(
            wd=1,
            mask=IN_MOVED_FROM | IN_ISDIR,
            cookie=66,
            name="leaving",
            dir_path=root,
            full_path=dir_out,
        )

        collector.collect_observations()

        # Both the directory and its child must be removed from watches
        assert dir_out.resolve() not in collector._watches
        assert child.resolve() not in collector._watches
        assert backend.get_wd_for_path(dir_out) is None
        assert backend.get_wd_for_path(child) is None

    def test_watched_directory_deleted_cleans_up_mappings(self, tmp_path: Path):
        backend = MockInotifyBackend()
        root = tmp_path / "root"
        root.mkdir()

        target_dir = root / "doomed"
        target_dir.mkdir()

        collector = FilesystemCollector(
            TEST_HOST_ID, watch_paths=[root], recursive=True, backend=backend
        )
        assert target_dir.resolve() in collector._watches

        # Inject IN_DELETE_SELF on the directory
        backend.inject_event(
            wd=collector._watches[target_dir.resolve()],
            mask=IN_DELETE_SELF | IN_ISDIR,
            name="",
            dir_path=target_dir,
            full_path=target_dir,
        )

        collector.collect_observations()

        # Must be removed from watches
        assert target_dir.resolve() not in collector._watches
        assert backend.get_wd_for_path(target_dir) is None


# ============================================================================
# 4. FILESYSTEM COLLECTOR LIFECYCLE & EVENT HANDLING
# ============================================================================


class TestFilesystemCollector:

    def test_create_file_observation(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)

        f = tmp_path / "created.log"
        f.write_text("line")

        backend.inject_event(
            wd=1, mask=IN_CREATE, name="created.log", dir_path=tmp_path, full_path=f
        )

        observations = collector.collect_observations()
        assert len(observations) == 1
        obs = observations[0]

        assert obs.source == "fs"
        assert obs.event_type == "filesystem.create"
        assert obs.action == "create"
        assert obs.object_type == "file"
        assert obs.object_path == str(f)
        assert obs.process_id is None
        assert obs.payload["timestamp_source"] == "collection_time"

    def test_create_directory_observation(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)

        d = tmp_path / "new_dir"
        d.mkdir()

        backend.inject_event(
            wd=1,
            mask=IN_CREATE | IN_ISDIR,
            name="new_dir",
            dir_path=tmp_path,
            full_path=d,
        )

        observations = collector.collect_observations()
        assert len(observations) == 1
        obs = observations[0]

        assert obs.event_type == "filesystem.create"
        assert obs.action == "create"
        assert obs.object_type == "directory"
        assert obs.payload["is_dir"] is True
        assert obs.payload["timestamp_source"] == "collection_time"

    def test_modify_file_observation(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)

        f = tmp_path / "modified.txt"
        f.write_text("initial")

        backend.inject_event(
            wd=1, mask=IN_MODIFY, name="modified.txt", dir_path=tmp_path, full_path=f
        )

        observations = collector.collect_observations()
        assert len(observations) == 1
        obs = observations[0]

        assert obs.event_type == "filesystem.modify"
        assert obs.action == "modify"
        assert obs.object_path == str(f)
        assert obs.payload["timestamp_source"] == "collection_time"

    def test_delete_file_observation(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)

        f = tmp_path / "deleted.txt"

        backend.inject_event(
            wd=1, mask=IN_DELETE, name="deleted.txt", dir_path=tmp_path, full_path=f
        )

        observations = collector.collect_observations()
        assert len(observations) == 1
        obs = observations[0]

        assert obs.event_type == "filesystem.delete"
        assert obs.action == "delete"
        assert obs.payload["inode"] is None
        assert obs.payload["timestamp_source"] == "collection_time"

    def test_rapid_consecutive_events_drained(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)

        for i in range(10):
            p = tmp_path / f"file_{i}.txt"
            backend.inject_event(
                wd=1, mask=IN_CREATE, name=f"file_{i}.txt", dir_path=tmp_path, full_path=p
            )

        observations = collector.collect_observations()
        assert len(observations) == 10
        for i, obs in enumerate(observations):
            assert obs.payload["name"] == f"file_{i}.txt"

    def test_nonexistent_watch_path_handled_gracefully(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)
        missing_path = tmp_path / "does_not_exist"

        # add_watch returns False and does not raise
        success = collector.add_watch(missing_path)
        assert success is False

    def test_permission_error_handled_gracefully(self, tmp_path: Path):
        backend = MockInotifyBackend()

        def raise_permission(*args, **kwargs):
            raise PermissionError("Access denied")

        backend.add_watch = raise_permission  # type: ignore[method-assign]
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)

        success = collector.add_watch(tmp_path)
        assert success is False

    def test_cleanup_and_context_manager(self, tmp_path: Path):
        backend = MockInotifyBackend()
        with FilesystemCollector(TEST_HOST_ID, watch_paths=[tmp_path], backend=backend) as col:
            assert col.is_running
            assert len(col._watches) == 1

        assert not col.is_running
        assert len(col._watches) == 0

    def test_remove_watch(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, watch_paths=[tmp_path], backend=backend)
        assert len(collector._watches) == 1

        removed = collector.remove_watch(tmp_path)
        assert removed is True
        assert len(collector._watches) == 0

        # Removing again returns False
        assert collector.remove_watch(tmp_path) is False


# ============================================================================
# 5. PLATFORM GUARD
# ============================================================================


class TestPlatformGuard:

    def test_default_backend_on_non_linux_raises_platform_error(self):
        with patch("sys.platform", "darwin"):
            with pytest.raises(PlatformError) as exc_info:
                FilesystemCollector(TEST_HOST_ID, backend=None)
            assert "requires Linux inotify" in str(exc_info.value)

    def test_custom_backend_allowed_on_any_platform(self):
        backend = MockInotifyBackend()
        with patch("sys.platform", "darwin"):
            collector = FilesystemCollector(TEST_HOST_ID, backend=backend)
            assert collector.get_source_name() == "fs"


# ============================================================================
# 6. EVENT PROCESSING INTEGRATION
# ============================================================================


class TestEventProcessorIntegration:

    def test_collector_output_passes_validator(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)

        f1 = tmp_path / "test1.txt"
        f1.write_text("data")
        backend.inject_event(
            wd=1, mask=IN_CREATE, name="test1.txt", dir_path=tmp_path, full_path=f1
        )
        backend.inject_event(
            wd=1, mask=IN_MODIFY, name="test1.txt", dir_path=tmp_path, full_path=f1
        )
        backend.inject_event(
            wd=1, mask=IN_DELETE, name="test1.txt", dir_path=tmp_path, full_path=f1
        )

        observations = collector.collect_observations()
        assert len(observations) == 3

        for obs in observations:
            errors = validate_raw_observation(obs)
            assert errors == [], f"Validation failed for {obs}: {errors}"

    def test_collector_output_normalizes_through_event_processor(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)
        processor = EventProcessor()

        f = tmp_path / "test.txt"
        f.write_text("line")
        backend.inject_event(
            wd=1, mask=IN_CREATE, name="test.txt", dir_path=tmp_path, full_path=f
        )
        backend.inject_event(
            wd=1, mask=IN_MODIFY, name="test.txt", dir_path=tmp_path, full_path=f
        )

        observations = collector.collect_observations()
        assert len(observations) == 2

        for obs in observations:
            result = processor.process(obs)
            assert result.success is True
            assert isinstance(result.event, NormalizedEvent)
            assert result.event.source == "fs"
            assert result.event.id is not None
            assert isinstance(result.event.id, uuid.UUID)
            assert result.event.timestamp.tzinfo is not None
            assert result.event.object_type == "file"
            assert result.event.object_path == str(f)
            assert result.event.payload["timestamp_source"] == "collection_time"
