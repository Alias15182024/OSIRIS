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

    def test_determine_object_type_with_symlinks(self, tmp_path: Path):
        # 1. Symlink to regular file
        target_file = tmp_path / "target_file.txt"
        target_file.write_text("data")
        symlink_to_file = tmp_path / "link_file"
        symlink_to_file.symlink_to(target_file)
        assert determine_object_type(0, symlink_to_file) == "symlink"

        # 2. Symlink to directory (critical: must resolve to symlink, not directory)
        target_dir = tmp_path / "target_dir"
        target_dir.mkdir()
        symlink_to_dir = tmp_path / "link_dir"
        symlink_to_dir.symlink_to(target_dir)
        assert determine_object_type(0, symlink_to_dir) == "symlink"
        # Even if IN_ISDIR mask was passed, symlink on disk takes precedence
        assert determine_object_type(IN_ISDIR, symlink_to_dir) == "symlink"

        # 3. Broken symlink
        broken_symlink = tmp_path / "broken_link"
        broken_symlink.symlink_to(tmp_path / "nonexistent")
        assert determine_object_type(0, broken_symlink) == "symlink"

    def test_determine_object_type_with_deleted_path_falls_back_to_mask(self, tmp_path: Path):
        deleted_file = tmp_path / "deleted.txt"
        # When path disappears and IN_ISDIR is set -> preserves directory classification
        assert determine_object_type(IN_ISDIR, deleted_file) == "directory"
        assert determine_object_type(IN_DELETE | IN_ISDIR, deleted_file) == "directory"
        assert determine_object_type(IN_DELETE_SELF | IN_ISDIR, deleted_file) == "directory"
        assert determine_object_type(IN_MOVED_FROM | IN_ISDIR, deleted_file) == "directory"
        assert determine_object_type(IN_MOVED_TO | IN_ISDIR, deleted_file) == "directory"
        assert determine_object_type(IN_ISDIR, None) == "directory"
        # When path disappears and IN_ISDIR is absent -> defaults safely to file
        assert determine_object_type(IN_DELETE, deleted_file) == "file"
        assert determine_object_type(IN_CREATE, deleted_file) == "file"
        assert determine_object_type(IN_MODIFY, deleted_file) == "file"
        assert determine_object_type(IN_MOVED_FROM, deleted_file) == "file"
        assert determine_object_type(0, deleted_file) == "file"
        assert determine_object_type(0, None) == "file"

    def test_determine_object_type_deleted_symlink_falls_back_to_file(self, tmp_path: Path):
        """A deleted symlink cannot be inferred from inotify mask alone (no IN_ISSYMLINK flag)."""
        # 1. Symlink to regular file
        target_file = tmp_path / "target_file.txt"
        target_file.write_text("hello")
        symlink_to_file = tmp_path / "symlink_file"
        symlink_to_file.symlink_to(target_file)
        # While the symlink exists on disk, it is correctly classified as "symlink"
        assert determine_object_type(0, symlink_to_file) == "symlink"
        assert determine_object_type(IN_DELETE, symlink_to_file) == "symlink"

        # Once the symlink is deleted before inspection, it cannot be identified from mask
        symlink_to_file.unlink()
        assert not symlink_to_file.exists(follow_symlinks=False)
        assert determine_object_type(IN_DELETE, symlink_to_file) == "file"
        assert determine_object_type(0, symlink_to_file) == "file"

        # 2. Symlink to directory
        target_dir = tmp_path / "target_dir"
        target_dir.mkdir()
        symlink_to_dir = tmp_path / "symlink_dir"
        symlink_to_dir.symlink_to(target_dir)
        # While present, resolves to "symlink"
        assert determine_object_type(0, symlink_to_dir) == "symlink"

        # Once deleted, inotify emits IN_DELETE without IN_ISDIR for unlinking a symlink
        symlink_to_dir.unlink()
        assert not symlink_to_dir.exists(follow_symlinks=False)
        assert determine_object_type(IN_DELETE, symlink_to_dir) == "file"

    def test_determine_object_type_inaccessible_path(self, tmp_path: Path):
        """Inaccessible paths (PermissionError/OSError) fall back safely to mask or file."""
        inaccessible = tmp_path / "inaccessible.txt"
        with patch.object(Path, "is_symlink", side_effect=PermissionError("Permission denied")):
            # With IN_ISDIR -> preserves directory indication
            assert determine_object_type(IN_ISDIR, inaccessible) == "directory"
            assert determine_object_type(IN_MODIFY | IN_ISDIR, inaccessible) == "directory"
            # Without IN_ISDIR -> defaults safely to file (cannot infer symlink from mask)
            assert determine_object_type(0, inaccessible) == "file"
            assert determine_object_type(IN_MODIFY, inaccessible) == "file"

        with patch.object(Path, "is_dir", side_effect=PermissionError("Permission denied")):
            assert determine_object_type(IN_ISDIR, inaccessible) == "directory"
            assert determine_object_type(0, inaccessible) == "file"

    def test_determine_object_type_with_empty_or_whitespace_or_dot(self):
        """Empty or dot paths must not erroneously resolve to current directory via Path.is_dir()."""
        assert determine_object_type(0, "") == "file"
        assert determine_object_type(IN_CREATE, "") == "file"
        assert determine_object_type(IN_ISDIR, "") == "directory"
        assert determine_object_type(0, "   ") == "file"
        assert determine_object_type(0, ".") == "file"
        assert determine_object_type(0, "./") == "file"
        assert determine_object_type(0, ".//") == "file"
        assert determine_object_type(IN_ISDIR, "./") == "directory"
        assert determine_object_type(0, Path("")) == "file"
        assert determine_object_type(0, Path(".")) == "file"
        assert determine_object_type(0, Path("./")) == "file"
        assert determine_object_type(IN_ISDIR, Path(".")) == "directory"
        assert determine_object_type(IN_ISDIR, Path("./")) == "directory"

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

    def test_get_inode_symlink_and_inaccessible(self, tmp_path: Path):
        # Symlink
        target = tmp_path / "target.txt"
        target.write_text("hello")
        link = tmp_path / "link.txt"
        link.symlink_to(target)
        link_inode = get_inode(link)
        assert link_inode is not None
        assert isinstance(link_inode, int)

        # Broken symlink (target deleted, symlink still present)
        broken = tmp_path / "broken_link"
        broken.symlink_to(tmp_path / "missing")
        broken_inode = get_inode(broken)
        assert broken_inode is not None
        assert isinstance(broken_inode, int)

        # Inaccessible path (PermissionError)
        with patch("os.stat", side_effect=PermissionError("Access denied")):
            assert get_inode(target) is None

        # Deleted symlink
        broken.unlink()
        assert get_inode(broken) is None

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

    def test_parse_inotify_event_symlink(self, tmp_path: Path):
        target = tmp_path / "target.txt"
        target.write_text("data")
        link = tmp_path / "symlink.txt"
        link.symlink_to(target)

        ev = InotifyEvent(
            wd=1,
            mask=IN_CREATE,
            cookie=0,
            name="symlink.txt",
            dir_path=tmp_path,
            full_path=link,
        )
        obs_dict = parse_inotify_event(ev, TEST_HOST_ID)
        assert obs_dict["object_type"] == "symlink"
        assert obs_dict["object_path"] == str(link)

    def test_parse_inotify_event_symlink_to_directory(self, tmp_path: Path):
        target_dir = tmp_path / "target_dir"
        target_dir.mkdir()
        link_dir = tmp_path / "link_dir"
        link_dir.symlink_to(target_dir)

        ev = InotifyEvent(
            wd=1,
            mask=IN_CREATE,
            cookie=0,
            name="link_dir",
            dir_path=tmp_path,
            full_path=link_dir,
        )
        obs_dict = parse_inotify_event(ev, TEST_HOST_ID)
        assert obs_dict["object_type"] == "symlink"
        assert obs_dict["object_path"] == str(link_dir)

    def test_parse_inotify_event_with_disappeared_paths(self, tmp_path: Path):
        """Events for entities that disappear before parsing are classified via fallback."""
        deleted_dir = tmp_path / "disappeared_dir"
        ev_dir = InotifyEvent(
            wd=1,
            mask=IN_DELETE | IN_ISDIR,
            cookie=0,
            name="disappeared_dir",
            dir_path=tmp_path,
            full_path=deleted_dir,
        )
        obs_dir = parse_inotify_event(ev_dir, TEST_HOST_ID)
        assert obs_dir["object_type"] == "directory"
        assert obs_dir["event_type"] == "filesystem.delete"
        assert obs_dir["action"] == "delete"
        assert obs_dir["payload"]["is_dir"] is True
        assert obs_dir["payload"]["inode"] is None

        deleted_file = tmp_path / "disappeared_file.txt"
        ev_file = InotifyEvent(
            wd=1,
            mask=IN_DELETE,
            cookie=0,
            name="disappeared_file.txt",
            dir_path=tmp_path,
            full_path=deleted_file,
        )
        obs_file = parse_inotify_event(ev_file, TEST_HOST_ID)
        assert obs_file["object_type"] == "file"
        assert obs_file["event_type"] == "filesystem.delete"
        assert obs_file["action"] == "delete"
        assert obs_file["payload"]["is_dir"] is False
        assert obs_file["payload"]["inode"] is None

        deleted_symlink = tmp_path / "disappeared_symlink"
        ev_sym = InotifyEvent(
            wd=1,
            mask=IN_DELETE,
            cookie=0,
            name="disappeared_symlink",
            dir_path=tmp_path,
            full_path=deleted_symlink,
        )
        obs_sym = parse_inotify_event(ev_sym, TEST_HOST_ID)
        assert obs_sym["object_type"] == "file"
        assert obs_sym["payload"]["is_dir"] is False
        assert obs_sym["payload"]["inode"] is None



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

    def test_paired_move_disappeared_destination(self, tmp_path: Path):
        """Move pair where destination disappeared before inspection uses fallback."""
        from_dir = tmp_path / "from_dir"
        to_dir = tmp_path / "to_dir"

        from_ev = InotifyEvent(
            wd=1,
            mask=IN_MOVED_FROM | IN_ISDIR,
            cookie=123,
            name="from_dir",
            dir_path=tmp_path,
            full_path=from_dir,
        )
        to_ev = InotifyEvent(
            wd=1,
            mask=IN_MOVED_TO | IN_ISDIR,
            cookie=123,
            name="to_dir",
            dir_path=tmp_path,
            full_path=to_dir,
        )

        obs_dir = parse_move_pair(from_ev, to_ev, TEST_HOST_ID)
        assert obs_dir["object_type"] == "directory"
        assert obs_dir["payload"]["is_dir"] is True
        assert obs_dir["payload"]["inode"] is None

        # File move where destination disappeared
        from_file = tmp_path / "from.txt"
        to_file = tmp_path / "to.txt"
        from_f_ev = InotifyEvent(
            wd=1,
            mask=IN_MOVED_FROM,
            cookie=124,
            name="from.txt",
            dir_path=tmp_path,
            full_path=from_file,
        )
        to_f_ev = InotifyEvent(
            wd=1,
            mask=IN_MOVED_TO,
            cookie=124,
            name="to.txt",
            dir_path=tmp_path,
            full_path=to_file,
        )

        obs_file = parse_move_pair(from_f_ev, to_f_ev, TEST_HOST_ID)
        assert obs_file["object_type"] == "file"
        assert obs_file["payload"]["is_dir"] is False
        assert obs_file["payload"]["inode"] is None



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

    def test_create_symlink_to_file_observation(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)

        target = tmp_path / "target_file.txt"
        target.write_text("data")
        link = tmp_path / "link_file"
        link.symlink_to(target)

        backend.inject_event(
            wd=1,
            mask=IN_CREATE,
            name="link_file",
            dir_path=tmp_path,
            full_path=link,
        )

        observations = collector.collect_observations()
        assert len(observations) == 1
        obs = observations[0]

        assert obs.event_type == "filesystem.create"
        assert obs.action == "create"
        assert obs.object_type == "symlink"
        assert obs.object_path == str(link)

    def test_create_symlink_to_directory_observation(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)

        target_dir = tmp_path / "target_subdir"
        target_dir.mkdir()
        link_dir = tmp_path / "link_to_dir"
        link_dir.symlink_to(target_dir)

        backend.inject_event(
            wd=1,
            mask=IN_CREATE,
            name="link_to_dir",
            dir_path=tmp_path,
            full_path=link_dir,
        )

        observations = collector.collect_observations()
        assert len(observations) == 1
        obs = observations[0]

        assert obs.event_type == "filesystem.create"
        assert obs.action == "create"
        assert obs.object_type == "symlink"
        assert obs.object_path == str(link_dir)

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
        assert obs.object_type == "file"
        assert obs.payload["is_dir"] is False
        assert obs.payload["inode"] is None
        assert obs.payload["timestamp_source"] == "collection_time"

    def test_delete_directory_observation(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)

        d = tmp_path / "deleted_dir"

        backend.inject_event(
            wd=1,
            mask=IN_DELETE | IN_ISDIR,
            name="deleted_dir",
            dir_path=tmp_path,
            full_path=d,
        )

        observations = collector.collect_observations()
        assert len(observations) == 1
        obs = observations[0]

        assert obs.event_type == "filesystem.delete"
        assert obs.action == "delete"
        assert obs.object_type == "directory"
        assert obs.payload["is_dir"] is True
        assert obs.payload["inode"] is None
        assert obs.payload["timestamp_source"] == "collection_time"

    def test_delete_symlink_observation_falls_back_to_file(self, tmp_path: Path):
        backend = MockInotifyBackend()
        collector = FilesystemCollector(TEST_HOST_ID, backend=backend)

        link = tmp_path / "deleted_link"

        # In Linux inotify, deleting a symlink emits IN_DELETE without IN_ISDIR.
        # Once unlinked, the path does not exist on disk, so it safely falls back to "file".
        backend.inject_event(
            wd=1,
            mask=IN_DELETE,
            name="deleted_link",
            dir_path=tmp_path,
            full_path=link,
        )

        observations = collector.collect_observations()
        assert len(observations) == 1
        obs = observations[0]

        assert obs.event_type == "filesystem.delete"
        assert obs.action == "delete"
        assert obs.object_type == "file"
        assert obs.payload["is_dir"] is False
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
