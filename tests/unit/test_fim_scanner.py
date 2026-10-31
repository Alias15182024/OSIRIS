"""Unit tests for OSIRIS FIM baseline scanner."""

from __future__ import annotations

import os
from pathlib import Path
import unittest.mock as mock

import pytest

from backend.services.fim.scanner import (
    DEFAULT_EXCLUDE_PATTERNS,
    FimScanner,
    ScanSummary,
)


class TestFimScanner:
    """Test filesystem scanner traversal, filters, and safety."""

    def test_scan_empty_directory(self, tmp_path: Path) -> None:
        scan_dir = tmp_path / "empty_dir"
        scan_dir.mkdir()

        scanner = FimScanner(paths=[scan_dir])
        results, summary = scanner.scan()

        assert summary.total_files == 1  # The directory itself
        assert str(scan_dir) in results
        assert results[str(scan_dir)].file_type == "directory"
        assert summary.is_complete is True
        assert len(summary.errors) == 0

    def test_scan_nested_directories_and_files(self, tmp_path: Path) -> None:
        base = tmp_path / "tree"
        base.mkdir()
        (base / "a.txt").write_text("file a", encoding="utf-8")
        sub = base / "sub"
        sub.mkdir()
        (sub / "b.txt").write_text("file b", encoding="utf-8")

        scanner = FimScanner(paths=[base])
        results, summary = scanner.scan()

        assert summary.total_files == 4  # base, a.txt, sub, b.txt
        assert str(base / "a.txt") in results
        assert str(sub / "b.txt") in results
        assert results[str(base / "a.txt")].file_type == "file"
        assert results[str(base / "a.txt")].sha256 is not None
        assert summary.is_complete is True

    def test_exclusion_patterns(self, tmp_path: Path) -> None:
        base = tmp_path / "excludes"
        base.mkdir()
        (base / "keep.txt").write_text("keep", encoding="utf-8")
        (base / "skip.tmp").write_text("skip", encoding="utf-8")
        git_dir = base / ".git"
        git_dir.mkdir()
        (git_dir / "HEAD").write_text("ref: master", encoding="utf-8")

        scanner = FimScanner(
            paths=[base],
            exclude_patterns=["*.tmp", "*/.git*", ".git"],
        )
        results, summary = scanner.scan()

        assert str(base / "keep.txt") in results
        assert str(base / "skip.tmp") not in results
        assert str(git_dir) not in results
        assert str(git_dir / "HEAD") not in results

    def test_inclusion_patterns(self, tmp_path: Path) -> None:
        base = tmp_path / "includes"
        base.mkdir()
        (base / "script.sh").write_text("echo", encoding="utf-8")
        (base / "readme.md").write_text("doc", encoding="utf-8")

        scanner = FimScanner(
            paths=[base],
            include_patterns=["*.sh", str(base)],
        )
        results, summary = scanner.scan()

        assert str(base / "script.sh") in results
        assert str(base / "readme.md") not in results

    def test_symlink_traversal_prevention(self, tmp_path: Path) -> None:
        base = tmp_path / "symlink_test"
        base.mkdir()

        outside_dir = tmp_path / "outside_scope"
        outside_dir.mkdir()
        (outside_dir / "secret.txt").write_text("secret", encoding="utf-8")

        # Create symlink pointing outside
        link_dir = base / "linked_dir"
        os.symlink(str(outside_dir), str(link_dir))

        scanner = FimScanner(paths=[base], follow_symlinks=False)
        results, summary = scanner.scan()

        # The symlink itself should be captured as a symlink
        assert str(link_dir) in results
        assert results[str(link_dir)].file_type == "symlink"
        assert results[str(link_dir)].symlink_target == str(outside_dir)

        # The contents of outside_dir MUST NOT be traversed into
        assert str(link_dir / "secret.txt") not in results
        assert str(outside_dir / "secret.txt") not in results

    def test_missing_root_path_recorded_as_error(self, tmp_path: Path) -> None:
        missing_root = tmp_path / "nonexistent_root"
        scanner = FimScanner(paths=[missing_root])
        results, summary = scanner.scan()

        assert len(results) == 0
        assert len(summary.errors) == 1
        assert summary.errors[0]["error"] == "root_path_not_found"
        assert summary.is_complete is False

    def test_permission_error_on_root_marks_scan_incomplete(self, tmp_path: Path) -> None:
        root = tmp_path / "protected_root"
        root.mkdir()
        scanner = FimScanner(paths=[root])

        with mock.patch("os.lstat", side_effect=PermissionError("Permission denied")):
            results, summary = scanner.scan()

        assert len(results) == 0
        assert len(summary.errors) == 1
        assert summary.errors[0]["error"] == "root_permission_denied"
        assert summary.is_complete is False

    def test_walk_error_marks_scan_incomplete(self, tmp_path: Path) -> None:
        root = tmp_path / "walk_root"
        root.mkdir()
        sub = root / "unreadable_sub"
        sub.mkdir()
        (sub / "secret.txt").write_text("secret", encoding="utf-8")

        scanner = FimScanner(paths=[root])

        def mock_walk(top, **kwargs):
            onerror = kwargs.get("onerror")
            if onerror:
                onerror(PermissionError(f"Permission denied: {sub}"))
            return iter([])

        with mock.patch("os.walk", side_effect=mock_walk):
            results, summary = scanner.scan()

        assert summary.is_complete is False
        assert any("Permission denied" in err.get("error", "") for err in summary.errors)

    def test_max_files_limit_enforced_on_directories(self, tmp_path: Path) -> None:
        base = tmp_path / "dir_limit_test"
        base.mkdir()
        cur = base
        for i in range(15):
            cur = cur / f"level_{i}"
            cur.mkdir()

        scanner = FimScanner(paths=[base], max_files=5)
        results, summary = scanner.scan()

        assert len(results) == 5
        assert summary.is_complete is False
        assert any("max_files_limit_reached" in err.get("error", "") for err in summary.errors)

    def test_folder_name_and_trailing_slash_exclusion_patterns(self, tmp_path: Path) -> None:
        base = tmp_path / "proj"
        base.mkdir()
        nm = base / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text("code", encoding="utf-8")
        logs = base / "logs"
        logs.mkdir()
        (logs / "app.log").write_text("log", encoding="utf-8")
        (base / "app.py").write_text("print()", encoding="utf-8")

        scanner = FimScanner(
            paths=[base],
            exclude_patterns=["node_modules", f"{logs}/"],
        )
        assert scanner.is_excluded(str(nm / "index.js")) is True
        assert scanner.is_excluded(str(logs / "app.log")) is True
        assert scanner.is_excluded(str(base / "app.py")) is False

        results, summary = scanner.scan()
        assert str(base / "app.py") in results
        assert str(nm / "index.js") not in results
        assert str(logs / "app.log") not in results

    def test_max_files_limit_enforced(self, tmp_path: Path) -> None:
        base = tmp_path / "limit_test"
        base.mkdir()
        for i in range(10):
            (base / f"file_{i}.txt").write_text(f"content {i}", encoding="utf-8")

        # Set max_files to 5 (including directory itself)
        scanner = FimScanner(paths=[base], max_files=5)
        results, summary = scanner.scan()

        assert len(results) == 5
        assert summary.is_complete is False
        assert any("max_files_limit_reached" in err.get("error", "") for err in summary.errors)

    def test_default_excludes_tmp_directory(self) -> None:
        """Verify DEFAULT_EXCLUDE_PATTERNS correctly excludes /tmp and /var/tmp.

        This is a regression test ensuring the production scanner always
        excludes temporary directories by default. These exclusions are a
        security feature — they prevent the FIM scanner from monitoring
        volatile temporary files in production.
        """
        assert "/tmp*" in DEFAULT_EXCLUDE_PATTERNS
        assert "/var/tmp*" in DEFAULT_EXCLUDE_PATTERNS
        assert "/proc*" in DEFAULT_EXCLUDE_PATTERNS
        assert "/sys*" in DEFAULT_EXCLUDE_PATTERNS

        # Verify a default scanner excludes /tmp paths
        scanner = FimScanner(paths=["/nonexistent"])
        assert scanner.is_excluded("/tmp") is True
        assert scanner.is_excluded("/tmp/pytest-of-ubuntu/test0") is True
        assert scanner.is_excluded("/var/tmp/somefile") is True
        # Paths outside /tmp must not be excluded by default
        assert scanner.is_excluded("/home/user/project") is False
        assert scanner.is_excluded("/opt/osiris/data") is False
