"""Unit tests for OSIRIS FIM cryptographic fingerprinting service."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import unittest.mock as mock

import pytest

from backend.services.fim.fingerprint import (
    FileFingerprint,
    fingerprint_file,
    normalize_path,
)


class TestFingerprintNormalization:
    """Test deterministic path normalization."""

    def test_normalize_clean_paths(self) -> None:
        assert normalize_path("/etc/passwd") == "/etc/passwd"
        assert normalize_path("/etc/nginx/") == "/etc/nginx"
        assert normalize_path("/var/log/../log/syslog") == "/var/log/syslog"
        assert normalize_path("/") == "/"

    def test_normalize_relative_path(self) -> None:
        current_dir = os.path.abspath(".")
        assert normalize_path(".") == current_dir
        assert normalize_path("./test") == os.path.join(current_dir, "test")


class TestCryptographicFingerprinting:
    """Test file hashing and metadata extraction."""

    def test_sha256_known_vector_empty_file(self, tmp_path: Path) -> None:
        empty_file = tmp_path / "empty.txt"
        empty_file.write_bytes(b"")

        fp = fingerprint_file(empty_file)
        assert fp.file_type == "file"
        assert fp.size == 0
        assert fp.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert fp.error is None

    def test_sha256_known_vector_content(self, tmp_path: Path) -> None:
        test_file = tmp_path / "fox.txt"
        content = b"The quick brown fox jumps over the lazy dog"
        test_file.write_bytes(content)

        fp = fingerprint_file(test_file, include_sha1=True, include_md5=True)
        assert fp.file_type == "file"
        assert fp.size == len(content)
        assert fp.sha256 == hashlib.sha256(content).hexdigest()
        assert fp.sha1 == hashlib.sha1(content).hexdigest()
        assert fp.md5 == hashlib.md5(content).hexdigest()
        assert fp.error is None

    def test_streaming_large_file(self, tmp_path: Path) -> None:
        large_file = tmp_path / "large.bin"
        chunk_data = b"A" * 8192
        total_chunks = 32
        with open(large_file, "wb") as f:
            for _ in range(total_chunks):
                f.write(chunk_data)

        expected_sha256 = hashlib.sha256(chunk_data * total_chunks).hexdigest()
        fp = fingerprint_file(large_file, chunk_size=4096)
        assert fp.size == len(chunk_data) * total_chunks
        assert fp.sha256 == expected_sha256

    def test_unicode_and_unusual_filenames(self, tmp_path: Path) -> None:
        filename = "unicode_test_🔒_文件_файл.conf"
        file_path = tmp_path / filename
        file_path.write_text("secure config", encoding="utf-8")

        fp = fingerprint_file(file_path)
        assert fp.file_name == filename
        assert fp.file_type == "file"
        assert fp.sha256 == hashlib.sha256(b"secure config").hexdigest()
        assert fp.error is None

    def test_permissions_and_attributes(self, tmp_path: Path) -> None:
        test_file = tmp_path / "script.sh"
        test_file.write_text("#!/bin/sh\necho hello", encoding="utf-8")
        os.chmod(test_file, 0o755)

        fp = fingerprint_file(test_file)
        assert fp.permissions == "0755"
        assert fp.is_executable is True
        assert fp.is_suid is False
        assert fp.is_sgid is False
        assert fp.mtime is not None
        assert fp.inode is not None

    def test_symlink_safety_does_not_follow(self, tmp_path: Path) -> None:
        target_file = tmp_path / "target.txt"
        target_file.write_text("original target content", encoding="utf-8")

        link_file = tmp_path / "link.txt"
        os.symlink(str(target_file), str(link_file))

        fp = fingerprint_file(link_file)
        assert fp.file_type == "symlink"
        assert fp.symlink_target == str(target_file)
        # Hashed value is the target path bytes, not target file content
        assert fp.sha256 == hashlib.sha256(str(target_file).encode("utf-8")).hexdigest()

    def test_directory_fingerprint(self, tmp_path: Path) -> None:
        subdir = tmp_path / "sub_dir"
        subdir.mkdir()

        fp = fingerprint_file(subdir)
        assert fp.file_type == "directory"
        assert fp.sha256 is None
        assert fp.error is None

    def test_missing_file_handling(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.file"
        fp = fingerprint_file(missing)
        assert fp.file_type == "unknown"
        assert fp.error == "file_not_found"

    def test_unreadable_file_permission_error(self, tmp_path: Path) -> None:
        unreadable = tmp_path / "unreadable.key"
        unreadable.write_text("secret", encoding="utf-8")

        with mock.patch("os.lstat", side_effect=PermissionError("Permission denied")):
            fp = fingerprint_file(unreadable)
            assert fp.error == "permission_denied"
            assert fp.fingerprint_metadata.get("unreadable") is True

    def test_file_disappearing_during_open(self, tmp_path: Path) -> None:
        disappearing = tmp_path / "transient.tmp"
        disappearing.write_text("ephemeral", encoding="utf-8")

        with mock.patch("builtins.open", side_effect=FileNotFoundError("Disappeared")):
            fp = fingerprint_file(disappearing)
            assert fp.error == "file_disappeared_during_read"

    def test_toctou_concurrent_modification_detected(self, tmp_path: Path) -> None:
        mod_file = tmp_path / "concurrent.log"
        mod_file.write_text("initial", encoding="utf-8")

        real_lstat = os.lstat
        call_count = 0

        def mock_lstat(path):
            nonlocal call_count
            st = real_lstat(path)
            call_count += 1
            if call_count > 1:
                # Alter mtime on second call
                return os.stat_result((
                    st.st_mode,
                    st.st_ino,
                    st.st_dev,
                    st.st_nlink,
                    st.st_uid,
                    st.st_gid,
                    st.st_size + 10,  # size changed!
                    st.st_atime,
                    st.st_mtime + 5.0,  # mtime changed!
                    st.st_ctime,
                ))
            return st

        with mock.patch("os.lstat", side_effect=mock_lstat):
            fp = fingerprint_file(mod_file)
            assert fp.error == "concurrent_modification_detected"
            assert fp.fingerprint_metadata.get("concurrent_modification_detected") is True

    def test_oversized_file_skips_hash(self, tmp_path: Path) -> None:
        oversized = tmp_path / "huge.dat"
        oversized.write_bytes(b"X" * 1024)

        fp = fingerprint_file(oversized, max_file_size=512)
        assert fp.file_type == "file"
        assert fp.sha256 is None
        assert fp.fingerprint_metadata.get("oversized") is True
        assert fp.fingerprint_metadata.get("hash_skipped_reason") == "size_exceeds_max_limit"

    def test_special_file_skips_reading(self, tmp_path: Path) -> None:
        dummy = tmp_path / "fifo_mock"
        dummy.write_text("mock", encoding="utf-8")

        real_lstat = os.lstat

        def mock_fifo_lstat(path):
            st = real_lstat(path)
            # Replace S_IFREG with S_IFIFO
            fifo_mode = (st.st_mode & ~stat.S_IFREG) | stat.S_IFIFO
            return os.stat_result((
                fifo_mode,
                st.st_ino,
                st.st_dev,
                st.st_nlink,
                st.st_uid,
                st.st_gid,
                st.st_size,
                st.st_atime,
                st.st_mtime,
                st.st_ctime,
            ))

        with mock.patch("os.lstat", side_effect=mock_fifo_lstat):
            with mock.patch("builtins.open") as mock_open:
                fp = fingerprint_file(dummy)
                assert fp.file_type == "special"
                assert fp.fingerprint_metadata.get("special_kind") == "fifo"
                mock_open.assert_not_called()

    def test_symlink_swap_during_open_is_caught(self, tmp_path: Path) -> None:
        target = tmp_path / "swap_test.txt"
        target.write_text("content", encoding="utf-8")

        eloop_err = OSError("Too many levels of symbolic links")
        eloop_err.errno = 62  # errno.ELOOP

        with mock.patch("builtins.open", side_effect=eloop_err):
            fp = fingerprint_file(target)
            assert fp.error == "symlink_swap_detected"
            assert fp.fingerprint_metadata.get("symlink_swap") is True

    def test_inode_swap_during_open_detected(self, tmp_path: Path) -> None:
        target = tmp_path / "inode_swap.txt"
        target.write_text("initial", encoding="utf-8")

        real_fstat = os.fstat
        def mock_fstat(fd):
            st = real_fstat(fd)
            return os.stat_result((
                st.st_mode,
                st.st_ino + 9999,  # Inode swapped!
                st.st_dev,
                st.st_nlink,
                st.st_uid,
                st.st_gid,
                st.st_size,
                st.st_atime,
                st.st_mtime,
                st.st_ctime,
            ))

        with mock.patch("os.fstat", side_effect=mock_fstat):
            fp = fingerprint_file(target)
            assert fp.error == "concurrent_modification_detected"
            assert fp.fingerprint_metadata.get("concurrent_modification_detected") is True
