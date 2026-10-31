#!/usr/bin/env python3
"""OSIRIS Cross-Platform Test Runner.

Executes pytest with an isolated temporary directory located outside the FIM
scanner's default production exclusion paths (/tmp*, /var/tmp*).

On Linux/Ubuntu, pytest defaults to creating temporary directories under
/tmp/pytest-of-<user>/, which the OSIRIS FIM scanner intentionally excludes as
part of its production security baseline. This runner creates a unique temporary
directory under the user's home directory (~/.osiris_test_tmp/run_<pid>_<uuid>/),
passes it via pytest's --basetemp flag, and cleans up only that unique directory
after execution completes.

Usage:
    python scripts/run_tests.py [pytest options and test targets]
    ./scripts/run_tests.py tests/unit/test_fim_scanner.py -v
    ./scripts/run_tests.py -k "test_fim"
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any


def _is_safe_unique_dir(target_dir: Path, expected_parent: Path) -> bool:
    """Validate that target_dir is strictly a unique test run subdirectory."""
    try:
        resolved_target = target_dir.resolve()
        resolved_parent = expected_parent.resolve()
        resolved_home = Path.home().resolve()
    except Exception:
        return False

    # Must be inside the designated test tmp parent
    if resolved_target.parent != resolved_parent:
        return False

    # Must never be home or root
    if resolved_target == resolved_home or resolved_target == resolved_target.parent:
        return False

    # Name must match our runner's unique naming pattern
    if not resolved_target.name.startswith("run_"):
        return False

    return True


def run() -> int:
    """Run pytest with an isolated home-based temporary directory."""
    parent_tmp = (Path.home() / ".osiris_test_tmp").resolve()
    unique_run_id = f"run_{os.getpid()}_{uuid.uuid4().hex[:12]}"
    unique_dir = (parent_tmp / unique_run_id).resolve()

    # Create the unique directory safely
    unique_dir.mkdir(parents=True, exist_ok=True)

    # Check whether the caller explicitly supplied --basetemp
    has_basetemp = any(
        arg == "--basetemp" or arg.startswith("--basetemp=")
        for arg in sys.argv[1:]
    )

    cmd = [sys.executable, "-m", "pytest"]
    if not has_basetemp:
        cmd.append(f"--basetemp={unique_dir}")
    cmd.extend(sys.argv[1:])

    exit_code = 1
    proc: subprocess.Popen[Any] | None = None

    def _handle_signal(signum: int, _frame: Any) -> None:
        if proc and proc.poll() is None:
            proc.terminate()
        _cleanup(unique_dir, parent_tmp)
        sys.exit(128 + signum)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        proc = subprocess.Popen(cmd)
        proc.wait()
        exit_code = proc.returncode
    finally:
        _cleanup(unique_dir, parent_tmp)

    return exit_code


def _cleanup(unique_dir: Path, parent_tmp: Path) -> None:
    """Safely remove only the runner's unique directory."""
    if _is_safe_unique_dir(unique_dir, parent_tmp) and unique_dir.exists():
        shutil.rmtree(unique_dir, ignore_errors=True)
    # Attempt to remove parent if empty, ignore if not
    try:
        if parent_tmp.exists():
            parent_tmp.rmdir()
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(run())
