"""Cross-platform JavaScript runtime discovery for contract tests.

Discovers an available JavaScript runtime for syntax validation and execution,
preferring Node.js (most portable) and falling back to macOS JavaScriptCore.

Discovery order:
    1. ``node --check``   — Node.js (Linux, macOS, Windows)
    2. ``nodejs --check`` — Debian/Ubuntu alternative binary name
    3. macOS JavaScriptCore (``jsc``) — /System/Library/...

If no runtime is found, callers must skip the test with an actionable message
rather than failing with FileNotFoundError or reporting unexecuted checks as passed.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# macOS JavaScriptCore paths (order: Current symlink, then versioned A)
_JSC_PATHS = [
    "/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc",
    "/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc",
]

SKIP_REASON = (
    "No JavaScript runtime found. Install Node.js (https://nodejs.org/ "
    "or 'sudo apt install nodejs' on Ubuntu/Debian) or run on macOS "
    "with JavaScriptCore."
)


@dataclass(frozen=True)
class JsRuntime:
    """Describes a discovered JavaScript runtime."""

    name: str  # "node", "nodejs", or "jsc"
    binary: str  # Full path or command name

    def check_syntax(self, js_file: Path | str) -> subprocess.CompletedProcess[str]:
        """Validate JavaScript file syntax without executing top-level code.

        For Node.js / nodejs, uses ``--check <file>`` which parses without executing.
        For JSC, uses ``-e "checkSyntax('<file>')"` which validates parse errors.
        """
        path_str = str(Path(js_file).resolve())
        if self.name in ("node", "nodejs"):
            return subprocess.run(
                [self.binary, "--check", path_str],
                capture_output=True,
                text=True,
            )
        else:
            # JSC: use built-in checkSyntax() to parse without executing
            return subprocess.run(
                [self.binary, "-e", f"checkSyntax('{path_str}')"],
                capture_output=True,
                text=True,
            )

    def run_script(self, js_source: str) -> subprocess.CompletedProcess[str]:
        """Execute a JavaScript source string.

        When running on Node.js / nodejs, a print() polyfill is automatically
        prepended so that scripts using JSC's built-in print() work identically.
        """
        full_source = js_source
        if self.name in ("node", "nodejs"):
            polyfill = (
                "if (typeof print === 'undefined') { var print = console.log; }\n"
            )
            full_source = polyfill + js_source

        return subprocess.run(
            [self.binary, "-e", full_source],
            capture_output=True,
            text=True,
        )


# Module-level cache — None means "not yet searched"
_cached_runtime: Optional[JsRuntime | bool] = None


def find_js_runtime() -> Optional[JsRuntime]:
    """Discover an available JavaScript runtime, caching the result.

    Returns a :class:`JsRuntime` if found, ``None`` otherwise.
    """
    global _cached_runtime  # noqa: PLW0603
    if _cached_runtime is not None:
        return _cached_runtime if isinstance(_cached_runtime, JsRuntime) else None

    # 1. Try node (most common, cross-platform)
    node_path = shutil.which("node")
    if node_path:
        _cached_runtime = JsRuntime(name="node", binary=node_path)
        return _cached_runtime

    # 2. Try nodejs (Debian/Ubuntu alternative binary name)
    nodejs_path = shutil.which("nodejs")
    if nodejs_path:
        _cached_runtime = JsRuntime(name="nodejs", binary=nodejs_path)
        return _cached_runtime

    # 3. Try macOS JavaScriptCore
    for jsc_path in _JSC_PATHS:
        if Path(jsc_path).exists():
            _cached_runtime = JsRuntime(name="jsc", binary=jsc_path)
            return _cached_runtime

    _cached_runtime = False  # Sentinel: searched but not found
    return None
