# OSIRIS Milestone 1.4: Linux Collectors & Orchestration Walkthrough

## Summary of Completed Work
Milestone 1.4 (Collectors, Orchestration, and Live Linux Integration: 1.4A–1.4E) has been fully implemented, verified, and validated according to the approved design and roadmap.

---

## 1. Components Implemented

### 1.1 Collectors & Orchestration
- **Process Collector** (`collectors/process/`): `/proc` parser, process start/end lifecycle tracking, `(pid, starttime)` composite keying, Linux-only platform enforcement.
- **Resource Collector** (`collectors/resource/`): `/proc/stat` CPU differential ticks, `/proc/loadavg`, `/proc/meminfo`, `/proc/diskstats` whole-disk filtering (512 bytes/sector), `os.statvfs` root filesystem usage.
- **Filesystem Collector** (`collectors/filesystem/`): Linux inotify ctypes backend, create/modify/delete/move events, cookie correlation for renames.
- **Collector Orchestrator** (`collectors/orchestrator.py`):
  - Transitions through `STOPPED -> STARTING -> RUNNING -> STOPPING -> STOPPED`.
  - Strict 4-step startup sequence: verify collectors -> register inotify watches -> start collectors -> enter `RUNNING` state.
  - Rollback on failure releasing watches and inotify descriptors without leaks.
  - Scheduling: filesystem drained every tick (0.5s); process interval (2.0s); resource interval (5.0s); `force_all=True` bypasses interval gating.
  - Cycle Serialization: protected by dedicated `_cycle_lock` so concurrent invocations (worker loop vs manual cycles) never interleave collection paths. `_cycle_lock` is not held across `start()` or `stop()`.
  - Injectable monotonic and wall clocks for deterministic interval testing without sleeps.
  - Error segmentation: `collector_errors` (`proc`, `resource`, `fs`), `processing_errors`, and `sink_errors` (`repository`, `callback`). `CycleResult.success` is `True` only when all three error collections are empty.

### 1.2 Package Exports: [`collectors/__init__.py`](file:///Users/alias/Desktop/OSIRIS/collectors/__init__.py)
- Exports `CollectorOrchestrator`, `OrchestratorConfig`, `CycleResult`, `OrchestratorState`, `OrchestratorError`, `CollectorStartupError`, `BaseCollector`, `ProcessCollector`, `ResourceCollector`, and `FilesystemCollector`.

### 1.3 Documentation
- [`docs/event-model.md`](file:///Users/alias/Desktop/OSIRIS/docs/event-model.md): Section 5 updated with complete specifications for Process Collector (§5.1), Filesystem Collector (§5.2), Resource Collector (§5.3), and Collector Orchestrator (§5.4).
- [`docs/development-roadmap.md`](file:///Users/alias/Desktop/OSIRIS/docs/development-roadmap.md): Milestone 1.4 marked completed (1.4A–1.4E) with Ubuntu 22.04 ARM64 live validation evidence.

---

## 2. Test Verification & Live Linux Validation

### 2.1 Unit Tests (Cross-Platform)
21 unit test cases in [`tests/unit/test_collector_orchestrator.py`](file:///Users/alias/Desktop/OSIRIS/tests/unit/test_collector_orchestrator.py) passing deterministically on macOS and Linux using mock collectors and fake clocks:
- Config parsing, defaults, and host ID conversion.
- Explicit startup order and watch registration.
- Startup failure rollback (closing backend and zero leaked watches).
- Cycle execution with deterministic fake clock (interval gating, filesystem every tick, `force_all=True`).
- Collector error isolation (process failure doesn't halt resource or filesystem).
- EventProcessor batch error isolation.
- Optional repository persistence and `sink_errors["repository"]` isolation without polluting `collector_errors`.
- Optional event callback invocation and `sink_errors["callback"]` isolation without polluting `collector_errors`.
- Background worker thread start/stop lifecycle.
- Context manager protocol.
- Telemetry status reporting.
- Idempotent cleanup and idempotent `stop()`.
- Granular resource event collection.
- Deterministic concurrent cycle execution serialization proving two threads cannot execute collector logic concurrently.

### 2.2 Live Linux Integration Tests (Ubuntu 22.04 ARM64 — Phase 1.4E)
All 11 live Linux integration tests executed and passed on the Ubuntu 22.04 ARM64 VM (gated on `sys.platform == 'linux'`):
- **Process Collector** ([`tests/integration/test_linux_process_collector.py`](file:///Users/alias/Desktop/OSIRIS/tests/integration/test_linux_process_collector.py)): 3 passed
  - Live `/proc` reads, PID enumeration, process lifecycle observation.
- **Filesystem Collector** ([`tests/integration/test_linux_filesystem_collector.py`](file:///Users/alias/Desktop/OSIRIS/tests/integration/test_linux_filesystem_collector.py)): 1 passed
  - Live kernel `inotify` event capture on file creation/modification in watched directory.
- **Resource Collector** ([`tests/integration/test_linux_resource_collector.py`](file:///Users/alias/Desktop/OSIRIS/tests/integration/test_linux_resource_collector.py)): 4 passed
  - Live reads from `/proc/stat`, `/proc/loadavg`, `/proc/meminfo`, `/proc/diskstats`, and `os.statvfs("/")`.
- **Collector Orchestrator** ([`tests/integration/test_linux_collector_orchestrator.py`](file:///Users/alias/Desktop/OSIRIS/tests/integration/test_linux_collector_orchestrator.py)): 3 passed
  - Unified live collection across process, resource, and filesystem subsystems.
  - Continuous background worker loop.
  - Live context manager lifecycle.

### 2.3 Full Test Suite Results
- **Ubuntu 22.04 ARM64 VM Validation Results**:
  ```text
  194 passed, 8 skipped in 1.81s
  ```
  - **194 tests passed**: 183 unit tests across database, event processing, collectors, and orchestrator, plus all 11 Linux subsystem integration tests.
  - **8 tests skipped**: 7 tests in `tests/integration/test_event_persistence.py` (which require an active PostgreSQL service at `postgresql://localhost:5432/osiris_dev`) and 1 test in `tests/unit/test_database.py` (SQLite CHECK constraint test). Live PostgreSQL persistence was not validated in this test run.
  - **0 failures, 0 errors**.

- **Development Host (macOS Darwin) Test Suite Results**:
  ```text
  183 passed, 19 skipped in 0.59s
  ```
  - 183 unit tests passed.
  - 19 skipped: 11 Linux integration tests (cleanly skipped due to absence of Linux `/proc` and `inotify`), 7 PostgreSQL tests (offline), 1 SQLite CHECK constraint test.

### 2.4 Verification Command Results

#### Ubuntu 22.04 ARM64 VM (Phase 1.4E Live Environment)
1. Full test suite:
   ```bash
   $ pytest -q
   194 passed, 8 skipped in 1.81s
   ```
2. Linux integration test suite:
   ```bash
   $ pytest -q \
       tests/integration/test_linux_process_collector.py \
       tests/integration/test_linux_filesystem_collector.py \
       tests/integration/test_linux_resource_collector.py \
       tests/integration/test_linux_collector_orchestrator.py
   11 passed in 1.11s
   ```

#### macOS/Darwin (Development Host)
1. Full test suite:
   ```bash
   $ pytest -q
   183 passed, 19 skipped in 0.59s
   ```
   *(183 unit tests passed; 19 skipped cleanly: 11 Linux integration tests, 7 offline PostgreSQL tests, 1 SQLite CHECK constraint test).*
2. Linux integration test suite:
   ```bash
   $ pytest -q \
       tests/integration/test_linux_process_collector.py \
       tests/integration/test_linux_filesystem_collector.py \
       tests/integration/test_linux_resource_collector.py \
       tests/integration/test_linux_collector_orchestrator.py
   11 skipped in 0.03s
   ```
   *(Cleanly skipped due to absence of Linux `/proc` and `inotify`).*
3. Whitespace and diff check:
   ```bash
   $ git diff --check
   # Clean (0 errors, no output)
   ```
