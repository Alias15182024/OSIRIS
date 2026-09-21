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
  190 passed, 12 skipped in 0.59s
  ```
  - 190 tests passed.
  - 12 skipped:
    - 11 Linux integration tests (cleanly skipped due to absence of Linux `/proc` and `inotify`)
    - 1 SQLite CHECK constraint test

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
   190 passed, 12 skipped in 0.59s
   ```
   *(190 passed; 12 skipped cleanly: 11 Linux integration tests, 1 SQLite CHECK constraint test).*
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

---

# OSIRIS Milestone 1.5: Backend REST API Walkthrough

## Summary of Completed Work
Milestone 1.5 (Backend REST API) provides authenticated, validated RESTful HTTP endpoints exposing OSIRIS observational data (events, processes, system resources, and files) backed by PostgreSQL and FastAPI.

All Phase 1.5 components (Steps 1 through 4E, along with database seeding compatibility) have been implemented, verified through automated unit tests, validated against OpenAPI 3.1.0 specifications, and exercised against a live PostgreSQL 18.6 instance on macOS Darwin.

---

## 1. Components Implemented

### 1.1 Security & Cryptographic Utilities ([`backend/api/security.py`](file:///Users/alias/Desktop/OSIRIS/backend/api/security.py))
- **Password Hashing:** PBKDF2-HMAC-SHA256 standard library implementation (`100,000` iterations, 16-byte cryptographically secure salt) with constant-time verification (`hmac.compare_digest`). Formatted as `pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>`.
- **Token Issuance & Verification:** Lightweight HMAC-SHA256 signed access tokens utilizing URL-safe Base64 encoding. Supports token expiration (`exp`), subject claims (`sub`), username, and role attributes with tampered signature detection.
- **Audit Logging Helper:** Helper `record_audit_log()` recording structured authentication and administrative events into PostgreSQL table `app_audit_log`.

### 1.2 Pydantic API Schemas ([`backend/api/schemas/`](file:///Users/alias/Desktop/OSIRIS/backend/api/schemas/))
- **Pydantic v2 Models:** Configured with `from_attributes=True` for seamless ORM entity serialization.
- **Authentication:** `LoginRequest`, `TokenResponse`, `UserResponse`.
- **Status:** `StatusResponse` reporting system health, version, host ID, and database connectivity.
- **Observational Schemas:**
  - `EventResponse`, `EventQueryParams`, `PaginatedEventResponse`
  - `ProcessResponse`, `ProcessQueryParams`, `PaginatedProcessResponse`
  - `ResourceSnapshotResponse`, `ResourceSnapshotQueryParams`, `PaginatedResourceSnapshotResponse`
  - `FileResponse`, `FileQueryParams`, `PaginatedFileResponse`
- **Standardized Pagination:** All collection queries share a consistent envelope: `{ total: int, items: list[...], limit: int, offset: int }`.
- **Files API Field Contract:** `FileResponse` strictly exposes only the approved Phase 1.5 fields: `id`, `host_id`, `path`, `inode`, `file_type`, `first_seen_at`, `last_seen_at`, and `created_at`.

### 1.3 API & Database Dependencies ([`backend/api/deps.py`](file:///Users/alias/Desktop/OSIRIS/backend/api/deps.py))
- **`get_db()`:** FastAPI generator yielding a SQLAlchemy `Session` from `SessionLocal` with guaranteed session teardown in `finally`.
- **`get_current_user()`:** Bearer token authentication dependency using `HTTPBearer`. Decodes token claims, validates user identity and `is_active` status against `AppUser`, and raises HTTP 401 on missing, malformed, expired, or tampered credentials.

### 1.4 REST Route Handlers ([`backend/api/routes/`](file:///Users/alias/Desktop/OSIRIS/backend/api/routes/))
- **Public Endpoints:**
  - `GET /health` &mdash; Lightweight liveness check (`backend/main.py`).
  - `GET /api/status` &mdash; Detailed platform health reporting database status (`connected` / `disconnected`), sanitized against internal database credential leakage.
- **Authentication Routes (`backend/api/routes/auth.py`):**
  - `POST /api/auth/login` &mdash; Authenticates credentials against `AppUser`, issues signed access token, and writes an audit log entry.
  - `GET /api/auth/me` &mdash; Returns current authenticated user profile.
- **Events API (`backend/api/routes/events.py`):**
  - `GET /api/events` &mdash; Filterable by `host_id`, `start_time`, `end_time`, `source`, `event_type`, `severity`, `process_id`, `pid`, `username`, `success`. Deterministic ordering: `timestamp ASC, id ASC`.
  - `GET /api/events/{event_id}` &mdash; Single event lookup with 404 handling.
- **Processes API (`backend/api/routes/processes.py`):**
  - `GET /api/processes` &mdash; Filterable by `host_id`, `pid`, `ppid`, `linux_user_id`, `command` substring, `state`. Deterministic ordering: `started_at ASC, id ASC`.
  - `GET /api/processes/{process_id}` &mdash; Single process lookup with 404 handling.
- **Resources API (`backend/api/routes/resources.py`):**
  - `GET /api/resources` &mdash; Filterable by `host_id`, `start_time`, `end_time`. Deterministic ordering: `timestamp ASC, id ASC`.
- **Files API (`backend/api/routes/files.py`):**
  - `GET /api/files` &mdash; Filterable by `host_id`, `file_type`, and `path` prefix. Directory boundaries are strictly enforced (e.g. `/tmp` matches `/tmp` and `/tmp/file.txt`, but never `/tmp2/file.txt`), with SQL wildcards (`%`, `_`) safely escaped. Deterministic ordering: `first_seen_at ASC, id ASC`.

### 1.5 Database Seed Compatibility ([`database/seeds/seed_phase1.py`](file:///Users/alias/Desktop/OSIRIS/database/seeds/seed_phase1.py))
- **Compatibility Alignment:** Updated the initial development seed script to hash the default development admin user password using `hash_password("changeme")`.
- **Security Notice:** The default password `"changeme"` is intended strictly for development and automated testing environments; production deployments must supply unique credentials via secure provisioning.

---

## 2. Verification & Validation Results

### 2.1 Automated Unit Tests (Cross-Platform via pytest)
All Phase 1.5 components were tested using in-memory and isolated transactional sessions:

- **Full Project Suite:**
  ```text
  331 passed, 12 skipped, 2 warnings in 2.63s
  ```
  *(12 skipped: 11 Linux integration tests cleanly skipped on macOS due to absence of Linux `/proc` and `inotify`; 1 SQLite CHECK constraint test).*

- **Phase 1.5 Focused Suite (141 passed):**
  - [`tests/unit/test_security.py`](file:///Users/alias/Desktop/OSIRIS/tests/unit/test_security.py): 22 passed (hashing, verification, token issuance, tampering detection, audit logging).
  - [`tests/unit/test_schemas.py`](file:///Users/alias/Desktop/OSIRIS/tests/unit/test_schemas.py): 33 passed (Pydantic validation, serialization, nullable field handling).
  - [`tests/unit/test_api_deps.py`](file:///Users/alias/Desktop/OSIRIS/tests/unit/test_api_deps.py): 16 passed (`get_db` lifecycle, bearer token extraction, inactive user handling).
  - [`tests/unit/test_api_auth.py`](file:///Users/alias/Desktop/OSIRIS/tests/unit/test_api_auth.py): 12 passed (login success, invalid credentials, token issuance, `/api/auth/me`).
  - [`tests/unit/test_api_status.py`](file:///Users/alias/Desktop/OSIRIS/tests/unit/test_api_status.py): 6 passed (health reporting, database disconnection fallback, information leak prevention).
  - [`tests/unit/test_api_events.py`](file:///Users/alias/Desktop/OSIRIS/tests/unit/test_api_events.py): 18 passed (filtering, pagination, ordering, 404 handling).
  - [`tests/unit/test_api_processes.py`](file:///Users/alias/Desktop/OSIRIS/tests/unit/test_api_processes.py): 14 passed (command substring matching, state filtering, pagination).
  - [`tests/unit/test_api_resources.py`](file:///Users/alias/Desktop/OSIRIS/tests/unit/test_api_resources.py): 4 passed (time-range filtering, pagination, ordering).
  - [`tests/unit/test_api_files.py`](file:///Users/alias/Desktop/OSIRIS/tests/unit/test_api_files.py): 14 passed (directory-boundary prefix filtering, wildcard escaping, pagination).
  - [`tests/unit/test_seed_phase1.py`](file:///Users/alias/Desktop/OSIRIS/tests/unit/test_seed_phase1.py): 2 passed (seed generation, admin user hash verification, idempotency).

### 2.2 OpenAPI 3.1.0 Specification Verification
- Inspected the generated schema at `/openapi.json`.
- All 10 documented endpoints are registered under `paths`.
- `HTTPBearer` security scheme is configured in `components.securitySchemes`.
- Protected endpoints explicitly declare `security: [{"HTTPBearer": []}]`; public endpoints declare empty security requirements.

### 2.3 Live PostgreSQL 18.6 API Smoke Test (`osiris_dev`)
*Executed against the live PostgreSQL 18.6 service on macOS Darwin (distinguished from automated test fixtures).*

1. **Service Connectivity:** Verified live connection to `postgresql://localhost:5432/osiris_dev`.
2. **Controlled Development Seed Update:** The development `admin` account in `app_users` was updated to the standard PBKDF2 hash format using `hash_password("changeme")`.
3. **End-to-End API Smoke Test Results:**
   - `GET /health` &rarr; `200 OK` (`{"status": "ok", "system": "osiris"}`)
   - `GET /api/status` &rarr; `200 OK` (`{"status": "healthy", "database": "connected"}`)
   - `POST /api/auth/login` &rarr; `200 OK` (authenticated development admin; issued bearer token; recorded login in `app_audit_log`)
   - `GET /api/auth/me` &rarr; `200 OK` (returned authenticated admin user profile)
   - `GET /api/events` &rarr; `200 OK` (total: 0)
   - `GET /api/processes` &rarr; `200 OK` (total: 1)
   - `GET /api/resources` &rarr; `200 OK` (total: 1)
   - `GET /api/files` &rarr; `200 OK` (total: 1)
4. **Authentication Boundary Verification:**
   - Unauthenticated requests to protected endpoints (`/api/auth/me`, `/api/events`, `/api/processes`, `/api/resources`, `/api/files`) consistently returned `401 Unauthorized` (`{"detail": "Missing authentication credentials"}`).
   - Malformed or invalid bearer tokens returned `401 Unauthorized` (`{"detail": "Invalid or malformed token"}`).

*(Note: Live Linux collector integration was validated separately in Milestone 1.4E on Ubuntu 22.04 and was not part of the macOS Phase 1.5 API smoke test).*

---

## 3. Milestone 1.6: Basic Web Dashboard Walkthrough

### 3.1 Overview & Architecture
Milestone 1.6 delivers a lightweight, pure vanilla HTML5/CSS3/JavaScript Single Page Application (SPA) web interface for forensic investigation and live system telemetry monitoring.

- **FastAPI Static Serving:** Root route (`GET /` &rarr; `frontend/templates/index.html`) and static asset mount (`/static` &rarr; `frontend/static/`).
- **No Third-Party Runtime Dependencies:** Zero Node.js, React, Vue, Angular, jQuery, Chart.js, or D3.
- **Pure Vector Telemetry Visualizations:** SVG charts constructed dynamically with `document.createElementNS` for responsive, accessible time-series data rendering.
- **Centralized Client Authentication:** `frontend/static/js/api.js` manages access tokens in `sessionStorage` (never `localStorage`), injects Authorization headers, and triggers automatic session expiration hooks on HTTP 401.

### 3.2 Implemented Views & Components
1. **Application Shell & Authentication:**
   - Dark cybersecurity aesthetic with CSS custom properties.
   - Header with status indicators, authenticated user profile, and sign-in/logout modal controls.
   - Navigation bar toggling across the five investigative domains.
2. **Dashboard Overview (`frontend/static/js/views/dashboard.js`):**
   - Platform status card (`GET /api/status`).
   - Latest resource utilization card (`GET /api/resources?limit=1`).
   - Observational inventory counters (Events, Processes, Files).
   - Recent events table (`GET /api/events?limit=5`).
3. **Event Explorer (`frontend/static/js/views/events.js`):**
   - Filter controls: `host_id`, `start_time`, `end_time`, `source`, `event_type`, `severity`, `process_id`, `pid`.
   - Event list with severity badges, timestamp formatting, and pagination.
   - Event Detail Inspector modal with raw JSON payload viewer.
4. **Process List (`frontend/static/js/views/processes.js`):**
   - Filter controls: `host_id`, `pid`, `is_active`.
   - Process list with active/terminated status badges and command line inspection.
   - Process Detail Inspector modal with executable, PPID, and start/end times.
5. **Resource Charts (`frontend/static/js/views/resources.js`):**
   - Current metric summary cards (CPU, Memory %, Memory Used/Total, Disk Usage, Disk I/O).
   - Four native SVG time-series charts (CPU Utilization, Memory Utilization, Disk Read & Write Bytes, Disk Usage).
   - Accessible companion snapshots data table with pagination.
6. **Files Explorer (`frontend/static/js/views/files.js`):**
   - Directory-boundary path prefix search, file type filtering, and host ID filtering.
   - Filesystem table with prominent word-breaking path rendering, file type badges, and inode values.
   - File Detail Inspector modal.

### 3.3 Security & Quality Guardrails
- **Zero `localStorage`:** Authentication tokens are stored exclusively in memory and `sessionStorage`.
- **Zero `innerHTML`:** All user-facing data rendering uses `document.createElement` and `textContent`.
- **Sanitized Parameterization:** All query strings constructed via `URLSearchParams`.
- **Strict Error Containment:** All network failures catch and display structured errors without exposing internal database or stack trace details.

### 3.4 Verification & Test Results
- **Full Workspace Pytest Suite:** 463 passed, 12 skipped in 3.23s.
- **Phase 1.6 Frontend Contract Suite:** 132 passed across 7 test suites.
- **JavaScriptCore Runtime Syntax Validation:** All 7 JavaScript files validated with `jsc` (exit code 0).
