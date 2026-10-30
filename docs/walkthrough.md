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

---

# OSIRIS Milestone 2.1: Historical Storage, Snapshots, and Snapshot Retrieval API Walkthrough

## Summary of Completed Work
Milestone 2.1 establishes point-in-time forensic snapshot capturing, historical session tracking foundations, and authenticated RESTful retrieval endpoints for stored system-state snapshots.

All components of Milestone 2.1 have been implemented, verified, and validated:
1. **Database Models & Migration 0003**: `Snapshot` and `UserSession` models mapped to PostgreSQL (`JSONB`) and SQLite (`JSON`) with composite index `ix_snapshots_host_ts`.
2. **Snapshot Creation Service**: `SnapshotService` in `backend/services/snapshots/service.py` captures active processes and latest resource metrics into a unified snapshot record, maintaining strict caller transaction ownership.
3. **Pydantic Schemas**: `backend/api/schemas/snapshots.py` provides `SnapshotQueryParams`, `SnapshotResponse`, and `PaginatedSnapshotResponse` with validation for UUIDs, ISO 8601 timestamps, and arbitrary JSON payloads.
4. **Snapshot Retrieval REST API**: `backend/api/routes/snapshots.py` provides authenticated endpoints `GET /api/snapshots` and `GET /api/snapshots/{snapshot_id}`.
5. **Full Test Coverage**: 31 comprehensive API tests in `tests/unit/test_api_snapshots.py`, 38 service tests in `tests/unit/test_snapshot_service.py`, and 44 schema tests in `tests/unit/test_schemas.py`.

---

## 1. Components Implemented

### 1.1 Database Architecture (Migration 0003)
- **`snapshots` table** (`backend/db/models/snapshot.py`):
  - Primary key: `id` (UUID4).
  - Foreign key: `host_id` referencing `hosts.id`.
  - Column: `timestamp` (TIMESTAMPTZ / UTC datetime).
  - Column: `snapshot_type` (VARCHAR(100), default `'system_state'`).
  - Column: `data` (JSONB on PostgreSQL, JSON on SQLite, not null).
  - Column: `created_at` (TIMESTAMPTZ / UTC datetime, default `utcnow`).
  - Index: `ix_snapshots_host_ts` on `(host_id, timestamp)`.
- **`sessions` table** (`backend/db/models/user_session.py`):
  - Primary key: `id` (UUID4).
  - Foreign key: `host_id` referencing `hosts.id`.
  - Foreign key: `linux_user_id` referencing `linux_users.id` (nullable).
  - Columns: `session_type`, `terminal`, `remote_host`, `started_at`, `ended_at`, `created_at`.
  - Indexes: `ix_sessions_host_started`, `ix_sessions_linux_user_id`.

### 1.2 Snapshot Creation Service (`backend/services/snapshots/service.py`)
- **Forensic History**: Every invocation persists a new immutable snapshot record. Previous snapshots are never overwritten.
- **Transaction Ownership**: The service executes `session.flush()` to surface database constraint violations immediately, but **never** calls `session.commit()` or `session.rollback()`. Transaction boundaries and rollbacks remain strictly caller-owned.
- **Exception Hierarchy**:
  - `SnapshotError`: Base class for service exceptions.
  - `HostNotFoundError`: Raised when the target `host_id` does not exist in `hosts`.
  - `SnapshotPersistenceError`: Raised when the database rejects an insert, attaching the underlying SQLAlchemy exception as `cause` / `__cause__`.
- **Graceful Degradation**: Empty process lists (`[]`) or absent resource telemetry (`null`) are recorded faithfully without error.

### 1.3 Pydantic Schemas (`backend/api/schemas/snapshots.py`)
- **`SnapshotQueryParams`**:
  - `host_id` (Optional[UUID]): Filter by monitored host UUID.
  - `snapshot_type` (Optional[str]): Filter by snapshot type (e.g., `'system_state'`).
  - `start_time` (Optional[datetime]): Earliest snapshot timestamp (inclusive).
  - `end_time` (Optional[datetime]): Latest snapshot timestamp (inclusive).
  - `limit` (int, default=50, ge=1, le=100): Maximum records per page.
  - `offset` (int, default=0, ge=0): Pagination record offset.
- **`SnapshotResponse`**:
  - `id` (UUID), `host_id` (UUID), `timestamp` (datetime), `snapshot_type` (str), `data` (dict[str, Any]), `created_at` (datetime).
  - Configured with `model_config = ConfigDict(from_attributes=True)` for seamless ORM model serialization.
  - Prevents information leakage: strictly exposes snapshot attributes without leaking internal database metadata or host relationships.
- **`PaginatedSnapshotResponse`**:
  - Standard pagination envelope: `{ total: int, items: list[SnapshotResponse], limit: int, offset: int }`.

### 1.4 REST Endpoints (`backend/api/routes/snapshots.py`)

#### `GET /api/snapshots`
- **Description**: Returns a paginated list of snapshots matching specified filters.
- **Security**: Requires Bearer token authentication via `get_current_user`.
- **Ordering**: Deterministic ordering with newest snapshots first (`Snapshot.timestamp.desc()`), and a stable secondary tie-breaker (`Snapshot.id.desc()`).
- **Filters**:
  - `host_id`: UUID
  - `snapshot_type`: String match
  - `start_time` / `end_time`: UTC-aware datetime comparisons (inclusive). Validates `start_time <= end_time` (returns HTTP 400 Bad Request if inverted; returns HTTP 400 if mixing naive and aware datetimes).
- **Example Request**:
  ```http
  GET /api/snapshots?host_id=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa&snapshot_type=system_state&limit=2&offset=0 HTTP/1.1
  Host: localhost:8000
  Authorization: Bearer <valid_jwt_token>
  ```
- **Example Response (200 OK)**:
  ```json
  {
    "total": 3,
    "items": [
      {
        "id": "22222222-2222-4222-8222-222222222222",
        "host_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "timestamp": "2026-03-01T12:00:10Z",
        "snapshot_type": "system_state",
        "data": {
          "processes": [
            {
              "id": "99999999-9999-4999-8999-999999999999",
              "pid": 101,
              "ppid": 1,
              "command": "/usr/bin/python3",
              "executable": "/usr/bin/python3",
              "linux_user_id": null,
              "started_at": "2026-03-01T11:00:00Z"
            }
          ],
          "resources": {
            "id": "88888888-8888-4888-8888-888888888888",
            "timestamp": "2026-03-01T12:00:10Z",
            "cpu_percent": 15.2,
            "memory_total": 16000000000,
            "memory_used": 4000000000,
            "memory_percent": 25.0,
            "disk_read_bytes": 1048576,
            "disk_write_bytes": 2097152,
            "disk_usage_percent": 45.5
          }
        },
        "created_at": "2026-03-01T12:00:10Z"
      }
    ],
    "limit": 2,
    "offset": 0
  }
  ```

#### `GET /api/snapshots/{snapshot_id}`
- **Description**: Retrieves a single snapshot by UUID.
- **Security**: Requires Bearer token authentication via `get_current_user`.
- **Validation**:
  - Returns `422 Unprocessable Entity` if `snapshot_id` is not a valid UUID.
  - Returns `404 Not Found` with `{"detail": "Snapshot not found"}` if the snapshot does not exist.
- **Example Request**:
  ```http
  GET /api/snapshots/22222222-2222-4222-8222-222222222222 HTTP/1.1
  Host: localhost:8000
  Authorization: Bearer <valid_jwt_token>
  ```
- **Example Response (200 OK)**:
  ```json
  {
    "id": "22222222-2222-4222-8222-222222222222",
    "host_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "timestamp": "2026-03-01T12:00:10Z",
    "snapshot_type": "system_state",
    "data": {
      "processes": [],
      "resources": null
    },
    "created_at": "2026-03-01T12:00:10Z"
  }
  ```

### 1.5 Error Handling & Security Model
| Status Code | Reason | Response Detail |
|-------------|--------|-----------------|
| `400 Bad Request` | Inverted time range | `{"detail": "start_time must be less than or equal to end_time"}` |
| `400 Bad Request` | Mixed naive and aware datetimes | `{"detail": "Cannot compare timezone-aware and naive datetimes"}` |
| `401 Unauthorized` | Missing Authorization header | `{"detail": "Missing authentication credentials"}` |
| `401 Unauthorized` | Invalid or malformed token | `{"detail": "Invalid or malformed token"}` |
| `401 Unauthorized` | Expired token | `{"detail": "Token has expired"}` |
| `403 Forbidden` | Inactive user account | `{"detail": "Inactive user account"}` |
| `404 Not Found` | Nonexistent snapshot UUID | `{"detail": "Snapshot not found"}` |
| `422 Unprocessable Entity` | Malformed UUID or out-of-range limit/offset | Standard FastAPI validation error envelope |

---

## 2. Test Verification & Results

### 2.1 Test Suite Breakdown
- **Full Workspace Pytest Suite**:
  ```text
  837 passed, 12 skipped, 30 warnings in 14.19s
  ```
  *(12 skipped: 11 Linux integration tests cleanly skipped on macOS Darwin due to lack of Linux `/proc` and `inotify`; 1 SQLite CHECK constraint test).*
- **Phase 2 Milestone 2.1 Targeted Suites**:
  - `tests/unit/test_api_snapshots.py` (37 passed): Listing, single retrieval, host filtering, type filtering, start/end time filtering, exact timestamp filtering, pagination with offsets beyond total, ordering, 404/422 errors, authentication/authorization enforcement, edge cases (empty JSON, large payloads, timezone offsets, multi-host isolation, case-insensitive UUID), OpenAPI registration, and PostgreSQL end-to-end integration with transaction rollback.
  - `tests/unit/test_snapshot_service.py` (38 passed): Point-in-time creation, process & resource gathering, empty process handling, null resource handling, forensic immutability, caller-owned transaction discipline without service commits or rollbacks.
  - `tests/unit/test_schemas.py` (44 passed): Schema defaults, boundary validation, serialization, and ORM validation.

---

# OSIRIS Milestone 2.2: Forensic Timeline Reconstruction Walkthrough

## Summary of Completed Work
Milestone 2.2 provides unified forensic timeline reconstruction, entity correlation, and REST API access across all stored OSIRIS observational data (events, processes, user sessions, system-state snapshots, resource telemetry, and files).

All Milestone 2.2 components have been implemented, verified through automated unit and contract tests, validated against OpenAPI 3.1.0 specifications, and integrated into the frontend SPA dashboard.

---

## 1. Components Implemented

### 1.1 Forensic Entity Correlation Engine ([`backend/services/timeline/correlator.py`](file:///Users/alias/Desktop/OSIRIS/backend/services/timeline/correlator.py))
- **Process Correlation (`correlate_process_by_id`, `correlate_process_by_pid`):**
  - Host-scoped process resolution using `host_id`.
  - Lifetime bounding: matches processes where `started_at <= timestamp` and `(ended_at IS NULL or timestamp <= ended_at)`.
  - PID reuse safety: distinct process lifetimes sharing the same PID are disambiguated by timestamp; overlapping or ambiguous matches return `None` without guessing.
- **Linux User Correlation (`correlate_user`):**
  - Resolves Linux identities against `linux_users` table by `uid`, `linux_user_id`, or `username`.
  - Missing or unresolvable users are preserved faithfully with available source fields (`user_id=None`) without inventing fictitious records.
- **User Session Correlation (`correlate_session`):**
  - Matches active login sessions for a specific user on a monitored host where `started_at <= timestamp` and `(ended_at IS NULL or timestamp <= ended_at)`.
- **Filesystem Correlation (`correlate_file`):**
  - Resolves file paths against `files` table to attach inode and file type metadata.
- **Resource Telemetry Correlation (`correlate_resource`):**
  - Locates nearest point-in-time resource snapshot within temporal tolerance (default 300s).
- **Snapshot Correlation (`correlate_snapshot`):**
  - Identifies nearest system-state snapshot on host within temporal tolerance (default 3600s).
  - Inspects snapshot payload data to verify process containment (`process_captured=True/False`).
- **Cross-Host Isolation:**
  - Entities belonging to different hosts are never correlated.

### 1.2 Timeline Reconstruction Service ([`backend/services/timeline/service.py`](file:///Users/alias/Desktop/OSIRIS/backend/services/timeline/service.py))
- **Multi-Source Ingestion:** Unifies `events`, `processes`, `sessions`, `snapshots`, `resource_snapshots`, and `files`.
- **Deduplication:** Prevents duplicate entries when events already record process starts/terminations, session logons/logoffs, or filesystem changes.
- **Database Query Push-Down:** Constructs SQLAlchemy `UNION ALL` subqueries that execute filtering (`host_id`, `start_time`, `end_time`, `event_type`), pagination (`limit`, `offset`), and deterministic ordering (`timestamp ASC, source_id ASC`) directly inside SQL. Eliminates in-memory buffering of large historical datasets.
- **Deterministic Ordering:** Supports chronological (`order="asc"`, default) and reverse chronological (`order="desc"`) with stable secondary sorting.

### 1.3 Pydantic API Schemas ([`backend/api/schemas/timeline.py`](file:///Users/alias/Desktop/OSIRIS/backend/api/schemas/timeline.py))
- `ProcessContext`, `UserContext`, `SessionContext`, `FileContext`, `ResourceContext`, `SnapshotContext`.
- `TimelineEntryResponse` containing unified fields and entity context envelopes.
- `TimelineQueryParams` validating filtering and bounded pagination parameters.
- `PaginatedTimelineResponse` returning standardized `{ total, items, limit, offset }`.

### 1.4 Timeline REST API Endpoint ([`backend/api/routes/timeline.py`](file:///Users/alias/Desktop/OSIRIS/backend/api/routes/timeline.py))
- `GET /api/timeline` mounted in `backend/main.py`.
- Bearer token authentication required.
- Input validation:
  - 400 Bad Request on inverted time window (`start_time > end_time`).
  - 404 Not Found on nonexistent host UUID (`detail="Host not found"`).
  - 422 Unprocessable Entity on malformed UUID or invalid pagination limits.

### 1.5 Frontend Visualization ([`frontend/static/js/views/timeline.js`](file:///Users/alias/Desktop/OSIRIS/frontend/static/js/views/timeline.js))
- Forensic timeline stream view in dark cybersecurity theme.
- Displays chronological cards with severity badges, source provenance, and correlation chips (process, user, session, snapshot).
- Filter controls for host UUID, start/end time, record type, and ordering.
- Strict security: zero `innerHTML`, zero `localStorage`, zero `eval`. Validated cleanly in JavaScriptCore.

---

## 2. Test Verification & Results

### 2.1 Test Suite Breakdown
- **Full Workspace Pytest Suite**:
  ```text
  911 passed, 12 skipped, 30 warnings in 18.20s
  ```
- **Phase 2 Milestone 2.2 Targeted Suites**:
  - `tests/unit/test_timeline_service.py` (20 passed): Multi-source timeline, chronological ordering, causal sequence ordering (starts precede ends on identical timestamps), user filtering across username/uid/user_id, deduplication, host isolation, cross-host process sanitization, corrupt snapshot data tolerance, pagination.
  - `tests/unit/test_timeline_correlator.py` (12 passed): PID reuse, lifetime bounds, cross-host isolation, user/session/snapshot correlation, snapshot PID containment disambiguation, null data safety.
  - `tests/unit/test_api_timeline.py` (21 passed): Auth enforcement, query filtering (host, record_type, process_id, pid, username), global timeline, mixed naive/aware datetimes, pagination, negative pid/uid 422 validation, OpenAPI registration.
  - `tests/unit/test_timeline_view_contract.py` (14 passed): DOM structure, static security rules, JavaScriptCore syntax validation.
  - `tests/unit/test_schemas.py` (51 passed): Pydantic v2 timeline schemas, non-negative pid/uid constraints, and envelope validation.

---

# Phase 2 Milestone 2.3: Session Reconstruction & Tracking Walkthrough

## 1. Architecture & Component Summary

### 1.1 Syslog Collector & Parser ([`collectors/syslog/`](file:///Users/alias/Desktop/OSIRIS/collectors/syslog/))
- **Syslog Parser ([`collectors/syslog/parser.py`](file:///Users/alias/Desktop/OSIRIS/collectors/syslog/parser.py))**:
  - Implements multi-format header parsing covering RFC 3164 (BSD syslog, e.g., `Oct 30 14:02:11`) with current/leap year resolution, and RFC 5424/ISO 8601 (`2026-10-30T14:02:11.123456+00:00`).
  - Regex-driven message parsers classify SSH logins (`Accepted ...`), SSH failures (`Failed ...`), invalid users, PAM session open/close (`pam_unix(...:session): session opened/closed for user ...`), sudo command execution (`sudo: alice : TTY=pts/0 ; PWD=... ; USER=root ; COMMAND=...`), su transitions, systemd-logind sessions (`New session 42 of user ...`), and local console logins.
  - Generates structured event payloads with standardized field names (`event_type`, `action`, `user`, `uid`, `terminal`, `remote_host`, `sudo_target_user`, `sudo_command`, `systemd_session_id`).
- **Log Cursor & Rotation Manager ([`collectors/syslog/checkpoint.py`](file:///Users/alias/Desktop/OSIRIS/collectors/syslog/checkpoint.py))**:
  - Inode and device tracking detects standard log rotation (`auth.log` -> `auth.log.1`), copytruncate operations (size truncation without inode change), and file recreation.
  - Incrementally reads newly appended bytes, persisting cursor state for seamless restartability.
- **Syslog Collector ([`collectors/syslog/collector.py`](file:///Users/alias/Desktop/OSIRIS/collectors/syslog/collector.py))**:
  - Derives from `BaseCollector`, automatically discovering host auth logs across `/var/log/auth.log`, `/var/log/secure`, and `/var/log/syslog`.
  - Gracefully handles permission denied errors (common in unprivileged test or container environments) by emitting warning logs rather than crashing.

### 1.2 Session Reconstruction Engine ([`backend/services/sessions/service.py`](file:///Users/alias/Desktop/OSIRIS/backend/services/sessions/service.py))
- **Stateful Lifecycle Management**:
  - Reconstructs sessions from disparate log sources into the `user_sessions` table (`UserSession` model).
  - Handles OpenSSH multi-event login patterns (SSH `Accepted` followed by PAM `session opened`) via a 10-second correlation window to prevent duplicate session records.
  - Detects terminal reuse (`pts/0`) and terminates stale active sessions before creating new ones.
  - Matches explicit logout events (`pam_unix session closed`, `systemd-logind session removed`, console logout) to active sessions, setting `ended_at`.
- **Process Association & PID Reuse Protection**:
  - Links processes from the `processes` table to sessions based on `host_id`, `linux_user_id`, matching terminal (when present), and strict temporal containment:
    `session.started_at <= process.started_at <= (session.ended_at or NOW())`.
  - Disambiguates reused PIDs by strictly bounding process queries to the active lifetime of each session.
- **Sudo & Privilege Escalation Tracking**:
  - Sudo executions and `su` switches are recorded as security events tied to the session and user, preserving the interactive login user identity while recording the elevated target user and executed command.

### 1.3 Session Retrieval REST API ([`backend/api/routes/sessions.py`](file:///Users/alias/Desktop/OSIRIS/backend/api/routes/sessions.py))
- **`GET /api/sessions`**:
  - Paginated list of sessions with filtering by `host_id`, `username`, `session_type`, `is_active`, `start_time`, and `end_time`.
  - Returns `PaginatedSessionResponse` containing `SessionResponse` items, duration calculation, and total count.
- **`GET /api/sessions/{session_id}`**:
  - Detailed view of a single session returning `SessionDetailResponse`.
  - Includes user details, session metrics (duration, status), and a list of all associated processes (`ProcessSummary` with PID, name, cmdline, start/end time, state).
  - Returns 404 for nonexistent UUID and 422 for malformed UUID format.

### 1.4 Frontend Integration ([`frontend/static/js/views/sessions.js`](file:///Users/alias/Desktop/OSIRIS/frontend/static/js/views/sessions.js))
- **Sessions View Explorer**:
  - Modern cybersecurity UI featuring a responsive data table of login sessions.
  - Filter controls: Host UUID, Username, Session Type (SSH, TTY, Systemd), Active Only toggle.
  - Badges for session state (Active: Green pulse; Closed: Slate).
- **Session Detail Modal**:
  - Detailed session metadata (Session ID, Terminal, Remote Host, Duration, Start/End times).
  - Associated processes table showing command, PID, status, and lifetime.
  - "View in Timeline" navigation button directly linking to the forensic timeline with session filters applied.
- **Security & Hygiene**:
  - Zero `innerHTML`, zero `localStorage`, zero `eval`.
  - Cleanly passes Apple JavaScriptCore (`jsc`) syntax validation.

---

## 2. Test Verification & Results

### 2.1 Full Workspace Pytest Results
```text
================ 1002 passed, 12 skipped, 30 warnings in 15.34s ================
```

### 2.2 Milestone 2.3 Targeted Test Suites
- **`tests/unit/test_syslog_parser.py` (28 passed)**:
  - RFC 3164 and RFC 5424 formats, ISO timestamps without timezone offset, SSH accepted/failed/invalid, PAM session opened/closed, sudo execution with GROUP/ENV attributes, su transitions, systemd-logind sessions, console logins, generic log fallback, year-wrap edge cases.
- **`tests/unit/test_syslog_collector.py` (13 passed)**:
  - Cursor tracking, checkpoint file persistence across restarts, partial in-flight line buffering, log rotation detection via inode/device across `.1` and dateext formats, copytruncate detection, missing log tolerance, permission error handling.
- **`tests/unit/test_session_reconstruction.py` (14 passed)**:
  - Session creation from SSH and PAM, login deduplication within 10s window, multi-user isolation on same IP/port, terminal reuse closure, explicit logout handling without terminating unrelated sessions, sudo execution tracking, multi-host isolation.
- **`tests/unit/test_session_process_association.py` (8 passed)**:
  - Process matching by time window, terminal matching, cross-host isolation, PID reuse protection across time boundaries, child process hierarchy tracking via PPID, cross-user root command segregation.
- **`tests/unit/test_api_sessions.py` (12 passed)**:
  - Bearer authentication enforcement, paginated listings, filtering (username, host, is_active, time bounds), single session detail with processes, 404/422 responses.
- **`tests/unit/test_sessions_view_contract.py` (10 passed)**:
  - DOM structure compliance, zero `innerHTML`, zero `localStorage`, zero `eval`, JavaScriptCore syntax verification.
- **`tests/integration/test_session_lifecycle_integration.py` (1 passed)**:
  - Full end-to-end integration: parsing auth log, session reconstruction, process correlation, timeline reconstruction, and REST API verification.
- **`tests/unit/test_schemas.py` (56 passed)**:
  - Validation of `SessionQueryParams`, `SessionResponse`, `SessionDetailResponse`, `PaginatedSessionResponse`, `ProcessSummary`.
- **`tests/unit/test_phase16_integration.py` (26 passed)**:
  - All API routes and contracts verified across frontend files.
- **Apple JavaScriptCore (`jsc`) Validation**:
  - All 9 frontend JavaScript scripts validated with zero syntax errors.
