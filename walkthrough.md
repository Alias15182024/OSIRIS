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

---

# Phase 2 Milestone 2.4: Detection Engine & Rules Foundation Walkthrough

## 1. Architecture & Component Summary

### 1.1 Declarative Detection Engine ([`backend/services/detection/`](file:///Users/alias/Desktop/OSIRIS/backend/services/detection/))
- **Safe Declarative AST Matcher ([`backend/services/detection/matcher.py`](file:///Users/alias/Desktop/OSIRIS/backend/services/detection/matcher.py))**:
  - Implements condition evaluation over telemetry events without `eval()` or `exec()`.
  - Supports 14 comparison operators: `==`, `!=`, `>`, `<`, `>=`, `<=`, `in`, `not_in`, `contains`, `startswith`, `endswith`, `regex`, `exists`, `not_exists`.
  - Supports recursive logical grouping nodes (`all`, `any`, `not`).
  - Dot-notation field extractor (`extract_field_value`) safely handles nested objects and returns structured evaluation details for every leaf node.
- **Temporal Sequence Correlator ([`backend/services/detection/sequence.py`](file:///Users/alias/Desktop/OSIRIS/backend/services/detection/sequence.py))**:
  - Reconstructs multi-event attack sequences over sliding time windows (`window_seconds`).
  - Enforces strict host boundary isolation: events are partitioned by `host_id` and events across distinct hosts are never correlated.
  - Correlates multi-event stages on shared identifiers (`match_field`, e.g., `data.user`).
  - Supports stage-specific event counts (`min_count`) and sequential transitions.
- **Rule Validator ([`backend/services/detection/validator.py`](file:///Users/alias/Desktop/OSIRIS/backend/services/detection/validator.py))**:
  - Parses YAML/JSON definitions with `yaml.safe_load`.
  - Validates all field types, categories, severities, regex syntax, and structural limits (max stages, window bounds, string lengths).
- **Rule Loader ([`backend/services/detection/rules_loader.py`](file:///Users/alias/Desktop/OSIRIS/backend/services/detection/rules_loader.py))**:
  - Discovers and loads rule definitions from YAML files with duplicate ID detection.
- **Detection Engine ([`backend/services/detection/engine.py`](file:///Users/alias/Desktop/OSIRIS/backend/services/detection/engine.py))**:
  - Unifies single-event evaluation (`evaluate_event`) and batch sequence evaluation (`evaluate_batch`).
  - Computes deterministic SHA-256 deduplication hashes over `host_id`, `rule_id`, canonical matched entities, and timestamp time buckets.
- **Detection Service ([`backend/services/detection/service.py`](file:///Users/alias/Desktop/OSIRIS/backend/services/detection/service.py))**:
  - Synchronizes file-based rules to the `detection_rules` table.
  - Evaluates events and persists new detections to `detections` table, preventing duplicates using `dedup_hash`.
  - Provides query filtering, pagination, and acknowledgment workflows.

### 1.2 Initial Rules Catalogue ([`backend/services/detection/rules/`](file:///Users/alias/Desktop/OSIRIS/backend/services/detection/rules/))
Nine production security rules:
1. `OSIRIS-PRIV-001`: Suspicious Sudo Execution (High, Sudo shell breakout / sensitive tool execution)
2. `OSIRIS-PRIV-002`: Privilege Binary Execution (Medium, Execution from `/tmp`, `/dev/shm`, `/var/tmp`)
3. `OSIRIS-PRIV-003`: Sudoers File Tampering (Critical, Unauthorized modifications to `/etc/sudoers*`)
4. `OSIRIS-AUTH-001`: Repeated Failed Logins (Medium, 5+ failed authentications within 300s window)
5. `OSIRIS-AUTH-002`: Failed Logins Followed by Successful Login (High, 3+ failures then success within 300s)
6. `OSIRIS-AUTH-003`: Remote SSH Root Login (High, Direct SSH login as root from external IP)
7. `OSIRIS-RECON-001`: Rapid System Discovery (Medium, 3+ system enumeration commands in 60s)
8. `OSIRIS-RECON-002`: User Account Enumeration (Low, Inspection of `/etc/passwd` or `/etc/shadow`)
9. `OSIRIS-RECON-003`: Sensitive System File Inspection (Critical, Access to SSH keys or shadow credentials)

### 1.3 Detection REST API ([`backend/api/routes/detections.py`](file:///Users/alias/Desktop/OSIRIS/backend/api/routes/detections.py))
- `GET /api/detections`: Paginated retrieval with filtering (`host_id`, `rule_id`, `severity`, `status`, `start_time`, `end_time`).
- `GET /api/detections/rules`: Rule catalog listing with optional category/severity/is_active filters.
- `GET /api/detections/rules/{rule_id}`: Single rule definition lookup.
- `GET /api/detections/{detection_id}`: Single detection lookup with explainability conditions tree and forensic evidence.
- `POST /api/detections/{detection_id}/acknowledge`: Analyst acknowledgment workflow recording timestamp and username.

### 1.4 Frontend Integration ([`frontend/static/js/views/detections.js`](file:///Users/alias/Desktop/OSIRIS/frontend/static/js/views/detections.js))
- Navigation tab with live alert count badge.
- Dashboard inventory counter (`invDetectionsCount`).
- Responsive detections data table with severity badges, status indicators, and time sorting.
- Interactive filter controls (Severity, Status, Rule ID).
- Detection Inspector Modal displaying rule metadata, MITRE techniques, explainability AST tree, raw forensic evidence, and one-click Acknowledge button.
- Strict security adherence: zero `innerHTML`, zero `localStorage`, zero `eval`, 100% textContent/createElement. Validated cleanly in JavaScriptCore.

---

## 2. Test Verification & Results

### 2.1 Full Workspace Pytest Results
```text
================ 1083 passed, 12 skipped, 40 warnings in 15.81s ================
```

### 2.2 Milestone 2.4 Targeted Test Suites
- **`tests/unit/test_migrations.py` (9 passed)**: Reversible migration 0004_detections_and_rules across SQLite and PostgreSQL, full up/down cycle verification.
- **`tests/unit/test_detection_rules.py` (14 passed)**: Rule models, YAML validation, operator validation, duplicate rules, invalid regex syntax, invalid schemas.
- **`tests/unit/test_detection_engine.py` (11 passed)**: Single-event AST evaluation, nested boolean logic (`all`/`any`/`not`), boolean type safety, explainability detail generation, idempotent rule registration.
- **`tests/unit/test_detection_sequence.py` (11 passed)**: Multi-stage sequence correlation, sliding time window expiration, host boundary isolation, match field correlation, multi-user attacker isolation, zero event reuse across stages, deterministic timestamp ordering.
- **`tests/unit/test_initial_rules.py` (18 passed)**: True-positive matching and true-negative non-matching tests for all 9 initial detection rules, including non-enumeration benign command isolation (`which`, `wc`, `wget`, `watch`).
- **`tests/unit/test_detection_persistence.py` (5 passed)**: Persistence service, rule synchronization, duplicate prevention via SHA-256 dedup_hash, acknowledgment state machine, foreign key cascades.
- **`tests/unit/test_api_detections.py` (10 passed)**: REST API auth enforcement, query filters, pagination, single detection inspection, acknowledge endpoint, OpenAPI route registration.
- **`tests/unit/test_detections_view_contract.py` (10 passed)**: Frontend contract tests verifying HTML structure, modal elements, table selectors, security hygiene (zero innerHTML/localStorage/eval), and JavaScriptCore syntax execution.
- **`tests/unit/test_phase16_integration.py` (26 passed)**: Cross-view API integration and route consistency.
- **Apple JavaScriptCore (`jsc`) Validation**: All 10 frontend JavaScript files validated with 0 syntax errors.

---

# Phase 2 Milestone 2.5: File Integrity Monitoring (FIM) Walkthrough

## 1. Architecture & Component Summary

### 1.1 Database Schema & Reversible Migrations ([`database/migrations/versions/0005_fim_baselines_and_deviations.py`](file:///Users/alias/Desktop/OSIRIS/database/migrations/versions/0005_fim_baselines_and_deviations.py))
- **`fim_baselines`**: Point-in-time cryptographic filesystem snapshots scoped by host and path.
  - Fields: `id`, `host_id`, `version`, `status` (`active`, `superseded`, `revoked`), `path_scope`, `include_patterns`, `exclude_patterns`, `total_files`, `total_bytes`, `scan_duration_ms`, `baseline_metadata`.
- **`fim_baseline_files`**: Per-file cryptographic digest and metadata entries.
  - Fields: `id`, `baseline_id`, `file_path`, `sha256_hash`, `sha1_hash`, `md5_hash`, `size_bytes`, `file_mode`, `uid`, `gid`, `mtime_epoch`, `is_symlink`, `symlink_target`, `attributes`.
  - Enforces `UNIQUE(baseline_id, file_path)`.
- **`fim_deviations`**: Detected filesystem anomalies between live storage and baseline state.
  - Fields: `id`, `baseline_id`, `host_id`, `detection_id`, `file_path`, `deviation_type` (`modified`, `added`, `removed`, `permission_changed`, `ownership_changed`), `severity`, `detected_at`, `expected_sha256`, `observed_sha256`, `expected_size`, `observed_size`, `expected_mode`, `observed_mode`, `expected_uid`, `observed_uid`, `expected_gid`, `observed_gid`, `details`.
- **Bidirectional Detection Link**:
  - `detections.fim_deviation_id` with `use_alter=True` links detections to deviations, while `fim_deviations.detection_id` links back to detections.

### 1.2 Cryptographic Fingerprinting Service ([`backend/services/fim/fingerprint.py`](file:///Users/alias/Desktop/OSIRIS/backend/services/fim/fingerprint.py))
- **Multi-Algorithm Hashing**: Primary SHA-256 with optional secondary SHA-1 and MD5 calculation in a single pass.
- **Chunked Streaming**: Streams files in 64 KB buffers, ensuring low memory footprint regardless of file size.
- **TOCTOU Race Detection**: Captures `stat` before and after stream hashing to detect concurrent modification during hash generation.
- **Symlink Protection**: Safe handling of symbolic links (`follow_symlinks=False` default) recording link targets without traversing outside scope.
- **Path Normalization**: Resolves and canonicalizes POSIX paths.

### 1.3 Baseline Filesystem Scanner ([`backend/services/fim/scanner.py`](file:///Users/alias/Desktop/OSIRIS/backend/services/fim/scanner.py))
- **Configurable Scope & Filters**: Supports root directory path, include glob patterns, and exclude glob patterns.
- **Safety Caps**: Enforces maximum directory recursion depth (default 32) and maximum file size (default 100 MB).
- **Graceful Error Recovery**: Resilient against permission denied errors, missing files, and broken links, capturing scan summaries with error counts.

### 1.4 Differential Integrity Comparator ([`backend/services/fim/comparator.py`](file:///Users/alias/Desktop/OSIRIS/backend/services/fim/comparator.py))
- **Change Classification**: Evaluates live scan fingerprints against baseline file records.
  - `modified`: SHA-256 hash or size changed.
  - `added`: File exists in live filesystem but not in baseline.
  - `removed`: File exists in baseline but missing from live filesystem.
  - `permission_changed`: File mode bits or SUID/SGID bits modified.
  - `ownership_changed`: UID or GID modified.
- **Granular Check Configuration**: Configurable verification toggles (`check_contents`, `check_permissions`, `check_ownership`).

### 1.5 FIM Service & Declarative Detection Integration ([`backend/services/fim/service.py`](file:///Users/alias/Desktop/OSIRIS/backend/services/fim/service.py))
- **Baseline Lifecycle**: Creates baselines, stores files in bulk, supersedes older active baselines for the same host.
- **On-Demand Verification**: Executes differential comparison and automatically transforms deviations into normalized telemetry events.
- **Declarative Security Detection Rules**:
  1. `OSIRIS-FIM-001` (Critical): Protected Configuration File Tampering (`/etc/pam.d/*`, `/etc/security/*`, `/etc/login.defs`, `/etc/sudoers*`).
  2. `OSIRIS-FIM-002` (Critical): Sensitive Authentication Database Tampering (`/etc/shadow`, `/etc/gshadow`, `/etc/passwd`, `/etc/group`).
  3. `OSIRIS-FIM-003` (Critical): Core System Executable Modification or Addition (`/bin/*`, `/sbin/*`, `/usr/bin/*`, `/usr/sbin/*`).
  4. `OSIRIS-FIM-004` (High): Suspicious Permission or SUID/SGID Bit Tampering.
  5. `OSIRIS-FIM-005` (High): SSH Authorized Keys or Host Keys Tampering (`.ssh/authorized_keys`, `/etc/ssh/ssh_host_*`).
  6. `OSIRIS-FIM-006` (High): System Startup Persistence Tampering (`/etc/cron*`, `/etc/systemd/system/*`, `/etc/init.d/*`).
- **Detection Association**: Newly triggered detections are bidirectionally associated with their causative `FimDeviation` records.

### 1.6 REST API ([`backend/api/routes/fim.py`](file:///Users/alias/Desktop/OSIRIS/backend/api/routes/fim.py))
- `GET /api/fim/baselines`: Query paginated baselines filtered by `host_id` and `status`.
- `POST /api/fim/baselines`: Create and record a new cryptographic baseline.
- `GET /api/fim/baselines/{id}`: Retrieve baseline metadata and summary.
- `GET /api/fim/baselines/{id}/files`: Paginated file entries for a baseline with path filtering.
- `GET /api/fim/deviations`: Query paginated deviations filtered by `host_id`, `baseline_id`, `file_path`, `deviation_type`, `severity`.
- `GET /api/fim/deviations/{id}`: Detailed view of a single deviation with expected vs. observed differences.
- `POST /api/fim/verify`: Trigger an on-demand verification check for a host.

### 1.7 Frontend FIM Dashboard ([`frontend/static/js/views/fim.js`](file:///Users/alias/Desktop/OSIRIS/frontend/static/js/views/fim.js))
- Modern dark-themed dashboard panel with sub-navigation tabs ("Integrity Deviations" and "Filesystem Baselines").
- Summary metric stat cards (Total Baselines, Active Deviations, Critical Deviations, Files Monitored).
- Interactive filter forms with URLSearchParams query sanitization.
- Deviation detail modal displaying side-by-side expected vs observed forensic comparisons.
- Baseline detail modal showing scan metrics and monitored file samples.
- Trigger verification modal for on-demand integrity verification runs.
- Strict security adherence: zero `innerHTML`, zero `localStorage`, zero `eval`. Validated cleanly in JavaScriptCore.

---

## 2. Test Verification & Results

### 2.1 Workspace Pytest Suite
All unit, migration, integration, and contract test suites execute cleanly with zero failures.

### 2.2 Milestone 2.5 Targeted Test Suites
- **`tests/unit/test_fim_fingerprint.py` (17 passed)**: SHA-256 calculation, optional secondary digests (SHA-1/MD5), file descriptor level validation with `O_NOFOLLOW` and `O_NONBLOCK`, TOCTOU modification detection, symlink swap detection, chunked streaming, permission handling.
- **`tests/unit/test_fim_scanner.py` (11 passed)**: Recursive scanning, path inclusion/exclusion globs, segment/folder name exclusions, directory resource limiting with `max_files`, root permission errors, walk errors marking partial scan completion.
- **`tests/unit/test_fim_comparator.py` (13 passed)**: Modified, added, deleted, permission, and ownership deviation detection, directory permission/ownership changes, file type transition detection, unreadable file detection, partial scan deletion prevention.
- **`tests/unit/test_fim_detection_integration.py` (6 passed)**: Rule evaluation against deviations across all 6 FIM rules, detection creation and bidirectional FK linkage, evidence enrichment with expected and observed metadata.
- **`tests/unit/test_fim_api.py` (11 passed)**: Baseline creation, baseline listing, baseline file inspection, deviation listing, deviation details, verification trigger endpoint, authentication enforcement, path format validation, and out-of-scope verification rejection.
- **`tests/unit/test_fim_view_contract.py` (10 passed)**: Markup element existence, security contract verification (zero innerHTML, zero localStorage, zero eval), Apple JavaScriptCore syntax execution.
- **`tests/unit/test_migrations.py` (11 passed)**: Full upgrade and downgrade testing for revision `0005_fim_baselines_deviations` on both SQLite and PostgreSQL.

---

# Phase 2 Milestone 2.6: Incident Lifecycle Management Walkthrough

Milestone 2.6 unifies the detection engine, forensic timeline, user sessions, system-state snapshots, process tracking, filesystem catalog, and file integrity monitoring into a cohesive incident lifecycle and evidence management framework.

All Milestone 2.6 components have been implemented, verified through automated unit and contract tests, validated against OpenAPI 3.1.0 specifications, and integrated into the frontend SPA dashboard.

---

## 1. Key Components & Implementation Summary

### 1.1 Relational Schema & Reversible Migrations
- **Revision `0006_incidents_and_evidence` (`database/migrations/versions/0006_incidents_and_evidence.py`)**:
  - `incidents`: Primary incident record tracking title, description, severity, status, category, host association, assignee, creator, observation bounds (`first_observed_at`, `last_observed_at`), and containment/resolution/closure audit timestamps and narratives.
  - `incident_events`: Many-to-many relationship mapping forensic audit telemetry directly to incidents with investigative notes and relationship labels.
  - `incident_evidence`: Polymorphic forensic evidence catalog with provenance metadata, supporting foreign keys to detections, events, FIM deviations, sessions, snapshots, processes, and files.
  - `incident_history`: Append-only immutable audit trail capturing lifecycle transitions, severity adjustments, analyst notes, and evidence associations.
- **Strict Integrity & Isolation**:
  - Check constraints for valid statuses (`open`, `investigating`, `contained`, `resolved`, `closed`) and severities (`info`, `low`, `medium`, `high`, `critical`).
  - Unique composite index `uq_incident_evidence_source` preventing duplicate evidence bindings.
  - Reversible Alembic upgrade and downgrade tested cleanly across both SQLite and PostgreSQL.

### 1.2 Incident Lifecycle State Machine & Service
- **Formal State Machine (`backend/services/incidents/lifecycle.py`)**:
  - Enforces permitted forward transitions (`open` → `investigating` → `contained` → `resolved` → `closed`) and valid shortcuts (`open` → `contained` or `open` → `closed` for false positives).
  - Enforces mandatory analyst rationale/justification when reopening closed incidents.
  - Rejects invalid backwards transitions (e.g. `closed` → `contained`).
- **Severity Management**:
  - Ranks severities: `critical` (5) > `high` (4) > `medium` (3) > `low` (2) > `info` (1).
  - Automatic escalation when higher-severity alerts correlate.
  - Requires explicit confirmation flag (`allow_downgrade=True`) and justification note for downgrades.
- **Transactional Service (`backend/services/incidents/service.py`)**:
  - CRUD operations with pagination, multi-criteria filtering, analyst assignment, and note appending.
  - Preserves caller-owned transaction boundaries with session flushing.

### 1.3 Detection Correlation Engine
- **Automated Correlation (`backend/services/incidents/correlator.py`)**:
  - Chronological correlation of incoming security detections into existing open/investigating incidents or automated creation of new incidents.
  - Multi-factor correlation rules: shared user session, shared process, shared FIM deviation, category match within active investigation window (default 2 hours), and temporal proximity fallback (15 minutes).
  - Strict host isolation: alerts on Host A never attach to incidents on Host B.
  - Deduplication and idempotency: identical alerts skip duplicate incident and evidence creation.
  - Decoupled lifecycle: detection acknowledgment never automatically resolves or closes the incident.

### 1.4 Forensic Evidence Management & Provenance
- **Evidence Manager (`backend/services/incidents/evidence_manager.py`)**:
  - Typed linking methods for detections, events, FIM deviations, sessions, snapshots, processes, files, and generic/custom artifacts.
  - Enforces host consistency: linking Host B artifacts to Host A incidents raises `HostMismatchError`.
  - Duplicate detection: attempting to link existing artifacts raises `EvidenceDuplicateError`.
  - Provenance capture: snapshots metadata, timestamps, and subsystem origins in JSONB for immutable auditability.

### 1.5 Forensic Report Generator
- **Report Generator (`backend/services/incidents/report.py`)**:
  - Structured JSON and Markdown forensic report exporter.
  - Segregates observed facts (`observed_fact` from telemetry and system artifacts) from analyst interpretations (`analyst_interpretation` from notes and manual status updates).
  - Handles missing or deleted source entities gracefully via cached provenance metadata.
  - Read-only safety: generates reports without mutating database state.

### 1.6 RESTful API
- **Route Handlers (`backend/api/routes/incidents.py`)**:
  - `GET /api/incidents`: Filtered and paginated incident listing.
  - `POST /api/incidents`: Incident creation (restricted to `admin`, `analyst`).
  - `GET /api/incidents/{id}`: Detailed incident retrieval.
  - `PATCH /api/incidents/{id}`: Metadata updates.
  - `POST /api/incidents/{id}/status`: Lifecycle transitions with summary capture.
  - `POST /api/incidents/{id}/severity`: Severity adjustments and downgrade gating.
  - `POST /api/incidents/{id}/assign`: Analyst assignment.
  - `POST /api/incidents/{id}/notes`: Investigation note logging.
  - `GET /api/incidents/{id}/history`: Complete audit trail retrieval.
  - `GET` & `POST /api/incidents/{id}/evidence`: Evidence inventory and linking.
  - `GET` & `POST /api/incidents/{id}/events`: Event association and timeline integration.
  - `GET /api/incidents/{id}/report`: Structured report export in JSON or Markdown.
- **RBAC Enforcement**:
  - `viewer` role permitted read access (`GET`).
  - Mutation endpoints (`POST`, `PATCH`) strictly restricted to `admin` and `analyst` roles (403 Forbidden for viewers).

### 1.7 Frontend Incident Management View
- **User Interface (`frontend/static/js/views/incidents.js`)**:
  - Incident queue with status tabs, severity badges, and host links.
  - Case inspector modal with summary statistics, timeline, correlated artifacts, and action controls.
  - Create incident modal with field validation.
  - Report export buttons triggering instantaneous file downloads.
  - Strict security adherence: zero `innerHTML`, zero `localStorage`, zero `eval`. Verified cleanly in JavaScriptCore.

---

## 2. Test Verification & Results

### 2.1 Workspace Pytest Suite
- **1,208 passed, 12 skipped, 56 warnings in 18.93s** across all test suites in the workspace.

### 2.2 Milestone 2.6 Targeted Test Suites
- **`tests/unit/test_incident_lifecycle.py` (10 passed)**: State machine valid forward transitions, valid shortcuts, reopening rationale enforcement, invalid transition rejection, severity ordering, CRUD operations, assignment, and note audit logging.
- **`tests/unit/test_incident_evidence.py` (8 passed)**: Evidence linking across all forensic entities (detections, events, FIM deviations, sessions, snapshots, processes, files), cross-host contamination prevention, duplicate evidence association rejection.
- **`tests/unit/test_incident_correlation.py` (10 passed)**: Automated incident creation from detections, shared session correlation, shared process correlation, category matching within time window, window expiration, idempotency/deduplication, cross-host isolation, severity escalation without downgrades, detection acknowledgment decoupling, and chronological batch processing.
- **`tests/unit/test_incident_report.py` (5 passed)**: Report generator schema validation, facts vs interpretations segregation, missing source entity handling, markdown export formatting, and read-only database safety.
- **`tests/unit/test_api_incidents.py` (11 passed)**: Authentication enforcement (401), RBAC authorization (403 for viewers on mutations, allowed for analysts/admins), filtering and pagination, CRUD endpoints, lifecycle transitions, severity adjustment gating, evidence/event linking, report downloads, and 404/400 error handling.
- **`tests/unit/test_incidents_view_contract.py` (9 passed)**: Static JavaScript delivery, HTML element existence, zero `localStorage`, zero `innerHTML`, zero `eval`, zero hardcoded secrets, and Apple JavaScriptCore syntax execution.
- **`tests/unit/test_migrations.py` (13 passed)**: Reversible migration upgrade and downgrade for `0006_incidents_and_evidence` on both SQLite and PostgreSQL.

---

# Phase 2 — Milestone 2.7: Investigation Workspace & Advanced Analytics

## 1. Architecture & Implementation Summary

### 1.1 Database Schema & Migration
- **Migration (`database/migrations/versions/0007_workspaces_and_annotations.py`)**:
  - `workspaces`: Persistent analyst investigation sessions with JSON/JSONB layout configuration (`configuration`), ownership tracking (`owner_id`), optional host scoping (`host_id`), linked incident scoping (`incident_id`), and lifecycle status (`active`, `archived`, `closed`).
  - `evidence_tags`: Reusable categorization tags with unique naming, custom color codes, and categories.
  - `evidence_tag_associations`: Polymorphic many-to-many relationship attaching tags across all forensic evidence types (`process`, `event`, `session`, `detection`, `fim_deviation`, `file`, `incident`, `host`, `snapshot`) with host scoping and creator attribution.
  - `evidence_annotations`: Freeform analyst investigation notes with creator attribution (`author_id`), optional workspace association (`workspace_id`), and host scoping.
- **Reversibility**: Dual-dialect support for PostgreSQL and SQLite with fully reversible `upgrade()` and `downgrade()` cycles.

### 1.2 Persistent Workspace Service
- **Service (`backend/services/workspace/service.py`)**:
  - Full CRUD lifecycle for analyst workspaces with paginated listing, privacy isolation (private workspaces visible only to owners and admins), and configuration preservation.
  - Enforces strict host isolation: linking an incident from Host B into a workspace scoped to Host A raises `HostIsolationError`.

### 1.3 Polymorphic Evidence Tagging & Annotations
- **Service (`backend/services/workspace/annotations.py`)**:
  - Manages reusable evidence tags and enforces deduplication (`TagDuplicateError`).
  - Polymorphic association linking tags to any forensic entity with host scoping.
  - Analyst investigation notes with author attribution and timestamps.
  - Non-destructive design: source telemetry and detection records remain immutable.

### 1.4 Interactive Forensic Entity Relationship Graph
- **Service (`backend/services/workspace/graph.py`)**:
  - Multi-entity graph model connecting 10 entity types: `host`, `process`, `user`, `session`, `event`, `snapshot`, `detection`, `fim_deviation`, `file`, and `incident`.
  - Directed edges capturing process hierarchies (`spawned`), user ownership (`owned_by`), session ties (`executed_in`), event generation (`generated`), alerts (`alerted_on`), file integrity deviations (`deviated_from`), and incident evidence (`evidence_of`).
  - Strict bounded expansion: limits traversal depth (default 1, max 3) and node count (default 50, max 150) to prevent denial of service and visual clutter.
  - Relationship provenance tracking in edge metadata (`source_table`, `source_column`).
  - Direct cross-entity pivoting (`get_entity_pivots`) for contextual navigation.

### 1.5 Structured Advanced Forensic Search
- **Service (`backend/services/workspace/search.py`)**:
  - Multi-criteria structured search across events, processes, sessions, detections, FIM deviations, files, and incidents.
  - Supports full-text substring queries, command prefix filters, object path patterns, severity levels, temporal windows, and tag filters.
  - Flexible logic combining filters with configurable `AND` or `OR` evaluation.
  - Host boundary isolation: queries scoped to a host strictly filter across all subsystems.
  - Deterministic pagination and descending timestamp sorting.

### 1.6 RESTful API Endpoints
- **Workspaces (`backend/api/routes/workspaces.py`)**:
  - `POST /api/workspaces`: Create investigation workspace (restricted to `admin`, `analyst`).
  - `GET /api/workspaces`: Paginated workspace listing with privacy isolation.
  - `GET /api/workspaces/{id}`: Detailed workspace configuration retrieval.
  - `PATCH /api/workspaces/{id}`: Metadata and configuration persistence.
  - `POST /api/workspaces/{id}/archive`: Workspace archiving.
  - `DELETE /api/workspaces/{id}`: Permanent deletion with authorization check.
- **Entity Graph (`backend/api/routes/graph.py`)**:
  - `GET /api/graph`: Host-centric or entity-centric initial subgraph retrieval.
  - `POST /api/graph/expand`: Bounded neighbor relationship expansion.
  - `GET /api/graph/pivot/{type}/{id}`: Direct cross-entity navigation pivots.
- **Advanced Search (`backend/api/routes/search.py`)**:
  - `POST /api/search/advanced`: Multi-criteria structured forensic search.
  - `GET /api/search`: Quick query search across forensic entities.
- **Annotations (`backend/api/routes/annotations.py`)**:
  - `GET` & `POST /api/annotations/tags`: Evidence tag listing and creation.
  - `PATCH /api/annotations/tags/{id}`: Evidence tag metadata and color update.
  - `DELETE /api/annotations/tags/{id}`: Evidence tag deletion with cascade.
  - `POST /api/annotations/tags/associate`: Attach tag to forensic evidence item.
  - `POST /api/annotations/tags/disassociate`: Detach tag from evidence item.
  - `GET /api/annotations`: Fetch active tags and notes for an evidence item.
  - `POST /api/annotations/notes`: Create analyst note.
  - `PATCH /api/annotations/notes/{id}`: Update analyst note with author/admin verification.
  - `DELETE /api/annotations/notes/{id}`: Delete analyst note with author verification.

### 1.7 Frontend Investigation Workspace View
- **Single-Page Application View (`frontend/static/js/views/workspace.js`)**:
  - Workspace switcher, rename modal dialog, and configuration persistence (active tab, search criteria, zoom level, pinned evidence).
  - Five investigation sub-panels: Overview, Unified Investigation Workbench, Entity Graph Explorer, Advanced Search, and Evidence & Notes.
  - Unified investigation grid displaying live correlated telemetry across timeline, processes, user sessions, detection alerts, FIM deviations, and incident records with responsive grid, stacked, and single layouts.
  - Native SVG interactive entity graph rendering with zoom, pan, radial layout, severity rings, and slide-out node inspector drawer with adjacent pivots.
  - Advanced forensic search form with multi-entity checkboxes, AND/OR logic, tag filter, and tabular results with "Pivot in Graph", "Pin", "Tag", and "Note" action buttons.
  - Evidence & Notes panel with pinned cards and tag manager.
  - Strict security adherence: zero `innerHTML`, zero `localStorage`, zero `eval()`. Verified with Apple JavaScriptCore.

---

## 2. Milestone 2.7 Verification Results

### 2.1 Workspace Pytest Suite
- **1,291 passed, 12 skipped, 64 warnings** across all test suites in the workspace.

### 2.2 Milestone 2.7 Targeted Test Suites (88 passed)
- **`tests/unit/test_migrations.py` (15 passed)**: Reversible upgrade and downgrade migrations for `0007_workspaces_and_annotations` on SQLite and PostgreSQL.
- **`tests/unit/test_workspace_service.py` (8 passed)**: Workspace creation, auto-host derivation from incidents, cross-host incident rejection, privacy isolation between analysts, permissions enforcement on private and unowned workspaces, metadata updates, and deletion.
- **`tests/unit/test_evidence_annotations.py` (8 passed)**: Tag lifecycle, tag metadata updates and duplication rejection, unique constraint and concurrent integrity enforcement, polymorphic tag association, analyst notes lifecycle and edits, permissions on authored and unauthored notes, and source record immutability.
- **`tests/unit/test_entity_graph.py` (10 passed)**: Initial host graph generation, process hierarchy and event traversal, FIM deviation and detection expansion, incident evidence expansion, snapshot expansion, cross-host isolation, bounded expansion limits, PID reuse protection on process parent/child traversal, dangling edge pruning on max node boundaries, and entity pivoting API.
- **`tests/unit/test_advanced_search.py` (11 passed)**: Query text search, tag filtering, command/severity filters, snapshot search, file path search, host boundary isolation under both AND and OR evaluation, time windowing, deterministic pagination and sorting, and empty/nonexistent tag search safety.
- **`tests/unit/test_api_workspaces.py` (8 passed)**: Authentication enforcement (401), RBAC (403 for viewers), CRUD lifecycle, incident host auto-derivation, host isolation validation (400), and privacy isolation.
- **`tests/unit/test_api_graph.py` (5 passed)**: Unauthenticated rejection (401), initial host graph retrieval, node expansion, snapshot expansion, and entity pivots.
- **`tests/unit/test_api_search.py` (4 passed)**: Unauthenticated rejection (401), quick search, multi-criteria advanced search, and snapshot filtering.
- **`tests/unit/test_api_annotations.py` (9 passed)**: Unauthenticated rejection (401), RBAC (403 for viewers on create and update), tag creation, update and listing, polymorphic association and queries, and analyst notes CRUD lifecycle.
- **`tests/unit/test_workspace_view_contract.py` (10 passed)**: Static JavaScript delivery, HTML element existence, unified view layout verification, zero `localStorage`, zero `innerHTML`, zero `eval`, zero hardcoded secrets, and Apple JavaScriptCore syntax execution.



