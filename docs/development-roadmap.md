# OSIRIS Development Roadmap

> Phased development plan for incremental, module-by-module implementation.

---

## Overview

OSIRIS is developed in two phases:

| Phase | Name                    | Focus                                              |
|-------|-------------------------|----------------------------------------------------|
| 1     | **Observe**             | Data collection, storage, basic API and dashboard   |
| 2     | **Reconstruct & Detect**| Historical analysis, security rules, incidents      |

Each phase is broken into milestones. Milestones are completed in order,
with testing checkpoints to validate correctness before proceeding.

---

## Phase 1: Observe

### Milestone 1.1 — Project Foundation

**Goal:** Establish project architecture and development environment.

- [x] Repository structure
- [x] Directory layout for all modules
- [x] Architecture documentation
- [x] Event model documentation
- [x] Database design documentation
- [x] Development roadmap
- [x] Configuration management (`.env.example`, `config.py`)
- [x] Dependency definitions (`requirements.txt`)
- [x] `.gitignore` configuration
- [x] Abstract `BaseCollector` interface

**Testing Checkpoint:**
- Project structure is clean and documented
- No code fails to import

---

### Milestone 1.2 — Database Setup

**Goal:** Create the PostgreSQL schema for Phase 1 entities.

- [ ] Alembic initialization and configuration
- [ ] Host table migration
- [ ] Linux User table migration
- [ ] Process table migration
- [ ] File table migration
- [ ] Resource Snapshot table migration
- [ ] Event table migration (including `process_id` FK)
- [ ] Application User table migration
- [ ] Application Audit Log table migration
- [ ] Seed data: default host, default admin user

> **Note:** Session table is deferred to Phase 2 — it requires the
> Security/System Log Collector for authentication/login data.

**Testing Checkpoint:**
- Migrations run successfully (upgrade and downgrade)
- All tables created with correct columns and constraints
- Seed data loads without errors

---

### Milestone 1.3 — Event Processing

**Goal:** Implement the authoritative event normalization and storage pipeline.

The Event Processing Layer is the single authority for validation,
normalization, timestamp conversion, enrichment, and event ID assignment.

- [ ] Event validation logic (required field checks)
- [ ] UUID assignment for events (`event_id`)
- [ ] Timestamp normalization (to UTC)
- [ ] Enrichment: UID → username resolution
- [ ] Enrichment: PID → `process_id` resolution (OSIRIS internal identity)
- [ ] Event storage service (insert common events into PostgreSQL)
- [ ] Batch event ingestion

**Testing Checkpoint:**
- Valid events are stored correctly
- Invalid events are rejected with meaningful errors
- Timestamps are correctly normalized to UTC
- `event_id` UUIDs are unique
- `process_id` is correctly resolved from PID + host + time context

---

### Milestone 1.4 — Collectors (Completed)

**Goal:** Implement Linux-specific collectors and validate on live Linux.

Collectors are responsible for gathering raw observations and performing
source-specific parsing via `parse()`. Final normalization is performed by
the Event Processing Layer (Milestone 1.3).

- [x] 1.4A Process Collector (reads from `/proc`, produces process observations)
- [x] 1.4B Resource Collector (reads CPU/memory/disk metrics, produces resource observations)
- [x] 1.4C Filesystem Collector (uses `inotify`, produces file observations)
- [x] 1.4D Collector Orchestration (coordinates lifecycle, intervals, cycle serialization, error isolation)
- [x] 1.4E Live Linux integration in Ubuntu VM (validates all collectors and orchestrator on live Linux subsystems)

**Testing Checkpoint:**
- Each collector produces valid structured observations
- Observations are correctly processed by the Event Processing Layer
- Collectors handle missing or inaccessible data gracefully
- All collectors and orchestration verified against live Linux subsystems

**Ubuntu VM Validation Evidence (Phase 1.4E):**
- **Environment:** Ubuntu 22.04 ARM64 VM
- **Python Version:** Python 3.12.13
- **Full Test Suite:** 194 passed, 8 skipped in 1.81s
  - 183 unit tests passed across database, event processing, collectors, and orchestrator.
  - 11 Linux integration tests passed against real Linux subsystems.
  - 8 tests skipped: 7 in `tests/integration/test_event_persistence.py` (which require an active PostgreSQL service at `postgresql://localhost:5432/osiris_dev`, which was offline during this validation run; live PostgreSQL persistence was not validated) and 1 in `tests/unit/test_database.py` (SQLite CHECK constraint test).
- **Linux Integration Suite:** 11 passed in 1.11s
  - `tests/integration/test_linux_process_collector.py` (3 passed: real `/proc` reads, PID enumeration, process lifecycle)
  - `tests/integration/test_linux_filesystem_collector.py` (1 passed: real `inotify` event capture)
  - `tests/integration/test_linux_resource_collector.py` (4 passed: real `/proc/stat`, `/proc/loadavg`, `/proc/meminfo`, `/proc/diskstats`, `statvfs`)
  - `tests/integration/test_linux_collector_orchestrator.py` (3 passed: unified cycle, background loop, context manager)

---

### Milestone 1.5 — Backend API (Completed)

**Goal:** Expose collected data through REST endpoints.

- [x] Authentication (login, token issuance, PBKDF2-HMAC-SHA256 password hashing, HMAC-SHA256 signed access tokens, application audit-log recorder)
- [x] Event listing and retrieval endpoints (`GET /api/events`, `GET /api/events/{event_id}`)
- [x] Process listing and retrieval endpoints (`GET /api/processes`, `GET /api/processes/{process_id}`)
- [x] Resource snapshot listing endpoint (`GET /api/resources`)
- [x] File listing endpoint with directory-boundary path-prefix filtering (`GET /api/files`)
- [x] Health and status endpoints (`GET /health`, `GET /api/status`)
- [x] Input validation on all endpoints (Pydantic v2 schemas)
- [x] Error handling, structured error responses, and database error safety (sanitized status on disconnect)
- [x] Database seed compatibility fix (`database/seeds/seed_phase1.py` aligned with PBKDF2 hashing)

**Testing Checkpoint:**
- API endpoints return correct data
- Authentication is enforced (401 on protected endpoints without/with invalid bearer tokens)
- Invalid inputs are rejected (422 validation errors on malformed parameters)
- API documentation is auto-generated (OpenAPI/Swagger 3.1.0 verified at `/openapi.json`)
- All unit and integration tests pass cleanly

**Milestone 1.5 Validation Evidence:**
- **Environment:** macOS Darwin (Apple Silicon) with PostgreSQL 18.6 (Homebrew)
- **Full Test Suite:** 331 passed, 12 skipped in 2.63s
  - 319 unit tests passed across database, event processing, collectors, orchestrator, security, schemas, dependencies, routes, and seed fixtures.
  - 7 integration tests passed against live PostgreSQL (`tests/integration/test_event_persistence.py`).
  - 12 skipped: 11 Linux integration tests (skipped on macOS due to lack of Linux `/proc`/`inotify`) and 1 SQLite CHECK constraint test.
  - 0 failures, 0 errors.
- **Phase 1.5 Focused Suite:** 141 passed in 2.14s
  - `tests/unit/test_security.py` (22 passed)
  - `tests/unit/test_schemas.py` (33 passed)
  - `tests/unit/test_api_deps.py` (16 passed)
  - `tests/unit/test_api_auth.py` (12 passed)
  - `tests/unit/test_api_status.py` (6 passed)
  - `tests/unit/test_api_events.py` (18 passed)
  - `tests/unit/test_api_processes.py` (14 passed)
  - `tests/unit/test_api_resources.py` (4 passed)
  - `tests/unit/test_api_files.py` (14 passed)
  - `tests/unit/test_seed_phase1.py` (2 passed)
- **Live PostgreSQL 18.6 API Smoke Test (`osiris_dev`):**
  - `GET /health` -> 200 OK
  - `GET /api/status` -> 200 OK (`database: connected`)
  - `POST /api/auth/login` -> 200 OK (issued bearer access token; recorded login audit log in `app_audit_log`)
  - `GET /api/auth/me` -> 200 OK (returned authenticated admin user details)
  - `GET /api/events` -> 200 OK (paginated envelope, total: 0)
  - `GET /api/processes` -> 200 OK (paginated envelope, total: 1)
  - `GET /api/resources` -> 200 OK (paginated envelope, total: 1)
  - `GET /api/files` -> 200 OK (paginated envelope, total: 1)
  - Unauthenticated / malformed requests -> 401 Unauthorized
  - Note: Development admin credential is configured with `"changeme"` for development/testing only; it must never be used in production environments.

---

### Milestone 1.6 — Basic Web Dashboard (Completed)

**Goal:** Provide a web interface for system overview.

- [x] Dashboard page: system summary, recent events, resource overview
- [x] Event explorer: list, filter, and search events
- [x] Process list view with process detail inspector modal
- [x] Resource charts (CPU, memory, disk activity & usage via native SVG)
- [x] Files Explorer view (path prefix search, file type badges, detail inspector modal)
- [x] Responsive layout (dark cybersecurity theme, CSS Grid & Flexbox)
- [x] Navigation between views (vanilla SPA controller, session management)

**Testing Checkpoint:**
- Dashboard loads and displays live telemetry
- Event explorer filters and inspector work correctly
- Process list and detail inspector work correctly
- Resource charts render responsive vector time series without third-party dependencies
- Files explorer filters and file detail inspector work correctly
- UI is usable, navigable, accessible, and securely parameterized
- All unit and integration tests pass cleanly

**Milestone 1.6 Validation Evidence:**
- **Environment:** macOS Darwin (Apple Silicon) / Python 3.12.13
- **Full Test Suite:** 463 passed, 12 skipped in 3.23s
  - 451 unit tests passed across collectors, event processing, database, backend API, and frontend integration.
  - 12 skipped: 11 Linux integration tests and 1 SQLite CHECK constraint test.
- **Phase 1.6 Frontend Contract Suite:** 132 passed in 1.02s
  - `tests/unit/test_frontend.py` (10 passed)
  - `tests/unit/test_dashboard_contract.py` (22 passed)
  - `tests/unit/test_events_view_contract.py` (26 passed)
  - `tests/unit/test_processes_view_contract.py` (26 passed)
  - `tests/unit/test_resources_view_contract.py` (21 passed)
  - `tests/unit/test_files_view_contract.py` (21 passed)
  - `tests/unit/test_phase16_integration.py` (26 passed)
- **JavaScriptCore (jsc) Syntax Validation:** All 7 JavaScript controllers cleanly validated with exit code 0.
- **Security Rules Verified:** Zero `localStorage` usage, zero `innerHTML` usage, zero `eval` or dynamic code execution, zero hardcoded secrets.

---

## Phase 2: Reconstruct & Detect

### Milestone 2.1 — Historical Storage, Snapshots, and Session Tracking

**Goal:** Support system-state snapshots, historical queries, and session data.

- [ ] Snapshot table migration
- [ ] Session table migration (enabled by Security/System Log Collector)
- [ ] Snapshot creation service (capture process list, resource state)
- [ ] Snapshot retrieval API
- [ ] Historical event queries with time-range filters

> **Note:** Thread entity is removed from scope. It will only be added if a
> concrete requirement is later identified.

**Testing Checkpoint:**
- Snapshots are created and stored correctly
- Historical queries return accurate results for specified time ranges

---

### Milestone 2.2 — Timeline Reconstruction

**Goal:** Reconstruct activity timelines from stored events.

- [ ] Timeline query service (events + processes + files within time window)
- [ ] Entity correlation (link events to processes, users, files)
- [ ] Timeline API endpoint
- [ ] Timeline visualization in frontend

**Testing Checkpoint:**
- Timelines are accurately reconstructed from stored data
- Entity correlation is correct
- Timeline UI displays events in correct chronological order

---

### Milestone 2.3 — Security/System Log Collector

**Goal:** Collect authentication, sudo, and security-relevant system log events.

- [ ] Security/System Log Collector implementation
  - Read from `/var/log/auth.log`, `journalctl`, or syslog
  - Parse authentication success/failure, sudo usage, session events
  - Produce structured observations via `parse()`
- [ ] Event types: `auth.login_success`, `auth.login_failure`, `auth.sudo`, `syslog.event`
- [ ] Integration with Event Processing Layer

**Testing Checkpoint:**
- Collector produces valid structured observations
- Authentication events are correctly processed and stored
- Collector handles missing or inaccessible log files gracefully

---

### Milestone 2.4 — Detection Engine

**Goal:** Evaluate security rules against events to generate alerts.

- [ ] Security rule table migration
- [ ] Rule definition format (declarative JSON/YAML conditions)
- [ ] Rule evaluation engine
- [ ] Seed security rules (e.g., root process execution, sensitive file access,
      repeated authentication failures)
- [ ] Rule explainability (each alert references its rule and evidence)

**Testing Checkpoint:**
- Rules evaluate correctly against test events
- Matching events produce alerts
- Non-matching events do not produce false alerts
- Each alert is explainable

---

### Milestone 2.5 — File Integrity Monitoring

**Goal:** Detect unauthorized file changes.

- [ ] File integrity baseline table migration
- [ ] File integrity observation table migration
- [ ] Baseline creation service (hash files, record metadata)
- [ ] Observation service (re-hash and compare)
- [ ] Alert generation on integrity violations

**Testing Checkpoint:**
- Baselines are created accurately
- Changes are detected correctly
- False positives from expected changes are minimized

---

### Milestone 2.6 — Alert and Incident Management

**Goal:** Organize alerts into investigable incidents.

- [ ] Alert table migration
- [ ] Incident table migration
- [ ] Evidence table migration
- [ ] Alert management API (list, filter, acknowledge)
- [ ] Incident management API (create, update, assign, close)
- [ ] Evidence association API
- [ ] Alert and incident views in frontend

**Testing Checkpoint:**
- Alerts are created from detection rules
- Alerts can be grouped into incidents
- Evidence is correctly linked
- Incident lifecycle (open → investigating → resolved) works

---

### Milestone 2.7 — Investigation Interface

**Goal:** Provide a comprehensive investigation UI.

- [ ] Investigation dashboard (active incidents, alert overview)
- [ ] Incident detail view (timeline, alerts, evidence)
- [ ] Alert detail view (rule explanation, triggering event)
- [ ] Timeline explorer with entity filtering
- [ ] Evidence viewer

**Testing Checkpoint:**
- Investigation workflow is complete and functional
- All relevant data is accessible from the investigation interface

---

### Milestone 2.8 — Database Enhancements

**Goal:** Apply advanced PostgreSQL features.

- [ ] Views for common investigation queries
- [ ] Triggers for automatic timestamp updates
- [ ] Optimized indexes based on observed query patterns
- [ ] Transaction isolation review
- [ ] Concurrency handling for incident updates

**Testing Checkpoint:**
- Views return correct results
- Triggers fire correctly
- Query performance is acceptable
- Concurrent operations do not corrupt data

---

## Development Order Summary

```text
Phase 1: Observe
  1.1 Project Foundation          ← Completed
  1.2 Database Setup
  1.3 Event Processing
  1.4 Collectors (1.4A–1.4E)      ← Completed
  1.5 Backend API (Basic)
  1.6 Basic Web Dashboard

Phase 2: Reconstruct & Detect
  2.1 Historical Storage, Snapshots & Session Tracking
  2.2 Timeline Reconstruction
  2.3 Security/System Log Collector
  2.4 Detection Engine
  2.5 File Integrity Monitoring
  2.6 Alert & Incident Management
  2.7 Investigation Interface
  2.8 Database Enhancements
```

---

## Testing Strategy

### Unit Tests

- Test individual functions and classes in isolation
- Mock external dependencies (database, Linux subsystems)
- Use mocked `/proc` data for collector unit tests
- Located in `tests/unit/`

### Integration Tests

- Test interactions between modules
- Use a test PostgreSQL database
- Test API endpoints with test client (httpx)
- Located in `tests/integration/`

### Live-Linux Integration Tests

Controlled live-Linux integration tests verify that collectors work correctly
against real Linux subsystems. These tests:

- **Must run only inside the controlled Linux VM/environment**
- **Must not run on the development host or in CI by default**
- Are gated by an environment variable (e.g., `OSIRIS_LIVE_TESTS=1`)
- Are located in `tests/integration/` with a `live_linux` marker

| Collector            | Live Test Scope                                        |
|----------------------|--------------------------------------------------------|
| Process Collector    | Verify real `/proc` reads, PID enumeration, process state |
| Filesystem Collector | Verify real `inotify` events on a temp directory          |
| Resource Collector   | Verify real CPU/memory/disk reads from `/proc/*`          |
| Collector Orchestrator | Verify unified collection, background worker, context manager |

### Testing Principles

1. Write tests alongside implementation, not after
2. Test both success and failure paths
3. Use fixtures for common test data (see `tests/conftest.py`)
4. Collector **unit tests** use mocked `/proc` data
5. Collector **live-Linux integration tests** run against real Linux
   subsystems inside the controlled VM only
6. No tests should have destructive side effects on the host system
