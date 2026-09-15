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

### Milestone 1.4 — Collectors

**Goal:** Implement Linux-specific collectors.

Collectors are responsible for gathering raw observations and performing
source-specific parsing via `parse()`. Final normalization is performed by
the Event Processing Layer (Milestone 1.3).

- [ ] Process Collector (reads from `/proc`, produces process observations)
- [ ] Filesystem Collector (uses `inotify` or polling, produces file observations)
- [ ] Resource Collector (reads CPU/memory/disk metrics, produces resource observations)
- [ ] Collector orchestration (start/stop collectors, configure intervals)

**Testing Checkpoint:**
- Each collector produces valid structured observations
- Observations are correctly processed by the Event Processing Layer
- Events from all collectors are stored in PostgreSQL
- Collectors handle missing or inaccessible data gracefully

---

### Milestone 1.5 — Backend API (Basic)

**Goal:** Expose collected data through REST endpoints.

- [ ] Authentication (login, token issuance)
- [ ] Event listing and filtering endpoints
- [ ] Process listing endpoint
- [ ] Resource snapshot endpoint
- [ ] File listing endpoint
- [ ] Health and status endpoints
- [ ] Input validation on all endpoints
- [ ] Error handling and structured error responses

**Testing Checkpoint:**
- API endpoints return correct data
- Authentication is enforced
- Invalid inputs are rejected
- API documentation is auto-generated (OpenAPI/Swagger)

---

### Milestone 1.6 — Basic Web Dashboard

**Goal:** Provide a web interface for system overview.

- [ ] Dashboard page: system summary, recent events, resource overview
- [ ] Event explorer: list, filter, and search events
- [ ] Process list view
- [ ] Resource charts (CPU, memory, disk)
- [ ] Responsive layout
- [ ] Navigation between views

**Testing Checkpoint:**
- Dashboard loads and displays live data
- Event explorer filters work correctly
- UI is usable and navigable

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
  1.4 Collectors
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

### Testing Principles

1. Write tests alongside implementation, not after
2. Test both success and failure paths
3. Use fixtures for common test data (see `tests/conftest.py`)
4. Collector **unit tests** use mocked `/proc` data
5. Collector **live-Linux integration tests** run against real Linux
   subsystems inside the controlled VM only
6. No tests should have destructive side effects on the host system
