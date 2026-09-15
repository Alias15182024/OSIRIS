# OSIRIS Architecture

> **Operating System Incident Reconstruction and Intelligence System**
> *"Turning Events into Evidence"*

---

## 1. Purpose

OSIRIS is a Linux-based system monitoring and cybersecurity investigation platform.

It collects operating system activities, converts them into structured events,
stores them in a relational database, and provides tools for historical
reconstruction, security analysis, and incident investigation.

OSIRIS integrates three academic disciplines:

- **Operating Systems** — process, filesystem, and resource monitoring on Linux
- **Database Management Systems** — relational storage, indexing, transactions, views, and triggers in PostgreSQL
- **Cybersecurity** — detection rules, alerting, incident management, and forensic reconstruction

---

## 2. System Layers

OSIRIS follows a layered architecture where each layer has a single responsibility
and communicates only with adjacent layers through well-defined interfaces.

```text
┌────────────────────────────────────────────────────┐
│                   Web Interface                    │
│            (HTML / CSS / JavaScript)               │
├────────────────────────────────────────────────────┤
│                   Backend API                      │
│                    (FastAPI)                        │
├────────────────────────────────────────────────────┤
│                 Service Layer                      │
│        (Business logic, orchestration)             │
├────────────────────────────────────────────────────┤
│    Detection &        │    Reconstruction &        │
│    Alerting Engine    │    Timeline Engine          │
├───────────────────────┼────────────────────────────┤
│              Event Processing Layer                │
│      (Normalization, validation, enrichment)       │
├────────────────────────────────────────────────────┤
│              Database Access Layer                 │
│           (SQLAlchemy / PostgreSQL)                │
├────────────────────────────────────────────────────┤
│                   PostgreSQL                       │
├────────────────────────────────────────────────────┤
│              Collection Layer                      │
│     (Process / Filesystem / Resource collectors)   │
├────────────────────────────────────────────────────┤
│               Linux Kernel & OS                    │
└────────────────────────────────────────────────────┘
```

---

## 3. Module Responsibilities

### 3.1 Collectors (`collectors/`)

**Responsibility:** Gather raw observations from specific Linux subsystems and
perform source-specific parsing.

Collectors are NOT responsible for final event normalization, event ID
assignment, timestamp normalization to UTC, or cross-source enrichment.
Those responsibilities belong to the Event Processing Layer (§3.2).

Each collector inherits from `BaseCollector` and implements:

| Method             | Purpose                                           |
|--------------------|---------------------------------------------------|
| `collect()`        | Read raw data from the Linux subsystem            |
| `parse()`          | Perform source-specific parsing into structured observation dicts |
| `get_source_name()`| Identify this collector as a named source         |

Phase 1 collectors:

| Collector            | Linux Source                | Data Gathered                          |
|----------------------|----------------------------|----------------------------------------|
| Process Collector    | `/proc`, system calls      | PID, PPID, command, user, state, CPU   |
| Filesystem Collector | `inotify`, `/proc/mounts`  | File creation, modification, deletion  |
| Resource Collector   | `/proc/stat`, `/proc/meminfo`, `/proc/diskstats` | CPU, memory, disk usage |

Planned Phase 2 collectors:

| Collector                     | Linux Source                        | Data Gathered                                    |
|-------------------------------|-------------------------------------|--------------------------------------------------|
| Security/System Log Collector | `/var/log/auth.log`, `journalctl`, syslog | Authentication events, sudo usage, session activity |

The Security/System Log Collector is planned for Phase 2 to provide the
event source required by detection rules that analyze authentication
failures, privilege escalation, and session-related security activity.
It is NOT implemented in Phase 1.

**Key Principle:** Collectors are the ONLY layer that contains Linux-specific code.
All other modules operate on the common event model.

### 3.2 Event Processing (`backend/services/`)

**Responsibility:** The authoritative layer for transforming raw collector
observations into validated, normalized common events.

The Event Processing Layer owns the following responsibilities exclusively:

1. **Validation** — ensure all required fields are present and well-formed
2. **Normalization** — convert source-specific parsed data into the common event model
3. **Timestamp normalization** — convert all timestamps to UTC
4. **Event ID assignment** — assign a unique UUID (`event_id`) to each event
5. **Enrichment** — resolve supplementary fields (e.g., UID → username) without
   altering the original observation data
6. **Ingestion timestamp** — set `ingested_at` at storage time
7. **OSIRIS process identity** — assign or resolve `process_id` (the internal
   historical process identity) from the observed PID + host + time context

No other layer may assign event IDs or perform final normalization.

### 3.3 Database Layer (`backend/db/`, `database/`)

**Responsibility:** Persistent storage and retrieval of all OSIRIS data.

- PostgreSQL relational schema
- SQLAlchemy ORM models
- Alembic migrations
- Parameterized queries (no raw string interpolation)
- Connection pooling
- Transaction management

### 3.4 Backend API (`backend/api/`)

**Responsibility:** Expose OSIRIS functionality via RESTful HTTP endpoints.

- FastAPI application
- Route handlers organized by domain (events, alerts, incidents, etc.)
- Input validation via Pydantic models
- Authentication and authorization middleware
- Error handling and structured responses

### 3.5 Service Layer (`backend/services/`)

**Responsibility:** Business logic that orchestrates operations across modules.

- Event ingestion pipeline
- Query building for timeline reconstruction
- Alert processing workflow
- Incident management logic

### 3.6 Detection Engine (`detection/`)

**Responsibility:** Apply predefined security rules to detect suspicious activity.

- Rule definitions (declarative, not arbitrary code execution)
- Rule evaluation engine
- Alert generation from rule matches
- Explainability — every alert traces back to a specific rule and evidence

### 3.7 Reconstruction Engine (Phase 2, within `backend/services/`)

**Responsibility:** Historical timeline reconstruction.

- Query events within a time window
- Correlate related entities (processes, files, users)
- Build ordered activity timelines
- System-state snapshots at selected points

### 3.8 Incident Management (Phase 2, within `backend/services/`)

**Responsibility:** Organize alerts into investigable incidents.

- Group related alerts
- Track incident lifecycle (open, investigating, resolved)
- Associate supporting evidence
- Maintain audit trail

### 3.9 Frontend (`frontend/`)

**Responsibility:** Web-based monitoring and investigation interface.

- Dashboard with system overview
- Event explorer with filtering and search
- Timeline visualization
- Alert and incident views
- No frontend framework — vanilla HTML/CSS/JavaScript

---

## 4. Data Flow

### 4.1 Collection Flow

```text
Linux OS
  │
  ├─→ Process Collector ──→ parse() ──→ Raw Observation ──→ Event Processing Layer ──→ Common Event ──→ PostgreSQL
  │
  ├─→ Filesystem Collector ──→ parse() ──→ Raw Observation ──→ Event Processing Layer ──→ Common Event ──→ PostgreSQL
  │
  └─→ Resource Collector ──→ parse() ──→ Raw Observation ──→ Event Processing Layer ──→ Common Event ──→ PostgreSQL
```

Note: Collectors produce **raw observations** via `parse()`. The **Event
Processing Layer** is the single authority that validates, normalizes,
assigns event IDs, normalizes timestamps to UTC, and enriches observations
into common events.

### 4.2 Detection Flow

```text
PostgreSQL (events)
  │
  └─→ Detection Engine ──→ Rule Evaluation ──→ Alert ──→ PostgreSQL (alerts)
```

### 4.3 Investigation Flow

```text
Investigator ──→ Web UI ──→ Backend API ──→ Service Layer ──→ PostgreSQL
                                                │
                                                ├─→ Timeline reconstruction
                                                ├─→ Entity correlation
                                                └─→ Evidence retrieval
```

---

## 5. Technology Stack

| Layer          | Technology                       | Rationale                                  |
|----------------|----------------------------------|--------------------------------------------|
| Language       | Python 3.11+                     | Required by project specification          |
| Web Framework  | FastAPI                          | Async support, automatic validation, OpenAPI|
| Database       | PostgreSQL                       | Required; robust relational capabilities   |
| ORM            | SQLAlchemy 2.0                   | Mature, type-safe, migration support       |
| Migrations     | Alembic                          | Standard SQLAlchemy migration tool         |
| Validation     | Pydantic                         | Data validation, settings, API schemas     |
| Testing        | pytest                           | Standard Python testing framework          |
| Frontend       | HTML / CSS / JavaScript          | Required; no framework overhead            |
| OS Target      | Linux                            | Required; collectors use Linux-specific APIs|

---

## 6. Security Boundaries

### 6.1 Authentication & Authorization

- OSIRIS application users authenticate before accessing the interface
- Role-based access controls where appropriate
- Session management with secure token handling

### 6.2 Data Integrity

- All database queries use parameterized statements
- Input validation on all API endpoints via Pydantic
- No raw SQL string concatenation

### 6.3 Collector Security

- Collectors operate with least-privilege access
- No collector executes arbitrary user-supplied commands
- No destructive system actions
- Read-only observation of Linux subsystems

### 6.4 Evidence Separation

- Observed system data (events, snapshots) is stored separately from
  application-generated conclusions (alerts, incidents)
- Alerts always reference the originating rule and supporting evidence
- The system never fabricates historical data

### 6.5 Secret Management

- Credentials loaded from environment variables, never hardcoded
- `.env` files excluded from version control
- `.env.example` provided as a template

### 6.6 Audit Logging

- Important application actions (login, configuration changes, incident
  state transitions) are logged with timestamps and actor information

---

## 7. Deployment Model

OSIRIS is designed as a **modular monolith**:

- Single deployable Python application
- Single PostgreSQL database
- Collectors run as part of the application process
- Frontend served by the backend (or a simple static server)
- Intended for a controlled environment (development VM or lab)

No microservices, containers, or cloud infrastructure are required for the
initial implementation.

---

## 8. Directory Structure

```text
OSIRIS/
├── README.md                    # Project overview (preserved)
├── .gitignore                   # Version control exclusions
├── .env.example                 # Environment variable template
├── requirements.txt             # Production dependencies
├── requirements-dev.txt         # Development dependencies
├── pyproject.toml               # Project metadata and tool config
├── docs/
│   ├── architecture.md          # This document
│   ├── event-model.md           # Common event model specification
│   ├── database-design.md       # Database schema design
│   └── development-roadmap.md   # Phased development plan
├── backend/
│   ├── __init__.py
│   ├── main.py                  # FastAPI application entry point
│   ├── config.py                # Application settings
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes/
│   │       └── __init__.py
│   ├── services/
│   │   └── __init__.py
│   └── db/
│       └── __init__.py
├── collectors/
│   ├── __init__.py
│   ├── base.py                  # Abstract BaseCollector
│   ├── process/
│   │   └── __init__.py
│   ├── filesystem/
│   │   └── __init__.py
│   ├── resource/
│   │   └── __init__.py
│   └── syslog/                  # Planned Phase 2
│       └── __init__.py
├── database/
│   ├── migrations/              # Alembic migration scripts
│   └── seeds/                   # Test/seed data
├── detection/
│   ├── __init__.py
│   ├── rules/
│   │   └── __init__.py
│   └── engine/
│       └── __init__.py
├── frontend/
│   ├── static/
│   │   ├── css/
│   │   └── js/
│   └── templates/
└── tests/
    ├── __init__.py
    ├── conftest.py              # Shared pytest fixtures
    ├── unit/
    │   └── __init__.py
    └── integration/
        └── __init__.py
```
