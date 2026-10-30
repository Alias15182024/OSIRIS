# OSIRIS Database Design

> Preliminary design for the OSIRIS PostgreSQL database.
>
> This document establishes the conceptual data model and schema direction.
> The production schema will be implemented incrementally using Alembic migrations.

---

## 1. Design Principles

1. **Relational first.** Frequently queried relationships are modeled as columns
   and foreign keys, not embedded in JSON blobs.
2. **Normalized.** Entities are separated into distinct tables to reduce redundancy
   and maintain data integrity.
3. **Timestamped.** Every record tracks when it was created and, where appropriate,
   when it was last updated.
4. **Parameterized.** All queries use parameterized statements. No raw string
   interpolation in SQL.
5. **Auditable.** Application actions that modify state are logged.
6. **Incremental.** The schema is built progressively using Alembic migrations,
   one module at a time.

---

## 2. Planned Entities

### 2.1 Entity Overview

| Entity                     | Phase | Purpose                                         |
|----------------------------|-------|-------------------------------------------------|
| Host                       | 1     | Monitored system identity                       |
| Linux User                 | 1     | Operating system user accounts                  |
| Process                    | 1     | Observed process instances                      |
| File                       | 1     | Observed file references                        |
| Resource Snapshot          | 1     | Point-in-time CPU/memory/disk metrics           |
| Event                      | 1     | Core event records                              |
| Application User           | 1     | OSIRIS platform user accounts                   |
| Application Audit Log      | 1     | Log of important application actions            |
| Snapshot                   | 2     | System-state snapshots                          |
| Session                    | 2     | User login sessions (requires Security/System Log Collector) |
| Security Rule              | 2     | Detection rule definitions                      |
| Alert                      | 2     | Security alerts from rule matches               |
| Incident                   | 2     | Groups of related alerts                        |
| Evidence                   | 2     | Supporting data linked to incidents             |
| File Integrity Baseline    | 2     | Known-good file checksums                       |
| File Integrity Observation | 2     | Observed file checksums for comparison           |

> **Removed from scope:** The **Thread** entity has been removed from the
> planned schema. It will only be added if a concrete Phase 2 requirement
> is later identified.
>
> **Session moved to Phase 2:** The **Session** entity requires authentication
> and login data that will be provided by the planned Phase 2 Security/System
> Log Collector. It has no concrete data source in Phase 1.

### 2.2 Entity Relationship Map

```text
             Phase 1                           Phase 2
┌───────────┐     ┌───────────────┐
│   Host    │────<│   Process     │
│           │────<│   File        │
│           │────<│   Linux User  │
│           │────<│   Resource    │
│           │     │   Snapshot    │
│           │────<│   Event       │
│           │────<│   Snapshot    │     (Phase 2)
│           │────<│   Session     │     (Phase 2 — requires syslog collector)
└───────────┘     └───────┬───────┘
                          │
                          │ references
                  ┌───────▼───────┐
                  │    Event      │
                  │  (process_id  │     ← OSIRIS internal process identity
                  │   + pid/uid)  │     ← source-level Linux identifiers
                  └───────┬───────┘
                          │ may trigger (Phase 2)
                  ┌───────▼───────┐
                  │    Alert      │◄────── Security Rule
                  └───────┬───────┘
                          │ grouped into
                  ┌───────▼───────┐
                  │   Incident    │
                  └───────┬───────┘
                          │ associated with
                  ┌───────▼───────┐
                  │   Evidence    │
                  └───────────────┘

┌──────────────────┐     ┌────────────────────┐
│ Application User │────<│ Application Audit   │
│                  │     │ Log                  │
└──────────────────┘     └────────────────────┘

┌─────────────────────┐     ┌──────────────────────────┐
│ File Integrity      │────<│ File Integrity            │     (Phase 2)
│ Baseline            │     │ Observation               │
└─────────────────────┘     └──────────────────────────┘
```

---

## 3. Preliminary Schema Direction

> These are directional designs, not final DDL. The production schema will be
> created through Alembic migrations during implementation.

### 3.1 Host

```
hosts
├── id              UUID        PRIMARY KEY
├── hostname        VARCHAR     NOT NULL
├── os_info         VARCHAR
├── ip_address      VARCHAR
├── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
└── updated_at      TIMESTAMPTZ
```

### 3.2 Linux User

```
linux_users
├── id              UUID        PRIMARY KEY
├── host_id         UUID        FK → hosts.id
├── uid             INTEGER     NOT NULL
├── username        VARCHAR
├── first_seen_at   TIMESTAMPTZ NOT NULL
├── last_seen_at    TIMESTAMPTZ
└── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
UNIQUE (host_id, uid)
```

### 3.3 Session (Phase 2 — Milestone 2.3)

User sessions represent interactive and remote user login sessions on monitored hosts, reconstructed from system log observations (SSHD, PAM, console login, and systemd-logind).

```
sessions
├── id              UUID        PRIMARY KEY
├── host_id         UUID        FK → hosts.id
├── linux_user_id   UUID        FK → linux_users.id (NULLABLE)
├── session_type    VARCHAR(50) (e.g., 'ssh', 'tty', 'systemd', 'su')
├── terminal        VARCHAR(255)(e.g., 'pts/0', 'tty1')
├── remote_host     VARCHAR(255)(e.g., IP address or hostname)
├── started_at      TIMESTAMPTZ NOT NULL
├── ended_at        TIMESTAMPTZ (NULL while session is active)
└── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
INDEX ix_sessions_host_started (host_id, started_at)
INDEX ix_sessions_linux_user_id (linux_user_id)
```

#### 3.3.1 Session Reconstruction & Lifecycle Architecture

`SessionReconstructionService` (`backend/services/sessions/service.py`) processes authentication observations to maintain session lifecycle:

1. **Multi-Event Login Deduplication:**
   OpenSSH logins typically emit an `Accepted publickey/password` event followed immediately (0-2 seconds) by a `pam_unix(sshd:session): session opened` event. To prevent duplicate session records, the service checks for an existing active session on the same host, terminal, and user within a configurable correlation window (default: 10s). If found, the session is updated or preserved rather than creating a duplicate.

2. **Terminal Collision Resolution:**
   Pseudo-terminals (e.g. `pts/0`) are frequently reused across successive connections. If a new login is observed on a terminal that has an existing unclosed session from an earlier time, the service automatically closes the stale session at the new session's start time before creating the new session.

3. **Session Closure:**
   Explicit logout events (`pam_unix session closed`, `systemd-logind session removed`, or console logout) locate the active session matching `host_id`, `terminal` (or `user_id`), and mark `ended_at = observation.timestamp`.

4. **Privilege Escalation Tracking:**
   `sudo` executions and `su` switches are tracked as distinct security events (`auth.sudo`, `auth.privilege_escalation`). Sudo commands preserve the originating interactive login session while logging target user, command, and TTY in event payloads, preventing attribution hijacking.

5. **Process Correlation Semantics:**
   Processes are mapped to sessions based on:
   - Identical `host_id`
   - Matching Linux user identity (`linux_user_id` or `uid`)
   - Temporal containment: `session.started_at <= process.started_at <= (session.ended_at or NOW())`
   - Optional terminal affinity (`process.terminal == session.terminal` when available)
   This eliminates PID reuse ambiguity by bounding process lookups strictly within the session's active lifetime.

### 3.4 Process

```
processes
├── id              UUID        PRIMARY KEY
├── host_id         UUID        FK → hosts.id
├── pid             INTEGER     NOT NULL
├── ppid            INTEGER
├── command         VARCHAR     NOT NULL
├── executable      VARCHAR
├── linux_user_id   UUID        FK → linux_users.id
├── started_at      TIMESTAMPTZ NOT NULL
├── ended_at        TIMESTAMPTZ
└── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
INDEX (host_id, pid, started_at)
```

### 3.5 File

```
files
├── id              UUID        PRIMARY KEY
├── host_id         UUID        FK → hosts.id
├── path            VARCHAR     NOT NULL
├── inode           BIGINT
├── file_type       VARCHAR     (e.g., 'file', 'directory', 'symlink')
├── first_seen_at   TIMESTAMPTZ NOT NULL
├── last_seen_at    TIMESTAMPTZ
└── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
INDEX (host_id, path)
```

### 3.6 Resource Snapshot

```
resource_snapshots
├── id              UUID        PRIMARY KEY
├── host_id         UUID        FK → hosts.id
├── timestamp       TIMESTAMPTZ NOT NULL
├── cpu_percent     REAL
├── memory_total    BIGINT
├── memory_used     BIGINT
├── memory_percent  REAL
├── disk_read_bytes BIGINT
├── disk_write_bytes BIGINT
├── disk_usage_percent REAL
└── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
INDEX (host_id, timestamp)
```

### 3.7 Event

```
events
├── id              UUID        PRIMARY KEY
├── host_id         UUID        FK → hosts.id
├── timestamp       TIMESTAMPTZ NOT NULL
├── ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
├── source          VARCHAR     NOT NULL
├── event_type      VARCHAR     NOT NULL
├── action          VARCHAR     NOT NULL
├── severity        VARCHAR     NOT NULL DEFAULT 'info'
│   -- Actor fields (source-level Linux identity)
├── uid             INTEGER                          -- Linux UID (preferred identity)
├── username        VARCHAR                          -- Supplementary/resolved from uid
│   -- Process fields
├── process_id      UUID        FK → processes.id    -- OSIRIS internal historical process identity (NULLABLE)
├── pid             INTEGER                          -- Linux PID observed at event time
├── ppid            INTEGER                          -- Linux parent PID observed at event time
├── command         VARCHAR
│   -- Object fields
├── object_type     VARCHAR
├── object_path     VARCHAR
│   -- Result fields
├── success         BOOLEAN
├── result          VARCHAR
│   -- Extensibility
├── payload         JSONB
└── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
INDEX (host_id, timestamp)
INDEX (event_type)
INDEX (source)
INDEX (severity)
INDEX (process_id)                                   -- for process-scoped queries
```

> **Field semantics:**
> - `uid` is the **preferred** Linux user identity (source-level).
> - `username` is **supplementary** — resolved from `uid` by the Event Processing
>   Layer. May be `null` if the account is deleted or unresolvable.
> - `pid` / `ppid` are **source-level Linux identifiers** observed at event time.
>   They are NOT globally unique due to PID reuse.
> - `process_id` is the **OSIRIS internal historical process identity** (UUID).
>   It uniquely identifies a process instance across PID reuse. Resolved by the
>   Event Processing Layer using `host_id` + `pid` + `timestamp`.

### 3.8 Snapshot (Phase 2)

```
snapshots
├── id              UUID        PRIMARY KEY
├── host_id         UUID        FK → hosts.id
├── timestamp       TIMESTAMPTZ NOT NULL
├── snapshot_type   VARCHAR     NOT NULL
├── data            JSONB       NOT NULL
└── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
INDEX (host_id, timestamp)
```

### 3.8.1 Timeline Reconstruction Query Architecture (Milestone 2.2)

Milestone 2.2 implements unified timeline reconstruction querying across `events`, `processes`, `sessions`, `snapshots`, `resource_snapshots`, and `files`.
Query optimization and indexing analysis confirmed that existing compound indexes adequately support timeline queries without schema modifications:
- `ix_events_host_ts (host_id, timestamp)`
- `ix_processes_host_pid_started (host_id, pid, started_at)`
- `ix_files_host_path (host_id, path)`
- `ix_snapshots_host_ts (host_id, timestamp)`
- `ix_sessions_host_started (host_id, started_at)`
- `ix_resource_snapshots_host_ts (host_id, timestamp)`

Database `UNION ALL` subqueries push down filtering (`host_id`, `start_time`, `end_time`, `event_type`), pagination (`LIMIT`, `OFFSET`), and deterministic ordering (`timestamp ASC, source_id ASC`) directly to the PostgreSQL/SQLite query planner, avoiding full-table scans and eliminating in-memory buffering of large historical datasets.

### 3.9 Detection Rule (Phase 2 — Milestone 2.4)

Declarative security detection rules evaluated by the OSIRIS Detection Engine. Rules support single-event AST evaluation (`condition`) or multi-event temporal correlation (`sequence`).

```
detection_rules
├── id                   VARCHAR(64)  PRIMARY KEY (e.g., 'OSIRIS-PRIV-001')
├── name                 VARCHAR(128) NOT NULL
├── description          TEXT         NOT NULL
├── severity             VARCHAR(16)  NOT NULL  (CHECK: critical, high, medium, low, info)
├── category             VARCHAR(32)  NOT NULL  (CHECK: privilege_escalation, authentication, reconnaissance,
│                                               persistence, execution, credential_access, defense_evasion,
│                                               lateral_movement, exfiltration, impact)
├── mitre_attack         VARCHAR(64)  NULLABLE  (e.g., 'T1548.003')
├── condition            JSON / JSONB NOT NULL  (Declarative boolean AST)
├── sequence             JSON / JSONB NULLABLE  (Temporal multi-stage correlation definition)
├── dedup_window_seconds INTEGER      NOT NULL DEFAULT 300
├── is_active            BOOLEAN      NOT NULL DEFAULT TRUE
├── created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
└── updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()

INDEX ix_detection_rules_category (category)
INDEX ix_detection_rules_severity (severity)
INDEX ix_detection_rules_is_active (is_active)
```

### 3.10 Detection (Phase 2 — Milestone 2.4)

Atomic security findings generated when telemetry events match a `detection_rule`. Includes full explainability trees (`matched_conditions`), forensic evidence payloads (`evidence`), and deterministic SHA-256 deduplication. In Milestone 2.6, detections serve as the alert feed for incident grouping.

```
detections
├── id                   UUID         PRIMARY KEY
├── rule_id              VARCHAR(64)  NOT NULL FK → detection_rules.id (ON DELETE RESTRICT)
├── host_id              UUID         NOT NULL FK → hosts.id (ON DELETE CASCADE)
├── event_id             UUID         NULLABLE FK → events.id (ON DELETE SET NULL)
├── timestamp            TIMESTAMPTZ  NOT NULL
├── severity             VARCHAR(16)  NOT NULL  (CHECK: critical, high, medium, low, info)
├── title                VARCHAR(256) NOT NULL
├── description          TEXT         NOT NULL
├── matched_conditions   JSON / JSONB NOT NULL  (Explainability tree detailing field comparisons)
├── evidence             JSON / JSONB NOT NULL  (Forensic context: cmdline, users, paths, session IDs)
├── dedup_hash           VARCHAR(64)  NOT NULL UNIQUE (SHA-256 deterministic deduplication)
├── status               VARCHAR(16)  NOT NULL DEFAULT 'new' (CHECK: new, acknowledged, resolved, false_positive)
├── fim_deviation_id     UUID         NULLABLE FK → fim_deviations.id (ON DELETE SET NULL, use_alter=True)
├── acknowledged_at      TIMESTAMPTZ  NULLABLE
├── acknowledged_by      VARCHAR(64)  NULLABLE
└── created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()

INDEX ix_detections_host_id (host_id)
INDEX ix_detections_rule_id (rule_id)
INDEX ix_detections_timestamp (timestamp)
INDEX ix_detections_severity (severity)
INDEX ix_detections_status (status)
INDEX ix_detections_fim_deviation_id (fim_deviation_id)
INDEX ix_detections_host_timestamp (host_id, timestamp)
INDEX ix_detections_rule_timestamp (rule_id, timestamp)
UNIQUE INDEX ix_detections_dedup_hash (dedup_hash)
```

### 3.11 File Integrity Baseline (Phase 2 — Milestone 2.5)

Represents a cryptographically validated point-in-time filesystem baseline for a host.

```
fim_baselines
├── id                   UUID         PRIMARY KEY
├── host_id              UUID         NOT NULL FK → hosts.id (ON DELETE CASCADE)
├── version              INTEGER      NOT NULL DEFAULT 1
├── status               VARCHAR(16)  NOT NULL DEFAULT 'active' (CHECK: active, superseded, revoked)
├── path_scope           VARCHAR(1024)NOT NULL
├── include_patterns     JSON / JSONB NOT NULL DEFAULT '[]'
├── exclude_patterns     JSON / JSONB NOT NULL DEFAULT '[]'
├── total_files          INTEGER      NOT NULL DEFAULT 0
├── total_bytes          BIGINT       NOT NULL DEFAULT 0
├── scan_duration_ms     INTEGER      NULLABLE
├── baseline_metadata    JSON / JSONB NOT NULL DEFAULT '{}'
├── created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
└── updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()

INDEX ix_fim_baselines_host_id (host_id)
INDEX ix_fim_baselines_status (status)
INDEX ix_fim_baselines_host_status (host_id, status)
INDEX ix_fim_baselines_created_at (created_at)
```

### 3.12 File Integrity Baseline File (Phase 2 — Milestone 2.5)

Individual file record within a cryptographic baseline, containing SHA-256 digest and filesystem attributes.

```
fim_baseline_files
├── id                   UUID         PRIMARY KEY
├── baseline_id          UUID         NOT NULL FK → fim_baselines.id (ON DELETE CASCADE)
├── file_path            VARCHAR(1024)NOT NULL
├── sha256_hash          VARCHAR(64)  NOT NULL
├── sha1_hash            VARCHAR(40)  NULLABLE
├── md5_hash             VARCHAR(32)  NULLABLE
├── size_bytes           BIGINT       NOT NULL
├── file_mode            VARCHAR(16)  NOT NULL
├── uid                  INTEGER      NOT NULL
├── gid                  INTEGER      NOT NULL
├── mtime_epoch          DOUBLE PREC  NOT NULL
├── is_symlink           BOOLEAN      NOT NULL DEFAULT FALSE
├── symlink_target       VARCHAR(1024)NULLABLE
├── attributes           JSON / JSONB NOT NULL DEFAULT '{}'
└── created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()

INDEX ix_fim_baseline_files_baseline_id (baseline_id)
INDEX ix_fim_baseline_files_file_path (file_path)
INDEX ix_fim_baseline_files_sha256 (sha256_hash)
UNIQUE (baseline_id, file_path)
```

### 3.13 File Integrity Deviation (Phase 2 — Milestone 2.5)

Forensic integrity deviations observed during verification against a baseline, with bidirectional linkage to detections.

```
fim_deviations
├── id                   UUID         PRIMARY KEY
├── baseline_id          UUID         NOT NULL FK → fim_baselines.id (ON DELETE CASCADE)
├── host_id              UUID         NOT NULL FK → hosts.id (ON DELETE CASCADE)
├── detection_id         UUID         NULLABLE FK → detections.id (ON DELETE SET NULL, use_alter=True)
├── file_path            VARCHAR(1024)NOT NULL
├── deviation_type       VARCHAR(32)  NOT NULL (CHECK: modified, added, removed, permission_changed, ownership_changed)
├── severity             VARCHAR(16)  NOT NULL (CHECK: critical, high, medium, low, info)
├── detected_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
├── expected_sha256      VARCHAR(64)  NULLABLE
├── observed_sha256      VARCHAR(64)  NULLABLE
├── expected_size        BIGINT       NULLABLE
├── observed_size        BIGINT       NULLABLE
├── expected_mode        VARCHAR(16)  NULLABLE
├── observed_mode        VARCHAR(16)  NULLABLE
├── expected_uid         INTEGER      NULLABLE
├── observed_uid         INTEGER      NULLABLE
├── expected_gid         INTEGER      NULLABLE
├── observed_gid         INTEGER      NULLABLE
├── details              JSON / JSONB NOT NULL DEFAULT '{}'
└── created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()

INDEX ix_fim_deviations_baseline_id (baseline_id)
INDEX ix_fim_deviations_host_id (host_id)
INDEX ix_fim_deviations_detection_id (detection_id)
INDEX ix_fim_deviations_file_path (file_path)
INDEX ix_fim_deviations_deviation_type (deviation_type)
INDEX ix_fim_deviations_severity (severity)
INDEX ix_fim_deviations_detected_at (detected_at)
INDEX ix_fim_deviations_host_detected (host_id, detected_at)
```

### 3.14 Incident (Phase 2 — Milestone 2.6)

Forensic incident container aggregating related security detections, forensic timeline events, file deviations, and system artifacts.

```
incidents
├── id                   UUID         PRIMARY KEY
├── title                VARCHAR(255) NOT NULL
├── description          TEXT         NULLABLE
├── severity             VARCHAR(20)  NOT NULL (CHECK: critical, high, medium, low, info)
├── status               VARCHAR(50)  NOT NULL DEFAULT 'open' (CHECK: open, investigating, contained, resolved, closed)
├── category             VARCHAR(100) NOT NULL DEFAULT 'general'
├── host_id              UUID         NULLABLE FK → hosts.id (ON DELETE CASCADE)
├── created_by_id        UUID         NULLABLE FK → app_users.id (ON DELETE SET NULL)
├── assigned_to_id       UUID         NULLABLE FK → app_users.id (ON DELETE SET NULL)
├── first_observed_at    TIMESTAMPTZ  NULLABLE
├── last_observed_at     TIMESTAMPTZ  NULLABLE
├── contained_at         TIMESTAMPTZ  NULLABLE
├── containment_summary  TEXT         NULLABLE
├── resolved_at          TIMESTAMPTZ  NULLABLE
├── resolution_summary   TEXT         NULLABLE
├── closed_at            TIMESTAMPTZ  NULLABLE
├── closure_summary      TEXT         NULLABLE
├── created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
└── updated_at           TIMESTAMPTZ  NULLABLE

INDEX ix_incidents_host_created (host_id, created_at)
INDEX ix_incidents_status (status)
INDEX ix_incidents_severity (severity)
INDEX ix_incidents_category (category)
INDEX ix_incidents_assigned_to (assigned_to_id)
INDEX ix_incidents_created_by (created_by_id)
INDEX ix_incidents_first_observed (first_observed_at)
INDEX ix_incidents_last_observed (last_observed_at)
```

### 3.15 Incident Events Association (Phase 2 — Milestone 2.6)

Forensic event linkage mapping granular audit/system telemetry directly to incident timelines.

```
incident_events
├── id                      UUID         PRIMARY KEY
├── incident_id             UUID         NOT NULL FK → incidents.id (ON DELETE CASCADE)
├── event_id                UUID         NOT NULL FK → events.id (ON DELETE CASCADE)
├── relationship            VARCHAR(50)  NOT NULL DEFAULT 'associated'
├── investigation_notes     TEXT         NULLABLE
├── association_timestamp   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
└── created_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW()

INDEX ix_incident_events_incident (incident_id)
INDEX ix_incident_events_event (event_id)
UNIQUE uq_incident_event (incident_id, event_id)
```

### 3.16 Incident Evidence (Phase 2 — Milestone 2.6)

Polymorphic forensic evidence repository supporting detections, sessions, snapshots, FIM deviations, processes, files, and external artifacts with full provenance tracking.

```
incident_evidence
├── id                   UUID         PRIMARY KEY
├── incident_id          UUID         NOT NULL FK → incidents.id (ON DELETE CASCADE)
├── evidence_type        VARCHAR(50)  NOT NULL (CHECK: detection, event, fim_deviation, session, snapshot, process, file, custom)
├── source_id            VARCHAR(255) NOT NULL
├── title                VARCHAR(255) NOT NULL
├── description          TEXT         NULLABLE
├── provenance           JSON / JSONB NOT NULL DEFAULT '{}'
├── detection_id         UUID         NULLABLE FK → detections.id (ON DELETE SET NULL)
├── event_id             UUID         NULLABLE FK → events.id (ON DELETE SET NULL)
├── fim_deviation_id     UUID         NULLABLE FK → fim_deviations.id (ON DELETE SET NULL)
├── session_id           UUID         NULLABLE FK → sessions.id (ON DELETE SET NULL)
├── snapshot_id          UUID         NULLABLE FK → snapshots.id (ON DELETE SET NULL)
├── process_id           UUID         NULLABLE FK → processes.id (ON DELETE SET NULL)
├── file_id              UUID         NULLABLE FK → files.id (ON DELETE SET NULL)
├── created_by_id        UUID         NULLABLE FK → app_users.id (ON DELETE SET NULL)
└── created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()

INDEX ix_incident_evidence_incident (incident_id)
INDEX ix_incident_evidence_type (evidence_type)
INDEX ix_incident_evidence_source (evidence_type, source_id)
INDEX ix_incident_evidence_detection (detection_id)
INDEX ix_incident_evidence_fim (fim_deviation_id)
INDEX ix_incident_evidence_session (session_id)
INDEX ix_incident_evidence_snapshot (snapshot_id)
INDEX ix_incident_evidence_process (process_id)
INDEX ix_incident_evidence_file (file_id)
UNIQUE uq_incident_evidence_source (incident_id, evidence_type, source_id)
```

### 3.17 Incident History & Audit Trail (Phase 2 — Milestone 2.6)

Immutable audit log recording status transitions, severity escalations, analyst notes, and evidence bindings.

```
incident_history
├── id                   UUID         PRIMARY KEY
├── incident_id          UUID         NOT NULL FK → incidents.id (ON DELETE CASCADE)
├── change_type          VARCHAR(50)  NOT NULL (CHECK: incident_created, status_change, severity_change, assignment, note_added, evidence_added, event_added, incident_updated)
├── from_status          VARCHAR(50)  NULLABLE
├── to_status            VARCHAR(50)  NULLABLE
├── from_severity        VARCHAR(20)  NULLABLE
├── to_severity          VARCHAR(20)  NULLABLE
├── user_id              UUID         NULLABLE FK → app_users.id (ON DELETE SET NULL)
├── notes                TEXT         NULLABLE
├── history_metadata     JSON / JSONB NOT NULL DEFAULT '{}'
└── created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()

INDEX ix_incident_history_incident (incident_id)
INDEX ix_incident_history_change (change_type)
INDEX ix_incident_history_user (user_id)
INDEX ix_incident_history_created (created_at)
INDEX ix_incident_history_incident_created (incident_id, created_at)
```

### 3.16 Application User

```
app_users
├── id              UUID        PRIMARY KEY
├── username        VARCHAR     NOT NULL UNIQUE
├── password_hash   VARCHAR     NOT NULL
├── display_name    VARCHAR
├── role            VARCHAR     NOT NULL DEFAULT 'viewer'
├── is_active       BOOLEAN     NOT NULL DEFAULT TRUE
├── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
└── updated_at      TIMESTAMPTZ
```

### 3.16 Application Audit Log

```
app_audit_log
├── id              UUID        PRIMARY KEY
├── user_id         UUID        FK → app_users.id  (NULLABLE)
├── action          VARCHAR     NOT NULL
├── target_type     VARCHAR
├── target_id       UUID
├── details         JSONB
├── ip_address      VARCHAR
└── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
INDEX (user_id)
INDEX (action)
INDEX (created_at)
```

---

## 4. Normalization Goals

The schema follows **Third Normal Form (3NF)** as the baseline:

1. **1NF:** All columns contain atomic values. No repeating groups.
2. **2NF:** All non-key columns depend on the entire primary key.
3. **3NF:** No transitive dependencies between non-key columns.

**Controlled denormalization** is permitted in the `events` table where actor
and process fields (`uid`, `username`, `pid`, `ppid`, `command`) are stored
directly alongside the `process_id` FK. This is intentional:

- `pid` and `ppid` are source-level snapshots; `process_id` is the OSIRIS FK
- Denormalized fields enable efficient timeline queries without multi-table joins
- The source-of-truth for process and user entities remains in their respective tables
- `uid` is the preferred Linux identity; `username` is supplementary/resolved

---

## 5. Indexing Considerations

### 5.1 Primary Indexes

| Table             | Index                          | Purpose                        |
|-------------------|--------------------------------|--------------------------------|
| events            | (host_id, timestamp)           | Time-range queries per host    |
| events            | (event_type)                   | Filter by event type           |
| events            | (source)                       | Filter by collector source     |
| events            | (severity)                     | Filter by severity level       |
| processes         | (host_id, pid, started_at)     | PID lookup with time context   |
| resource_snapshots| (host_id, timestamp)           | Time-series resource queries   |
| alerts            | (status)                       | Open alert queries             |
| alerts            | (timestamp)                    | Alert timeline                 |
| app_audit_log     | (created_at)                   | Audit chronology               |

### 5.2 Indexing Strategy

- Use B-tree indexes for equality and range comparisons (default)
- Consider GIN indexes on JSONB `payload` columns if full-payload queries
  become necessary
- Avoid over-indexing: add indexes only when query patterns justify them
- Monitor query plans during development to validate index usage

---

## 6. Transaction Considerations

### 6.1 Event Ingestion

- Batch event inserts should use transactions to ensure atomicity
- If a batch partially fails, the entire batch should be rolled back
- Use `INSERT ... ON CONFLICT` where appropriate to handle edge cases

### 6.2 Alert and Incident Updates

- Alert status changes and incident assignments must be atomic
- Concurrent updates to the same incident should be handled with
  row-level locking (`SELECT ... FOR UPDATE`)

### 6.3 Isolation Level

- Default to `READ COMMITTED` isolation level
- Use `SERIALIZABLE` only where strict consistency is required
  (e.g., file integrity baseline comparisons in Phase 2)

### 6.4 Connection Pooling

- Use SQLAlchemy's built-in connection pooling
- Configure pool size based on expected concurrent operations
- Use context managers to ensure connections are returned to the pool

---

## 7. Migration Strategy

- All schema changes are managed through **Alembic** migrations
- Each migration has an `upgrade()` and `downgrade()` function
- Migrations are applied in order and tracked in the `alembic_version` table
- Migration files are stored in `database/migrations/`
- No manual DDL changes to the production database

---

## 8. Seed and Test Data

- Seed data scripts are stored in `database/seeds/`
- Seed data provides minimal starting records (e.g., default host, default
  application user, sample security rules)
- Test data is generated in test fixtures, not stored in the database permanently
- No sensitive or realistic credential data in seeds

---

## 9. Future Considerations

These are acknowledged but NOT implemented in the initial architecture:

- **Partitioning:** The `events` table may benefit from time-based partitioning
  if event volume grows significantly
- **Archival:** Older events may be moved to archive tables to maintain
  query performance
- **Views:** PostgreSQL views will be created in Phase 2 for common
  investigation queries (e.g., active alerts with event details)
- **Triggers:** PostgreSQL triggers will be considered in Phase 2 for
  automatic actions (e.g., updating `updated_at` timestamps, cascading
  alert status changes)
