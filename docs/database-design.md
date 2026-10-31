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

### 3.17 Application Audit Log

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

### 3.18 Workspace (Phase 2 — Milestone 2.7)

```
workspaces
├── id              UUID         PRIMARY KEY
├── name            VARCHAR(255) NOT NULL
├── description     TEXT         NULLABLE
├── owner_id        UUID         NOT NULL FK → app_users.id (ON DELETE CASCADE)
├── host_id         UUID         NULLABLE FK → hosts.id (ON DELETE SET NULL)
├── incident_id     UUID         NULLABLE FK → incidents.id (ON DELETE SET NULL)
├── status          VARCHAR(50)  NOT NULL DEFAULT 'active'
├── is_shared       BOOLEAN      NOT NULL DEFAULT FALSE
├── configuration   JSON / JSONB NOT NULL DEFAULT '{}'
├── created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
└── updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()

INDEX ix_workspaces_owner (owner_id)
INDEX ix_workspaces_host (host_id)
INDEX ix_workspaces_incident (incident_id)
INDEX ix_workspaces_status (status)
CHECK chk_workspace_status (status IN ('active', 'archived', 'closed'))
```

### 3.19 Evidence Tag (Phase 2 — Milestone 2.7)

```
evidence_tags
├── id              UUID         PRIMARY KEY
├── name            VARCHAR(100) NOT NULL UNIQUE
├── description     TEXT         NULLABLE
├── color           VARCHAR(20)  NOT NULL DEFAULT '#ef4444'
├── category        VARCHAR(50)  NOT NULL DEFAULT 'general'
├── created_by_id   UUID         NULLABLE FK → app_users.id (ON DELETE SET NULL)
└── created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()

INDEX ix_evidence_tags_name (name) UNIQUE
INDEX ix_evidence_tags_category (category)
```

### 3.20 Evidence Tag Association (Phase 2 — Milestone 2.7)

```
evidence_tag_associations
├── id              UUID         PRIMARY KEY
├── tag_id          UUID         NOT NULL FK → evidence_tags.id (ON DELETE CASCADE)
├── evidence_type   VARCHAR(50)  NOT NULL
├── evidence_id     VARCHAR(128) NOT NULL
├── host_id         UUID         NULLABLE FK → hosts.id (ON DELETE CASCADE)
├── created_by_id   UUID         NULLABLE FK → app_users.id (ON DELETE SET NULL)
└── created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()

INDEX ix_evidence_tag_assoc_lookup (evidence_type, evidence_id)
INDEX ix_evidence_tag_assoc_tag (tag_id)
INDEX ix_evidence_tag_assoc_host (host_id)
UNIQUE uq_evidence_tag_assoc (tag_id, evidence_type, evidence_id)
```

### 3.21 Evidence Annotation (Phase 2 — Milestone 2.7)

```
evidence_annotations
├── id              UUID         PRIMARY KEY
├── evidence_type   VARCHAR(50)  NOT NULL
├── evidence_id     VARCHAR(128) NOT NULL
├── host_id         UUID         NULLABLE FK → hosts.id (ON DELETE CASCADE)
├── workspace_id    UUID         NULLABLE FK → workspaces.id (ON DELETE SET NULL)
├── author_id       UUID         NOT NULL FK → app_users.id (ON DELETE CASCADE)
├── annotation_text TEXT         NOT NULL
├── created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
└── updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()

INDEX ix_evidence_annotations_lookup (evidence_type, evidence_id)
INDEX ix_evidence_annotations_author (author_id)
INDEX ix_evidence_annotations_workspace (workspace_id)
INDEX ix_evidence_annotations_host (host_id)
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

### 5.3 Forensic Optimization Indexes (Phase 2 — Milestone 2.8)

Migration `0008_database_optimization.py` introduced 23 specialized compound, foreign key, and timestamp indexes based on observed query access patterns across timeline reconstruction, detection matching, FIM integrity checks, and workspace analysis:

| Table | Index Name | Columns / Expressions | Optimization Target |
|---|---|---|---|
| `events` | `ix_events_host_uid` | `(host_id, uid)` | User-filtered timeline & activity queries |
| `events` | `ix_events_host_pid` | `(host_id, pid)` | Process PID timeline reconstruction |
| `events` | `ix_events_host_event_type_ts` | `(host_id, event_type, timestamp DESC)` | Event-type bounded timeline queries |
| `processes` | `ix_processes_host_started` | `(host_id, started_at)` | Process chronological enumeration |
| `processes` | `ix_processes_host_user` | `(host_id, linux_user_id)` | User-process correlation lookups |
| `processes` | `ix_processes_host_ended` | `(host_id, ended_at)` | Active running process queries (`ended_at IS NULL`) |
| `sessions` | `ix_sessions_host_user_started` | `(host_id, linux_user_id, started_at)` | User login session correlation |
| `sessions` | `ix_sessions_host_ended` | `(host_id, ended_at)` | Active login session tracking |
| `detections` | `ix_detections_host_status_ts` | `(host_id, status, timestamp DESC)` | Active alert triage and status filtering |
| `incidents` | `ix_incidents_host_created` | `(host_id, created_at DESC)` | Host incident chronology listing |
| `incidents` | `ix_incidents_host_status` | `(host_id, status)` | Status-filtered incident queues |
| `incident_evidence` | `ix_incident_evidence_session_id` | `(session_id)` | Session evidence reverse lookup |
| `incident_evidence` | `ix_incident_evidence_snapshot_id`| `(snapshot_id)` | Snapshot evidence reverse lookup |
| `incident_evidence` | `ix_incident_evidence_process_id` | `(process_id)` | Process evidence reverse lookup |
| `incident_evidence` | `ix_incident_evidence_file_id`    | `(file_id)` | File evidence reverse lookup |
| `incident_evidence` | `ix_incident_evidence_inc_type`   | `(incident_id, evidence_type)` | Incident evidence tab filtering |
| `incident_history`  | `ix_incident_history_inc_created` | `(incident_id, created_at DESC)` | Incident timeline audit chronology |
| `incident_history`  | `ix_incident_history_user_id`     | `(user_id)` | Analyst attribution lookups |
| `fim_deviations`    | `ix_fim_deviations_host_detected` | `(host_id, detected_at DESC)` | Host deviation timeline queries |
| `fim_deviations`    | `ix_fim_deviations_host_sev_detected` | `(host_id, severity, detected_at DESC)` | Severity-gated deviation filtering |
| `workspaces`        | `ix_workspaces_owner_status_created` | `(owner_id, status, created_at DESC)` | Analyst workspace dashboard listing |
| `evidence_annotations` | `ix_evidence_annotations_host_id` | `(host_id)` | Host-scoped annotation searches |
| `evidence_tag_associations` | `ix_evidence_tag_assoc_host_tag` | `(host_id, tag_id)` | Host-scoped threat actor tag filtering |

---

## 6. Forensic Database Views (Phase 2 — Milestone 2.8)

Five high-performance database views encapsulate complex joins for frontline forensic analysis, supporting both PostgreSQL and SQLite dialects:

### 6.1 `view_active_detections`
Combines unresolved detections (`open`, `investigating`) with host network metadata and rule provenance for rapid analyst triage:
```sql
CREATE VIEW view_active_detections AS
SELECT
    d.id AS detection_id, d.rule_id, d.rule_version, d.host_id,
    d.event_id, d.process_id, d.timestamp, d.severity, d.title,
    d.description, d.category, d.status, d.notification_status,
    d.dedup_hash, d.created_at, h.hostname, h.ip_address
FROM detections d
JOIN hosts h ON d.host_id = h.id
WHERE d.status IN ('open', 'investigating');
```

### 6.2 `view_incident_summary`
Aggregates incident lifecycle states, analyst assignments, timestamps, and attached evidence counts in a single record:
```sql
CREATE VIEW view_incident_summary AS
SELECT
    i.id AS incident_id, i.title, i.severity, i.status, i.category,
    i.host_id, h.hostname, i.created_by_id, i.first_observed_at,
    i.last_observed_at, i.contained_at, i.closed_at, i.created_at,
    i.updated_at,
    COUNT(ie.id) AS evidence_count
FROM incidents i
JOIN hosts h ON i.host_id = h.id
LEFT JOIN incident_evidence ie ON i.id = ie.incident_id
GROUP BY i.id, i.title, i.severity, i.status, i.category, i.host_id,
         h.hostname, i.created_by_id, i.first_observed_at,
         i.last_observed_at, i.contained_at, i.closed_at,
         i.created_at, i.updated_at;
```

### 6.3 `view_fim_deviation_details`
Denormalizes deviations against baseline golden file attributes (expected hashes, permissions, file size) without application-level JOINs:
```sql
CREATE VIEW view_fim_deviation_details AS
SELECT
    dev.id AS deviation_id, dev.host_id, h.hostname, dev.baseline_id,
    dev.baseline_file_id, dev.file_path, dev.deviation_type,
    dev.severity, dev.detected_at, dev.summary,
    bf.hash_sha256 AS expected_hash_sha256,
    bf.permissions AS expected_permissions,
    bf.file_size AS expected_file_size
FROM fim_deviations dev
JOIN hosts h ON dev.host_id = h.id
LEFT JOIN fim_baseline_files bf ON dev.baseline_file_id = bf.id;
```

### 6.4 `view_process_lineage`
Reconstructs process execution hierarchy by joining processes with their parents scoped to the same host and execution window:
```sql
CREATE VIEW view_process_lineage AS
SELECT
    p.id AS process_id, p.host_id, h.hostname, p.pid, p.ppid,
    p.command, p.executable, p.started_at, p.ended_at,
    u.uid, u.username,
    parent.command AS parent_command,
    parent.executable AS parent_executable
FROM processes p
JOIN hosts h ON p.host_id = h.id
LEFT JOIN linux_users u ON p.linux_user_id = u.id
LEFT JOIN processes parent ON p.host_id = parent.host_id
                           AND p.ppid = parent.pid
                           AND parent.started_at <= p.started_at
                           AND (parent.ended_at IS NULL OR parent.ended_at >= p.started_at);
```

### 6.5 `view_session_overview`
Provides session telemetry enriched with Linux identity, terminal, remote network origins, and duration bounds:
```sql
CREATE VIEW view_session_overview AS
SELECT
    s.id AS session_id, s.host_id, h.hostname, s.linux_user_id,
    lu.uid, lu.username, s.session_type, s.terminal, s.remote_host,
    s.started_at, s.ended_at, s.created_at
FROM sessions s
JOIN hosts h ON s.host_id = h.id
LEFT JOIN linux_users lu ON s.linux_user_id = lu.id;
```

---

## 7. Database Triggers & Data Integrity (Phase 2 — Milestone 2.8)

Dual-dialect database triggers enforce automated timestamp updates and legal immutability invariants:

### 7.1 Automatic `updated_at` Timestamp Maintenance
Triggered on `BEFORE UPDATE` across:
- `hosts`
- `incidents`
- `workspaces`
- `detection_rules`
- `evidence_annotations`

Implementation:
- **PostgreSQL:** Uses a shared PL/pgSQL trigger function `trg_fn_set_updated_at()` assigning `NEW.updated_at = CURRENT_TIMESTAMP`.
- **SQLite:** Uses `CREATE TRIGGER trg_..._updated_at AFTER UPDATE ON ... BEGIN UPDATE ... SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id; END;`.

### 7.2 Immutability Protection Triggers
Forensic audit and history logs must never be tampered with. Immutability triggers abort any attempt to update or delete records in:
- `incident_history`
- `app_audit_log`

Implementation:
- **PostgreSQL:** PL/pgSQL function `trg_prevent_history_mutation()` / `trg_prevent_audit_mutation()` executed on `BEFORE UPDATE OR DELETE` raising `EXCEPTION '... records are immutable and cannot be modified or deleted.'`.
- **SQLite:** Dedicated `BEFORE UPDATE` and `BEFORE DELETE` triggers (`trg_..._immutable`, `trg_..._no_delete`) executing `SELECT RAISE(ABORT, '... records are immutable and cannot be deleted.');`.

---

## 8. Concurrency & Transaction Management (Phase 2 — Milestone 2.8)

### 8.1 Caller-Owned Transaction Boundaries
- All service methods (`IncidentService`, `FimService`, `WorkspaceService`) adhere to caller-owned transaction boundaries.
- Rogue internal `.commit()` calls were eliminated; services issue `db.flush()` to generate IDs and enforce database constraints while letting FastAPI route handlers manage commit or rollback.

### 8.2 Incident Concurrency & Row-Level Locking
- `IncidentService.get_incident` and `get_incident_or_404` accept `eager_load: bool = True` and `for_update: bool = False`.
- In mutation paths (`update_incident`, `transition_status`, `escalate_severity`), `eager_load=False, for_update=True` issues `SELECT ... FOR UPDATE`, acquiring an exclusive row lock on PostgreSQL. This eliminates lost updates under concurrent analyst status changes and avoids loading the entire evidence/history ORM tree into memory.

### 8.3 Multi-Source Timeline Query Optimization
- In `TimelineService` and `EntityCorrelator`, unified union timeline pages hydrate in bounded SQL queries:
  - Batch prefetching for Linux users (`prefetch_users`) across the page host set.
  - Batch prefetching for candidate processes (`prefetch_processes`) and PID resolution caching (`_proc_pid_cache`).
  - Batch prefetching for observed file records (`prefetch_files`) across event `object_path` entries.
  - Window-based prefetching for candidate sessions (`prefetch_sessions`), snapshots (`prefetch_snapshots`), and resources (`prefetch_resources`) matching the page's `[min_ts, max_ts]` window.
- This eliminated the classic N+1 query pattern, reducing timeline reconstruction on 50 events from **151 queries down to 10 queries** (>93% reduction in database round-trips).

---

## 9. Performance Benchmark Results

Measured via `scripts/benchmark_db.py` against PostgreSQL and SQLite engines:

| Category | Benchmark / Operation | Scale | Records | Time (ms) | Queries | SLA Threshold | Status |
|---|---|---|---|---|---|---|---|
| Forensic Timeline | `Unified Timeline Reconstruction` | medium | 1,000 | 66.20ms | 10 | <500ms | **PASS** |
| Detections | `Host & Status Filtered Detections` | medium | 150 | 6.79ms | 2 | <200ms | **PASS** |
| FIM | `FIM Baseline & Deviation Lookups` | medium | 600 | 8.63ms | 4 | <200ms | **PASS** |
| Incidents | `Incident Transition & Locking` | medium | 50 | 16.60ms | 4 | <200ms | **PASS** |
| Graph Expansion | `Entity Graph 1-Hop Expansion` | medium | 61 | 5.59ms | 6 | <300ms | **PASS** |
| Forensic Search | `Multi-Entity Full Search` | medium | 200 | 9.62ms | 4 | <300ms | **PASS** |
| Database Views | `5 Forensic Views Aggregation` | medium | 850 | 3.48ms | 5 | <250ms | **PASS** |
