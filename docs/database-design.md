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

### 3.3 Session (Phase 2)

> Moved to Phase 2. Requires the Security/System Log Collector to provide
> authentication and login event data. No concrete Phase 1 collector produces
> session information.

```
sessions
├── id              UUID        PRIMARY KEY
├── host_id         UUID        FK → hosts.id
├── linux_user_id   UUID        FK → linux_users.id
├── session_type    VARCHAR     (e.g., 'tty', 'pts', 'ssh')
├── terminal        VARCHAR
├── remote_host     VARCHAR
├── started_at      TIMESTAMPTZ NOT NULL
├── ended_at        TIMESTAMPTZ
└── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

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
├── file_type       VARCHAR     (e.g., 'regular', 'directory', 'symlink')
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

### 3.9 Security Rule (Phase 2)

```
security_rules
├── id              UUID        PRIMARY KEY
├── name            VARCHAR     NOT NULL UNIQUE
├── description     TEXT
├── rule_type       VARCHAR     NOT NULL
├── condition       JSONB       NOT NULL
├── severity        VARCHAR     NOT NULL
├── enabled         BOOLEAN     NOT NULL DEFAULT TRUE
├── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
└── updated_at      TIMESTAMPTZ
```

### 3.10 Alert (Phase 2)

```
alerts
├── id              UUID        PRIMARY KEY
├── rule_id         UUID        FK → security_rules.id
├── event_id        UUID        FK → events.id
├── host_id         UUID        FK → hosts.id
├── timestamp       TIMESTAMPTZ NOT NULL
├── severity        VARCHAR     NOT NULL
├── title           VARCHAR     NOT NULL
├── description     TEXT
├── status          VARCHAR     NOT NULL DEFAULT 'open'
├── incident_id     UUID        FK → incidents.id  (NULLABLE)
└── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
INDEX (status)
INDEX (severity)
INDEX (timestamp)
```

### 3.11 Incident (Phase 2)

```
incidents
├── id              UUID        PRIMARY KEY
├── title           VARCHAR     NOT NULL
├── description     TEXT
├── severity        VARCHAR     NOT NULL
├── status          VARCHAR     NOT NULL DEFAULT 'open'
├── opened_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
├── closed_at       TIMESTAMPTZ
├── assigned_to     UUID        FK → app_users.id  (NULLABLE)
└── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
INDEX (status)
```

### 3.12 Evidence (Phase 2)

```
evidence
├── id              UUID        PRIMARY KEY
├── incident_id     UUID        FK → incidents.id
├── event_id        UUID        FK → events.id  (NULLABLE)
├── evidence_type   VARCHAR     NOT NULL
├── description     TEXT
├── data            JSONB
└── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

### 3.13 File Integrity Baseline (Phase 2)

```
file_integrity_baselines
├── id              UUID        PRIMARY KEY
├── host_id         UUID        FK → hosts.id
├── file_path       VARCHAR     NOT NULL
├── hash_sha256     VARCHAR     NOT NULL
├── file_size       BIGINT
├── permissions     VARCHAR
├── owner_uid       INTEGER
├── baseline_at     TIMESTAMPTZ NOT NULL
└── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
UNIQUE (host_id, file_path)
```

### 3.14 File Integrity Observation (Phase 2)

```
file_integrity_observations
├── id              UUID        PRIMARY KEY
├── baseline_id     UUID        FK → file_integrity_baselines.id
├── host_id         UUID        FK → hosts.id
├── file_path       VARCHAR     NOT NULL
├── hash_sha256     VARCHAR     NOT NULL
├── file_size       BIGINT
├── permissions     VARCHAR
├── owner_uid       INTEGER
├── observed_at     TIMESTAMPTZ NOT NULL
├── match           BOOLEAN     NOT NULL
└── created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

### 3.15 Application User

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
