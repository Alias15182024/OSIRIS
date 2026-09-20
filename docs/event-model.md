# OSIRIS Event Model

> Specification for the common event model used across all OSIRIS modules.

---

## 1. Overview

Every observation made by an OSIRIS collector is transformed into a **common event**
before it enters the database. This ensures that the database, detection engine,
reconstruction engine, and UI never need to understand Linux-specific data
formats directly.

**Key principle:** The event model is the contract between the Event Processing
Layer and all downstream modules. Collectors produce raw observations and
perform source-specific parsing; the **Event Processing Layer** is the single
authority that validates, normalizes, assigns event IDs, normalizes timestamps
to UTC, and enriches observations into common events.

---

## 2. Event Concept

An **event** represents a single, discrete observation of system activity at a
specific point in time.

Examples:

| Event Type              | Phase | Description                                    |
|-------------------------|-------|------------------------------------------------|
| `process.start`         | 1     | A new process was observed starting             |
| `process.end`           | 1     | A process was observed terminating              |
| `filesystem.create`     | 1     | A new file was created                          |
| `filesystem.modify`     | 1     | A file was modified                             |
| `filesystem.delete`     | 1     | A file was deleted                              |
| `resource.cpu`          | 1     | CPU utilization snapshot                        |
| `resource.memory`       | 1     | Memory utilization snapshot                     |
| `resource.disk`         | 1     | Disk I/O or usage snapshot                      |
| `auth.login_success`    | 2     | Successful user authentication                  |
| `auth.login_failure`    | 2     | Failed authentication attempt                   |
| `auth.sudo`             | 2     | Privilege escalation via sudo                   |
| `syslog.event`          | 2     | General system log event of security interest   |

---

## 3. Event Fields

### 3.1 Core Fields

Every event MUST contain the following fields:

| Field          | Type         | Description                                              |
|----------------|-------------|----------------------------------------------------------|
| `event_id`     | UUID         | Unique identifier assigned by the Event Processing Layer |
| `host_id`      | String       | Identifier of the monitored host                         |
| `timestamp`    | DateTime     | When the activity occurred on the source system (UTC)    |
| `ingested_at`  | DateTime     | When OSIRIS received and stored the event (UTC)          |
| `source`       | String       | Name of the collector that produced this event           |
| `event_type`   | String       | Hierarchical type identifier (e.g., `process.start`)     |
| `action`       | String       | The specific action observed                             |
| `severity`     | Enum         | `info`, `low`, `medium`, `high`, `critical`              |

### 3.2 Actor Fields

When the event involves a user or actor:

| Field          | Type         | Description                                              |
|----------------|-------------|----------------------------------------------------------|
| `uid`          | Integer      | Linux UID — the **preferred** Linux user identity. This is the source-level identifier as observed on the system. |
| `username`     | String       | **Supplementary/resolved.** Best-effort resolution of `uid` to a human-readable name. May be `null` if the user account has been deleted or cannot be resolved. Not authoritative — always prefer `uid` for identity matching. |

### 3.3 Process Fields

When the event involves a process:

| Field          | Type         | Description                                              |
|----------------|-------------|----------------------------------------------------------|
| `process_id`   | UUID         | **OSIRIS internal historical process identity.** Assigned by OSIRIS to uniquely identify a process instance across PID reuse. Links to the `processes` table. May be `null` if the process could not be resolved. |
| `pid`          | Integer      | **Linux PID** observed at the time of the event. This is the source-level identifier. PIDs are reused by Linux, so `pid` alone is NOT sufficient to uniquely identify a process over time — use `process_id` for that. |
| `ppid`         | Integer      | **Linux parent PID** observed at the time of the event. Same reuse caveats as `pid`. |
| `command`      | String       | Command line or executable name                          |

> **Identity distinction:** `pid` and `ppid` are **source-level Linux identifiers**
> observed at event time. `process_id` is the **OSIRIS internal identity** that
> remains stable even when Linux reuses the same PID number for a different
> process. The Event Processing Layer resolves `pid` + `host_id` + `timestamp`
> to the correct `process_id`.

### 3.4 Object Fields

When the event involves a target object (file, resource, etc.):

| Field              | Type     | Description                                          |
|--------------------|---------|------------------------------------------------------|
| `object_type`      | String  | Type of the target object (`file`, `socket`, etc.)   |
| `object_path`      | String  | Path or identifier of the target object              |

### 3.5 Result Fields

| Field          | Type         | Description                                              |
|----------------|-------------|----------------------------------------------------------|
| `success`      | Boolean      | Whether the observed action succeeded (if determinable)  |
| `result`       | String       | Additional result or status information                  |

### 3.6 Payload

| Field          | Type         | Description                                              |
|----------------|-------------|----------------------------------------------------------|
| `payload`      | JSON Object  | Source-specific additional data                           |

The payload stores structured data that is specific to a particular collector
or event type. It allows extensibility without modifying the core schema.

**Important:** Frequently queried relationships (process, user, file) are stored
as relational fields, NOT buried in the JSON payload.

---

## 4. Timestamp Handling

OSIRIS uses two timestamps for every event:

### 4.1 Event Timestamp (`timestamp`)

- When the activity actually occurred on the monitored system
- Reported by the collector in whatever form the source provides
- **Normalized to UTC by the Event Processing Layer** (not by the collector)
- This is the primary timestamp used for timeline queries

### 4.2 Ingestion Timestamp (`ingested_at`)

- When OSIRIS received and stored the event
- Set by the event processing layer at storage time
- Always UTC
- Used for audit purposes and to detect ingestion delays

### 4.3 Timestamp Rules

1. All timestamps are stored in UTC
2. Collectors report timestamps in the source system's time; the normalizer
   converts them to UTC
3. If a collector cannot determine the exact event time, it uses the collection
   time and marks this in the payload
4. Timestamps use ISO 8601 format in transit, stored as `TIMESTAMP WITH TIME ZONE`
   in PostgreSQL

---

## 5. Event Sources

Each event carries a `source` field identifying which collector produced it.

| Source Name       | Collector                       | Phase | Description                            |
|-------------------|---------------------------------|-------|----------------------------------------|
| `proc`            | Process Collector               | 1     | Process lifecycle and state             |
| `fs`              | Filesystem Collector            | 1     | File system changes                    |
| `resource`        | Resource Collector              | 1     | CPU, memory, disk metrics              |
| `syslog`          | Security/System Log Collector   | 2     | Authentication, sudo, security events  |

Future sources may be added by implementing new collectors that conform to
the `BaseCollector` interface. No changes to the event model or downstream
modules are required.

### 5.1 Process Collector (`proc`)

The Process Collector (`collectors/process/`) is the Phase 1 Linux collector for
process activity:

- **Source Filesystem**: Linux `/proc/<pid>/` (`stat`, `cmdline`, `status`, `exe`).
- **Identity Keying**: Tracks processes via `(pid, starttime)` composite key.
  `starttime` (clock ticks since boot from `/proc/<pid>/stat`) prevents PID
  reuse from incorrectly merging two distinct process lifecycles.
- **Lifecycle Events**:
  - `process.start` (action: `start`): Emitted when a new `(pid, starttime)` is observed.
  - `process.end` (action: `exit`): Emitted when a previously observed process disappears,
    preserving the last-known process metadata without attempting to read `/proc` post-exit.
- **Platform Policy**: Strictly Linux-only. Instantiation or collection against default
  `/proc` on non-Linux platforms raises `PlatformError`. Custom directory injection is
  supported strictly for unit testing.
- **Contract Boundary**: Emits `RawObservation` with `process_id=None`. OSIRIS internal
  process identity resolution and event UUID assignment are owned exclusively by downstream
  layers.

### 5.2 Filesystem Collector (`fs`)

The Filesystem Collector (`collectors/filesystem/`) is the Phase 1 Linux collector for
filesystem activity:

- **Notification Mechanism**: Linux kernel `inotify` subsystem via standard library `ctypes` wrapper.
- **Observed Events**:
  - `filesystem.create` (action: `create`): File or directory created in a watched path.
  - `filesystem.modify` (action: `modify`): File contents modified or metadata altered.
  - `filesystem.delete` (action: `delete`): File or directory deleted.
  - `filesystem.move` (action: `move`): File or directory renamed or moved.
- **Rename Correlation**: Correlates inotify `cookie` identifiers across `IN_MOVED_FROM`
  and `IN_MOVED_TO` events into a unified `filesystem.move` observation with both
  `from_path` and `to_path` recorded in the payload. Unmatched move notifications
  are captured deterministically.
- **Object Context**: Distinguishes files vs directories (`object_type`), records target path
  (`object_path`), and captures inode (`payload["inode"]`) when the path is accessible.
- **Platform Policy**: Strictly Linux-only for real collection. Instantiation with default
  backend on non-Linux platforms raises `PlatformError`. Pluggable mock backend is supported
  for deterministic cross-platform unit testing.
- **Timestamp Semantics**: Inotify does not provide kernel event timestamps. The observation
  timestamp reflects collection time and is marked with `payload["timestamp_source"] = "collection_time"`
  per §4.3 Rule 3.
- **Contract Boundary**: Emits `RawObservation` with `source="fs"` and `process_id=None`.
  Validation, timestamp UTC conversion, event UUID assignment, and persistence are owned
  exclusively by the Event Processing Layer.

### 5.3 Resource Collector (`resource`)

The Resource Collector (`collectors/resource/`) is the Phase 1 Linux collector for
system resource metrics:

- **Source Subsystem**: Linux `/proc` pseudo-filesystem (`/proc/stat`, `/proc/loadavg`,
  `/proc/meminfo`, `/proc/diskstats`) and standard library `os.statvfs` (strictly zero
  external dependencies; no `psutil`).
- **Observed Events**:
  - `resource.snapshot` (action: `snapshot`): Canonical consolidated system observation
    combining CPU utilization, load averages, memory metrics, disk I/O bytes, and disk
    usage into a single structured observation.
  - Granular events (action: `snapshot`): `resource.cpu`, `resource.memory`, and `resource.disk`
    available via `collect_observations(granular=True)` matching §2.
- **CPU Differential Utilization**:
  - On the first collection cycle, records baseline CPU ticks from `/proc/stat` and returns
    `cpu_percent = None`.
  - On subsequent cycles, calculates system-wide CPU utilization over `[0.0, 100.0]` from tick
    deltas: `(1.0 - (delta_idle / delta_total)) * 100.0`.
- **Memory Formulation**:
  - Core metrics: `memory_total` (`MemTotal * 1024`), `memory_used` (`(MemTotal - MemAvailable) * 1024`),
    and `memory_percent` (`round((memory_used / memory_total) * 100.0, 2)`).
  - Supplementary payload metrics: `memory_available`, `memory_free`, `buffers`, `cached`,
    `swap_total`, `swap_used`, `swap_percent`.
- **Disk I/O Aggregation**:
  - Aggregates whole physical/virtual block devices (`sd*`, `nvme*n*`, `vd*`, `xvd*`, `hd*`,
    `mmcblk*`) matching `WHOLE_DISK_PATTERN`, excluding partitions, loop devices, ramdisks,
    and device-mapper entries to prevent double counting.
  - Converts sector counts to bytes using standard Linux 512 bytes per sector.
- **Platform Policy**: Strictly Linux-only for live collection. Accessing default `/proc` on
  non-Linux platforms raises `PlatformError`. Injection of custom `proc_dir` and `statvfs_fn`
  is supported strictly for deterministic unit testing.
- **Timestamp Semantics**: Metrics represent point-in-time state at collection; timestamp is
  marked with `payload["timestamp_source"] = "collection_time"` per §4.3 Rule 3.
- **Contract Boundary**: Emits `RawObservation` with `source="resource"`, `process_id=None`,
  `pid=None`, `uid=None`. Direct persistence into `resource_snapshots` is decoupled and
  outside Milestone 1.4B; all observations flow through the authoritative Event Processing
  Layer.

### 5.4 Collector Orchestration (`CollectorOrchestrator`)

The Collector Orchestrator (`collectors/orchestrator.py`) is the coordinating layer
for Phase 1 collectors:

- **Coordinated Collectors**: Manages all active Phase 1 collectors (`ProcessCollector`,
  `ResourceCollector`, `FilesystemCollector`) under a unified `host_id`.
- **Scheduling & Concurrency**:
  - Drains the event-driven filesystem inotify buffer on every scheduler tick (e.g., 0.5s).
  - Polls process and resource collectors according to configurable intervals (`process_interval`,
    `resource_interval`).
  - Supports both synchronous, deterministic single-pass cycles (`run_cycle()`) and continuous
    background execution via a daemon worker thread (`start()` / `stop()`).
  - **Cycle Serialization**: Execution within `run_cycle()` is protected by a dedicated `_cycle_lock`.
    Concurrent invocations (e.g. background worker loop alongside manual forced cycles) are strictly
    serialized without interleaving collection or processing paths. The cycle lock is not held across
    `start()` or `stop()`.
- **Injectable Time Sources**:
  - Accepts injectable `monotonic_clock` and `wall_clock` callables. All interval gating and cycle
    durations use the monotonic clock, allowing tests to advance time deterministically without sleeps.
- **Startup Sequence & Rollback**:
  - Explicit 4-step sequence: construct collectors → register filesystem watches → start collectors
    → enter `RUNNING` state.
  - If watch registration or collector startup fails, immediately rolls back all initialized collectors,
    closing inotify file descriptors and watches cleanly without resource leaks.
- **Error Containment & Segmentation**:
  - `collector_errors`: Strictly limited to collector source failures (`"proc"`, `"resource"`, `"fs"`).
    A failure in one collector does not prevent remaining collectors from running.
  - `processing_errors`: Observation validation or normalization failures reported by `EventProcessor.process_batch()`.
  - `sink_errors`: Isolated downstream persistence or dispatch errors (`sink_errors["repository"]`,
    `sink_errors["callback"]`), ensuring sink failures do not pollute collector error telemetry.
  - `CycleResult.success`: Evaluates to `True` only when `collector_errors`, `processing_errors`, and
    `sink_errors` are all empty.
- **Contract Boundary & Persistence**:
  - Aggregates `RawObservation` objects and passes them to `EventProcessor`. Does not assign UUIDs,
    normalize timestamps, or enrich data.
  - Does not manage database sessions or transactions. An externally managed `EventRepository`
    or `event_callback` may be injected to receive normalized events.

---

## 6. Entity Relationships

Events reference several entities. These references allow OSIRIS to correlate
activities across different collectors and reconstruct comprehensive timelines.

```text
                    ┌──────────┐
                    │   Host   │
                    └────┬─────┘
                         │ has many
              ┌──────────┼──────────┐
              │          │          │
         ┌────▼───┐ ┌───▼────┐ ┌──▼────┐
         │ Process│ │  User  │ │ File  │
         └────┬───┘ └───┬────┘ └──┬────┘
              │         │         │
              └─────┬───┘─────────┘
                    │
              ┌─────▼─────┐
              │   Event   │
              └─────┬─────┘
                    │ may trigger
              ┌─────▼─────┐
              │   Alert   │
              └─────┬─────┘
                    │ grouped into
              ┌─────▼─────┐
              │ Incident  │
              └───────────┘
```

### 6.1 Host → Events

Every event belongs to a specific monitored host. In Phase 1, OSIRIS monitors
a single host, but the schema supports multiple hosts for future extensibility.

### 6.2 Process → Events

Process events reference PIDs. Since PIDs are reused by Linux, OSIRIS
distinguishes between two levels of process identity:

1. **`pid`** (source-level): The Linux PID observed at event time. Not
   globally unique due to PID reuse.
2. **`process_id`** (OSIRIS-level): An internal UUID assigned by OSIRIS to
   uniquely identify a process instance. Resolved by the Event Processing
   Layer using `host_id` + `pid` + `timestamp` against the `processes` table
   (which records start/end times).

This allows accurate correlation even when PIDs are recycled.

### 6.3 User → Events

Events reference Linux users by `uid`. Username resolution may not always be
possible (e.g., deleted user accounts), so `uid` is the primary identifier
and `username` is a best-effort supplementary field.

### 6.4 File → Events

File events reference files by path. File identity is complex because:

- Files can be renamed or moved
- Files can be deleted and recreated at the same path
- Hard links create multiple paths to the same inode

OSIRIS uses file path as the primary reference, with inode information
captured in the payload when available. This is an acknowledged limitation:
path-based tracking may lose correlation when files are renamed.

---

## 7. Process Identity Concerns

### 7.1 PID Reuse

Linux reuses PIDs. A PID observed at 10:00 may belong to a different process
than the same PID observed at 15:00.

OSIRIS mitigates this by:

1. Recording process start events (which establish PID → command mapping)
2. Recording process end events (which close the PID's lifecycle)
3. Using time-bounded PID lookups during reconstruction

### 7.2 Process Hierarchy

OSIRIS records PPID (parent PID) to support process tree reconstruction.
The same PID-reuse concerns apply to PPID values.

### 7.3 Short-Lived Processes

Processes that start and stop between collection cycles may not be captured.
This is an acknowledged limitation of polling-based collection.

---

## 8. File Identity Concerns

### 8.1 Path vs. Inode

OSIRIS primarily identifies files by path. Inode-based tracking is recorded
when available but is not the primary key, because:

- Inodes are filesystem-specific and not globally unique
- Inode numbers are reused after file deletion
- Tracking by path is more intuitive for investigators

### 8.2 Rename Tracking

If the filesystem collector uses `inotify`, rename events provide the old
and new path. OSIRIS records both paths to maintain correlation.

### 8.3 Directory Scope

Filesystem monitoring will cover configured directories, not the entire
filesystem. This is a deliberate scope limitation for performance and safety.

---

## 9. Normalization Principles

All normalization is performed by the **Event Processing Layer**, not by
individual collectors. Collectors perform source-specific parsing via
`parse()`, producing structured observation dicts. The Event Processing
Layer then applies the following principles:

### 9.1 Consistency

The Event Processing Layer produces common events in a uniform format.
A common event originating from the process collector is structurally
identical to one originating from the filesystem collector.

### 9.2 Completeness

The Event Processing Layer ensures all required fields are present.
Missing required fields cause the event to be rejected with a logged error.

### 9.3 Accuracy

Collectors report only what they actually observe. No values are interpolated
or fabricated. If a field cannot be determined, it is set to `null` rather
than guessed.

### 9.4 Enrichment

The Event Processing Layer may enrich events with additional context (e.g.,
resolving UID to username, resolving PID to `process_id`) but must never
alter the original observation data, which is preserved in the payload.

### 9.5 Idempotency

Each event receives a unique `event_id` (UUID) from the Event Processing
Layer. Duplicate detection is not currently in scope but may be added later
using a hash of key event fields.

---

## 10. Event Lifecycle

```text
1. Collector reads raw data from Linux subsystem          (Collector)
2. Collector calls parse() to produce a structured        (Collector)
   observation dict with source-specific parsing
3. Observation is submitted to the Event Processing Layer (Handoff)
4. Event Processing Layer validates required fields       (Event Processing)
5. Event Processing Layer assigns event_id (UUID)         (Event Processing)
6. Event Processing Layer normalizes timestamp to UTC     (Event Processing)
7. Event Processing Layer enriches fields                 (Event Processing)
   (e.g., UID → username, PID → process_id)
8. Event Processing Layer sets ingested_at timestamp      (Event Processing)
9. Common event is persisted to PostgreSQL                (Database)
10. Detection engine evaluates the event against rules    (Phase 2)
11. If a rule matches, an alert is generated              (Phase 2)
```

**Boundary:** Steps 1–2 are the collector's responsibility. Steps 4–8 are
exclusively the Event Processing Layer's responsibility. No other layer may
assign event IDs or perform final normalization.

---

## 11. Event Processing Implementation Contract

The Event Processing Layer (`backend/services/events/`) implements the contract
between raw collector observations and PostgreSQL persistence.

### 11.1 Raw Observation Boundary (`RawObservation`)

Collectors submit observations conforming to `RawObservation`. This model
is independent of the SQLAlchemy persistence model:

- Required fields: `source`, `host_id`, `event_type`, `action`
- Optional context: `observed_at`, `uid`, `username`, `pid`, `ppid`, `command`, `process_id`, `object_type`, `object_path`, `success`, `result`
- Source-specific extensibility: `payload` (JSON object)

### 11.2 Validation Rules (`validator.py`)

Validation runs before normalization and aggregates all errors:

1. `source`, `event_type`, and `action` must be non-empty strings
2. `severity` must belong to the canonical set: `info`, `low`, `medium`, `high`, `critical`
3. `observed_at` is required, must parse as a valid timestamp, and must be timezone-aware
4. `uid`, `pid`, and `ppid` must be non-negative integers when present (`>= 0`)
5. Malformed observations are rejected with explicit, actionable error messages

### 11.3 Timestamp Normalization Policy (`normalizer.py`)

All timestamps entering OSIRIS must be normalized to timezone-aware UTC:

1. Timezone-aware timestamps (`datetime` or ISO 8601 string with offset) are converted to UTC (`timezone.utc`)
2. Naive timestamps (lacking timezone information) are **explicitly rejected**; OSIRIS does not guess or assume local timezones
3. Ingestion timestamp (`ingested_at`) is assigned by the normalizer at processing time in UTC

### 11.4 Event ID Ownership

The Event Processing Layer exclusively assigns the unique event UUID (`id`).
Collectors must never assign or control the authoritative OSIRIS event UUID.

### 11.5 Enrichment Boundary (`enricher.py`)

In Phase 1, enrichment is deterministic and self-contained:

- Strips and lowercases `source` and `event_type` for canonical formatting
- Strips extraneous whitespace from `username`
- Extracts `command` from `payload` if omitted from the top-level actor context
- Leaves live `/proc` lookups and runtime entity resolution as planned future extensions (Milestone 1.4+)

### 11.6 Normalized Event (`NormalizedEvent`)

The authoritative domain representation of a processed event. Enforces type
invariants and non-negative constraints via Pydantic validators before persistence.

### 11.7 Persistence Boundary (`EventRepository`)

The `EventRepository` maps `NormalizedEvent` to the SQLAlchemy `Event` ORM model:

- Operates within caller-managed database sessions/transactions
- Flushes immediately to detect constraint violations (e.g., foreign key errors)
- Supports single-event and batch persistence without partial silent writes
- Rolls back atomically on error

