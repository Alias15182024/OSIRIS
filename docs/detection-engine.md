# OSIRIS Detection Engine & Rules Manual

## 1. Overview & Architectural Philosophy

The **OSIRIS Detection Engine** provides real-time and post-ingestion declarative security detection capabilities for endpoint telemetry collected by OSIRIS. It evaluates telemetry events against declarative rule sets to identify suspicious activity, privilege escalation, credential abuse, and reconnaissance maneuvers.

### Core Architectural Principles
1. **Declarative & Safe (Zero-Eval):** Detection rules are defined strictly in declarative YAML/JSON format. Rule conditions are evaluated using an Abstract Syntax Tree (AST) parser in native Python. Under no circumstances are `eval()`, `exec()`, or dynamic code generators invoked.
2. **Deterministic & Explainable:** Every generated detection contains complete explainability metadata (`matched_conditions`) recording the exact boolean sub-clauses that evaluated to true, the observed runtime values, and the expected values, alongside structured forensic evidence (`evidence`).
3. **Multi-Event Sequence Correlation:** Beyond atomic, single-event pattern matching, the engine provides stateful temporal sequence correlation capable of detecting threshold-based behaviors (e.g. brute force attempts) and multi-stage attack patterns (e.g. failed authentication followed by successful logon, or rapid reconnaissance tool sequences) within bounded sliding time windows.
4. **Deterministic Deduplication:** To prevent alert fatigue and redundant database storage during repeated evaluation, detections are hashed using SHA-256 over their rule ID, host UUID, and sorted triggering event UUIDs.
5. **Strict Host Isolation:** Detections and temporal correlation windows are strictly scoped to individual hosts. Events originating from different hosts are never correlated across sequences.
6. **Separation of Detection and Incident Management:** In OSIRIS, **Detections** (Milestone 2.4) represent atomic security findings generated directly by detection rules. **Incidents** (Milestone 2.6) represent higher-order investigation containers that group one or more related detections/alerts, associate external evidence artifacts, and manage the analyst investigation lifecycle.

---

## 2. Rule Specification Format

Detection rules are defined as YAML files stored in `backend/services/detection/rules/` and synchronized to the `detection_rules` database table.

### 2.1 Rule Schema Definition

| Field | Type | Required | Description |
|---|---|---|---|
| `rule_id` | String | Yes | Unique rule identifier (format: `OSIRIS-<CATEGORY>-<NUM>`, e.g., `OSIRIS-PRIV-001`). Max 100 chars. |
| `name` | String | Yes | Human-readable title for the detection rule. Max 255 chars. |
| `description` | String | No | Comprehensive explanation of the threat, attack technique, and risk. |
| `severity` | String | Yes | Threat severity: `critical`, `high`, `medium`, `low`, or `info`. |
| `category` | String | Yes | Threat category: `privilege_escalation`, `suspicious_authentication`, `reconnaissance`, `persistence`, `execution`, `file_integrity`, `defense_evasion`, `lateral_movement`. |
| `enabled` | Boolean | No | Administrative toggle enabling/disabling rule evaluation (default: `true`). |
| `version` | Integer | No | Schema/rule revision number (default: `1`). |
| `rule_type` | String | No | Rule evaluation type: `single_event` (default) or `sequence`. |
| `explanation` | String | No | Threat rationale and operational context. |
| `conditions` | Object | Yes* | Boolean AST tree for single-event evaluation (*required if `rule_type == "single_event"`). |
| `sequence` | Object | Yes* | Multi-stage temporal sequence correlation definition (*required if `rule_type == "sequence"`). |
| `metadata` | Object | No | Key-value metadata (e.g. `mitre_technique`, `mitre_tactic`, `author`). |

---

## 3. Condition Evaluator & Operator Catalogue

Rule conditions represent an Abstract Syntax Tree (AST) composed of logical grouping nodes (`all`, `any`, `not`) and leaf comparison nodes (`field`, `operator`, `value`).

### 3.1 Field Extraction
Field paths support top-level event fields and nested payload fields using standard dot notation:
- Top-level fields: `event_type`, `action`, `source`, `severity`, `uid`, `username`, `pid`, `ppid`, `command`, `process_id`, `session_id`, `object_type`, `object_path`, `success`, `result`, `host_id`, `timestamp`.
- Nested payload fields: `payload.<key>` (e.g. `payload.remote_host`).

If a path does not exist, the extractor returns `None` safely without throwing an exception.

### 3.2 Comparison Operators

| Operator | Target Types | Description | Example |
|---|---|---|---|
| `==`, `eq` | Any | Equality comparison. | `field: event_type, operator: "==", value: "auth:sudo"` |
| `!=`, `neq` | Any | Inequality comparison. | `field: username, operator: "!=", value: "root"` |
| `>`, `gt` | Numeric | Greater than. | `field: uid, operator: ">", value: 1000` |
| `<`, `lt` | Numeric | Less than. | `field: uid, operator: "<", value: 500` |
| `>=`, `gte` | Numeric | Greater than or equal to. | `field: uid, operator: ">=", value: 1000` |
| `<=`, `lte` | Numeric | Less than or equal to. | `field: pid, operator: "<=", value: 100` |
| `in` | Collection | Target value is contained in collection. | `field: event_type, operator: "in", value: ["proc:exec", "proc:start"]` |
| `not_in` | Collection | Target value is not in collection. | `field: username, operator: "not_in", value: ["root", "daemon"]` |
| `contains` | String | Field string contains substring. | `field: command, operator: "contains", value: "sudo -i"` |
| `startswith` | String | Field string begins with prefix. | `field: command, operator: "startswith", value: "pkexec"` |
| `endswith` | String | Field string ends with suffix. | `field: object_path, operator: "endswith", value: "/sudoers"` |
| `regex` | String | Regular expression match. | `field: command, operator: "regex", value: "^(?:/usr/bin/|/bin/)?w(\\s.*)?$"` |
| `exists` | Any | Field value is present and not `None`. | `field: payload.remote_host, operator: "exists"` |
| `not_exists` | Any | Field value is missing or evaluates to `None`. | `field: process_id, operator: "not_exists"` |

### 3.3 Logical Grouping Nodes

Conditions can be nested to arbitrary depths using boolean combinators:
- **`all` (Logical AND):** All child conditions must evaluate to `True`.
- **`any` (Logical OR):** At least one child condition must evaluate to `True`.
- **`not` (Logical NOT):** Inverts the evaluation of the nested condition.

#### Example Single-Event Condition:
```yaml
rule_id: OSIRIS-PRIV-001
name: Suspicious Sudo Execution by Non-Admin
category: privilege_escalation
severity: high
enabled: true
rule_type: single_event
conditions:
  all:
    - field: event_type
      operator: in
      value: ["auth:sudo", "proc:exec", "proc:start"]
    - any:
        - field: command
          operator: contains
          value: "sudo -i"
        - field: command
          operator: contains
          value: "sudo -s"
```

---

## 4. Multi-Event Sequence Correlation

Sequence correlation detects complex, multi-stage attacks occurring across time.

### 4.1 Sequence Definition Format
A sequence rule specifies a time window, and an ordered list of stages:

```yaml
rule_id: OSIRIS-AUTH-002
name: Failed Logins Followed by Successful Authentication
category: suspicious_authentication
severity: high
enabled: true
rule_type: sequence
sequence:
  time_window_seconds: 300
  stages:
    - stage_id: failed_attempts
      conditions:
        all:
          - field: event_type
            operator: in
            value: ["auth:login:fail", "auth:ssh:fail"]
      min_count: 2
      match_fields: ["username"]
    - stage_id: successful_login
      conditions:
        all:
          - field: event_type
            operator: in
            value: ["auth:login:success", "auth:ssh:success"]
      min_count: 1
      match_fields: ["username"]
```

### 4.2 Sequence Evaluation Mechanics
1. **Host-Scoped Partitioning:** Sequence correlation evaluates events grouped strictly by `host_id`. Events from distinct hosts never interact.
2. **Chronological Ingestion:** Events are sorted by UTC timestamp ascending (then by event UUID for determinism) before evaluation.
3. **Sliding Time Window:** All stages must complete within `time_window_seconds`. Specifically, the time elapsed between the first triggering event of stage 1 and the final event of the last stage must be `<= time_window_seconds`.
4. **Field Correlation (`match_fields`):** When `match_fields` is specified (e.g., `["username"]`), all events participating in the sequence across stages where `match_fields` is active must share the exact same non-None value for that field. Intra-stage and inter-stage correlation is strictly enforced.
5. **Stage Progression & Zero Event Reuse:** The sequence progresses sequentially through Stage 0, Stage 1, ..., Stage K-1. A stage is fulfilled when at least `min_count` events satisfy its condition within the sliding window, and distinct events are required for every stage.

---

## 5. Deterministic Deduplication

To eliminate duplicate alerts from recurring events, the engine computes a deterministic SHA-256 deduplication hash over the rule ID, host ID, and sorted triggering event IDs:

```python
dedup_hash = hashlib.sha256(
    f"{rule_id}:{host_id}:{','.join(sorted_eids)}".encode("utf-8")
).hexdigest()
```

If a detection with an identical `dedup_hash` already exists in the database, repeated evaluations do not insert duplicate records.

---

## 6. Explainability & Evidence Capture

Every detection persisted to the database includes full explainability data:

### `matched_conditions`
Captures the evaluated AST branch with actual observed runtime values vs expected values:
```json
{
  "conditions": [
    {
      "field": "command",
      "operator": "contains",
      "expected": "sudo -i",
      "actual": "sudo -i",
      "passed": true
    }
  ]
}
```

### `evidence`
Extracts relevant forensic artifacts from the triggering event(s):
- `rule_id`: String identifier of the rule.
- `command`: Full command line execution string.
- `username`: Initiating Linux username.
- `uid`: User ID.
- `event_type`: Type of event.
- `object_path`: Target file or object path.
- `triggering_event_id`: Primary triggering event identifier.
- `stages`: In sequence rules, per-stage event breakdown with individual event IDs.

---

## 7. Initial Rule Catalogue

The engine ships with 9 production detection rules covering high-risk Linux attack techniques:

### Privilege Escalation
1. **`OSIRIS-PRIV-001` (High) — Suspicious Sudo Execution by Non-Admin:**
   - Detects users invoking sudo with interactive shells (`sudo -i`, `sudo -s`, `sudo su`, `sudo /bin/bash`).
   - MITRE: `T1548.003` (Privilege Escalation: Sudo and Sudo Caching)
2. **`OSIRIS-PRIV-002` (Medium) — Unexpected Privilege Boundary Binary Execution:**
   - Detects execution of privilege-transition binaries (`pkexec`, `su`).
   - MITRE: `T1548.001` (Privilege Escalation: Setuid and Setgid)
3. **`OSIRIS-PRIV-003` (Critical) — Sudoers Configuration Modification or Tampering:**
   - Detects modification or write access to `/etc/sudoers` or files inside `/etc/sudoers.d/`, or use of `visudo`.
   - MITRE: `T1548.003` (Privilege Escalation: Sudo and Sudo Caching)

### Suspicious Authentication
4. **`OSIRIS-AUTH-001` (Medium, Sequence) — Repeated Failed Authentication Attempts:**
   - Detects multiple consecutive failed authentications within a 300s window.
   - MITRE: `T1110.001` (Credential Access: Password Guessing)
5. **`OSIRIS-AUTH-002` (High, Sequence) — Failed Logins Followed by Successful Authentication:**
   - Detects repeated authentication failures followed by a successful login for the same target user within 300s.
   - MITRE: `T1110.001` (Credential Access: Password Spraying / Brute Force)
6. **`OSIRIS-AUTH-003` (High) — Direct Remote Root Login Observed:**
   - Detects direct remote SSH or login authentication as `root` from an external network host.
   - MITRE: `T1078.001` (Initial Access: Valid Accounts)

### Reconnaissance
7. **`OSIRIS-RECON-001` (Medium, Sequence) — Rapid Host and Network Discovery Execution Chain:**
   - Detects sequential execution of system identification (`uname`, `whoami`, `id`) and network discovery (`ip`, `ifconfig`, `netstat`, `ss`) commands within 180s.
   - MITRE: `T1082` (Discovery: System Information Discovery)
8. **`OSIRIS-RECON-002` (Low) — User Account and Group Enumeration:**
   - Detects command-line enumeration of accounts (`/etc/passwd`, `getent passwd`, `lastlog`, `w`, `who`).
   - MITRE: `T1087.001` (Discovery: Local Accounts)
9. **`OSIRIS-RECON-003` (Critical) — Sensitive Credential and System File Inspection:**
   - Detects process access or file operations targeting sensitive credential databases and private keys (`/etc/shadow`, `/etc/gshadow`, `id_rsa`, `id_ed25519`).
   - MITRE: `T1003.008` (Credential Access: /etc/passwd and /etc/shadow)

---

## 8. Detection REST API Reference

All detection endpoints require Bearer JWT authentication.

### Endpoints
- **`GET /api/detections`**: Query paginated detections with filtering:
  - `host_id` (UUID, optional)
  - `rule_id` (String, optional)
  - `severity` (String: `critical`, `high`, `medium`, `low`, `info`, optional)
  - `category` (String, optional)
  - `status` (String: `open`, `acknowledged`, `resolved`, `closed`, optional)
  - `start_time` / `end_time` (ISO-8601 UTC timestamps, optional)
  - `limit` (int, default 50, max 500)
  - `offset` (int, default 0)
- **`GET /api/detections/rules`**: List all registered detection rules.
  - `category` (optional filter)
  - `severity` (optional filter)
  - `enabled` (optional boolean filter)
- **`GET /api/detections/rules/{rule_identifier}`**: Retrieve specific rule specification by ID or UUID.
- **`GET /api/detections/{detection_id}`**: Retrieve single detection with full explainability condition tree and evidence payload.
- **`POST /api/detections/{detection_id}/acknowledge`**: Mark detection as acknowledged.
  - Body: `{"notes": "Analyst confirmation notes"}`
  - Records `acknowledged_at` timestamp and `acknowledged_by` username.

---

## 9. Rule Authoring Guide

To author a new detection rule:
1. Create a new YAML file under `backend/services/detection/rules/` (e.g. `priv_004_new_rule.yaml`).
2. Provide mandatory metadata: `rule_id`, `name`, `description`, `severity`, `category`.
3. Construct the boolean `conditions` AST or temporal `sequence` block.
4. Validate the rule definition using the built-in validator:
   ```python
   from backend.services.detection.validator import validate_rule_yaml
   with open("backend/services/detection/rules/priv_004_new_rule.yaml") as f:
       rule_def = validate_rule_yaml(f.read())
   ```
5. Synchronize the rules into the database via `DetectionService(session).sync_rules()`.
6. Add corresponding unit test cases in `tests/unit/test_initial_rules.py` verifying both matching behavior and negative non-matching conditions.
