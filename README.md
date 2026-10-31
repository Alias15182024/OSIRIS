# OSIRIS

### Operating System Incident Reconstruction and Intelligence System
**_Turning Events into Evidence_**

OSIRIS is a Linux-based system monitoring and cybersecurity investigation platform designed to collect, store, reconstruct, and analyze operating system activities. The project brings together concepts from **Operating Systems, Database Management Systems, and Cybersecurity** into a single investigative platform.

---

## Summary

OSIRIS monitors selected Linux activities related to processes, users, filesystem changes, and system resources. The collected activities are converted into structured, timestamped events and stored in a relational database using **PostgreSQL**.

The system maintains historical activity data so that users can examine events that occurred within a particular time period, reconstruct sequences of activities of interest, and analyze potentially suspicious behavior.

OSIRIS also includes an explainable security-analysis module that applies predefined rules to identify suspicious activities and generate alerts for further investigation.

---

## Core Capabilities

- Linux process and system activity monitoring
- Filesystem change monitoring
- System resource monitoring
- Structured event collection and normalization
- Historical event storage using PostgreSQL
- Historical activity reconstruction
- Explainable security analysis
- File integrity monitoring
- Alert generation and incident management
- Web-based monitoring and investigation dashboard

---

## Technology Stack

**Backend:** Python, FastAPI  
**Database:** PostgreSQL  
**Environment:** Linux  
**Frontend:** HTML, CSS, JavaScript

---

## System Workflow

```text
Linux System
     ↓
Activity Collection
     ↓
Event Normalization
     ↓
PostgreSQL Database
     ↓
Historical Reconstruction
     ↓
Security Analysis
     ↓
Alerts
     ↓
Incident Investigation
```

---

## Quickstart & Execution

### 1. Prerequisites
- Python 3.11+
- PostgreSQL 14+ (or SQLite fallback for isolated testing)

### 2. Environment Setup
```bash
# Clone and enter directory
cd OSIRIS

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install core and development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Configure environment variables
cp .env.example .env
# Edit .env with your PostgreSQL credentials and secure secret key
```

### 3. Database Migration & Seeding
```bash
# Apply canonical Alembic migrations (0001 through 0008)
alembic upgrade head

# Insert Phase 1 baseline development seed data (optional)
python -m database.seeds.seed_phase1
```

### 4. Running the Application
```bash
# Start backend API and SPA dashboard on http://127.0.0.1:8000
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### 5. Running the Test Suite (Cross-Platform)

```bash
# Recommended: Run full test suite using the portable runner
python scripts/run_tests.py -v

# Or run specific test modules
python scripts/run_tests.py tests/unit/test_fim_scanner.py -v
```

> [!NOTE]
> **Why `scripts/run_tests.py`?**
> The OSIRIS File Integrity Monitoring (FIM) subsystem intentionally excludes volatile temporary directories (`/tmp*` and `/var/tmp*`) as a core security baseline to prevent alert fatigue. On Linux (including Ubuntu), standard `pytest` creates temporary test directories under `/tmp/pytest-of-<user>/`, which the production scanner correctly excludes.
>
> The portable test runner (`scripts/run_tests.py`) allocates an isolated, unique test workspace under `~/.osiris_test_tmp/run_<pid>_<uuid>/`, passes it via `--basetemp`, forwards all arguments to `pytest`, and safely cleans up only its own temporary directory upon exit.
>
> **JavaScript Syntax Validation:**
> Contract tests validate frontend JavaScript syntax using `node --check` (or `nodejs --check` on Debian/Ubuntu), falling back to macOS JavaScriptCore (`jsc`). If no JavaScript runtime is installed, syntax checks are explicitly skipped with an informative installation hint rather than raising unexpected errors. To enable syntax checks on Ubuntu:
> ```bash
> sudo apt install -y nodejs
> ```

---

## Submission Documentation

- **[Final Completion Report](docs/OSIRIS_FINAL_COMPLETION_REPORT.md)**: Comprehensive project overview, Phase 1 & Phase 2 architecture, full migration audit, security review, benchmark reproducibility, and submission verdict.
- **[Project Demonstration Guide](docs/OSIRIS_PROJECT_DEMO_GUIDE.md)**: Step-by-step walkthrough of the end-to-end incident investigation workflow (*Operation DarkLoom*), demo account configuration, API catalog, and verification flows.
- **[System Architecture](docs/architecture.md)**: Layered component architecture and dataflow pipeline.
- **[Database Design](docs/database-design.md)**: Relational schema, indexes, forensic views, and triggers.
- **[Detection Engine](docs/detection-engine.md)**: Declarative rule evaluation and temporal sequence correlator.
- **[Development Roadmap](docs/development-roadmap.md)**: Phased implementation tracking and validation records.