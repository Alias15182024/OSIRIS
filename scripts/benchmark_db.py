#!/usr/bin/env python3
"""Forensic Database Benchmark Utility (Phase 2 Milestone 2.8).

Runs repeatable forensic query performance benchmarks across dataset sizes,
measures query execution times, row counts, query counts, and outputs
formatted markdown benchmark tables for reporting and performance auditing.

Usage:
    python scripts/benchmark_db.py [--scale {small,medium,large}] [--db-url DB_URL] [--format {markdown,json}]
"""

from __future__ import annotations

import os
import sys

# Auto re-exec with virtualenv python if invoked with outdated system Python < 3.10
if sys.version_info < (3, 10):
    _project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _venv_python = os.path.join(_project_root, ".venv", "bin", "python")
    if os.path.exists(_venv_python):
        os.execv(_venv_python, [_venv_python] + sys.argv)
    else:
        sys.stderr.write("Error: Python >= 3.10 is required to run benchmark_db.py\n")
        sys.exit(1)

import argparse
import json
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import sqlalchemy as sa
from sqlalchemy import event, select, text
from sqlalchemy.orm import Session

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.api.schemas.search import SearchFilter
from backend.config import settings
from backend.db.base import Base, new_uuid
from backend.db.models.app_user import AppUser
from backend.db.models.detection import Detection
from backend.db.models.detection_rule import DetectionRule
from backend.db.models.event import Event
from backend.db.models.evidence_annotation import EvidenceAnnotation
from backend.db.models.evidence_tag import EvidenceTag
from backend.db.models.evidence_tag_association import EvidenceTagAssociation
from backend.db.models.file import File
from backend.db.models.fim_baseline import FimBaseline
from backend.db.models.fim_baseline_file import FimBaselineFile
from backend.db.models.fim_deviation import FimDeviation
from backend.db.models.host import Host
from backend.db.models.incident import Incident
from backend.db.models.incident_evidence import IncidentEvidence
from backend.db.models.incident_history import IncidentHistory
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.resource_snapshot import ResourceSnapshot
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession
from backend.db.models.workspace import Workspace
from backend.services.detection.service import DetectionService
from backend.services.fim.service import FimService
from backend.services.incidents.service import IncidentService
from backend.services.sessions.service import SessionReconstructionService
from backend.services.snapshots.service import SnapshotService
from backend.services.timeline.service import TimelineService
from backend.services.workspace.graph import EntityGraphService
from backend.services.workspace.search import AdvancedSearchService


class QueryCounter:
    """Tracks number of SQL statements executed on an engine."""

    def __init__(self, engine: sa.Engine) -> None:
        self.engine = engine
        self.count = 0
        self._listener = self._on_execute

    def _on_execute(self, conn, cursor, statement, parameters, context, executemany):  # type: ignore[no-untyped-def]
        self.count += 1

    def __enter__(self) -> "QueryCounter":
        self.count = 0
        event.listen(self.engine, "before_cursor_execute", self._listener)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        event.remove(self.engine, "before_cursor_execute", self._listener)


@dataclass
class BenchmarkResult:
    category: str
    benchmark_name: str
    target_operation: str
    dataset_scale: str
    total_records: int
    execution_time_ms: float
    query_count: int
    sla_threshold_ms: float
    status: str
    notes: str = ""


SCALE_CONFIGS = {
    "small": {
        "processes": 100,
        "sessions": 10,
        "events": 200,
        "detections": 30,
        "baseline_files": 100,
        "deviations": 20,
        "incidents": 10,
    },
    "medium": {
        "processes": 500,
        "sessions": 50,
        "events": 1000,
        "detections": 150,
        "baseline_files": 500,
        "deviations": 100,
        "incidents": 50,
    },
    "large": {
        "processes": 2000,
        "sessions": 200,
        "events": 5000,
        "detections": 500,
        "baseline_files": 2000,
        "deviations": 300,
        "incidents": 200,
    },
}


def populate_benchmark_data(session: Session, scale: str = "small") -> dict[str, Any]:
    """Generate and insert synthetic forensic dataset according to scale profile."""
    cfg = SCALE_CONFIGS.get(scale, SCALE_CONFIGS["small"])
    base_time = datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc)
    host_id = new_uuid()
    host = Host(
        id=host_id,
        hostname=f"bench-{scale}-srv",
        os_info="Linux 6.8.0-benchmark",
        ip_address="10.0.0.100",
        created_at=base_time,
    )
    session.add(host)

    # Users
    user_root = LinuxUser(id=new_uuid(), host_id=host_id, uid=0, username="root", first_seen_at=base_time)
    user_alice = LinuxUser(id=new_uuid(), host_id=host_id, uid=1001, username="alice", first_seen_at=base_time)
    app_admin = AppUser(id=new_uuid(), username=f"admin_{scale}", password_hash="hash", role="admin")
    session.add_all([user_root, user_alice, app_admin])
    session.flush()

    # Processes
    procs = []
    for i in range(cfg["processes"]):
        p_ts = base_time + timedelta(seconds=i * 5)
        p = Process(
            id=new_uuid(),
            host_id=host_id,
            pid=1000 + (i % 30000),
            ppid=1000 if i > 0 else 1,
            command=f"/usr/bin/service_{i % 50} --worker",
            executable=f"/usr/bin/service_{i % 50}",
            linux_user_id=user_alice.id if i % 2 == 0 else user_root.id,
            started_at=p_ts,
            ended_at=p_ts + timedelta(seconds=600) if i % 3 == 0 else None,
        )
        procs.append(p)
    session.add_all(procs)
    session.flush()

    # Sessions
    sessions = []
    for i in range(cfg["sessions"]):
        s_ts = base_time + timedelta(minutes=i * 10)
        s = UserSession(
            id=new_uuid(),
            host_id=host_id,
            linux_user_id=user_alice.id if i % 2 == 0 else user_root.id,
            session_type="ssh",
            terminal=f"pts/{i % 20}",
            remote_host=f"192.168.1.{10 + (i % 200)}",
            started_at=s_ts,
            ended_at=s_ts + timedelta(minutes=60) if i % 4 != 0 else None,
        )
        sessions.append(s)
    session.add_all(sessions)
    session.flush()

    # Events
    events = []
    for i in range(cfg["events"]):
        e_ts = base_time + timedelta(seconds=i * 3)
        p = procs[i % len(procs)]
        e = Event(
            id=new_uuid(),
            host_id=host_id,
            process_id=p.id,
            timestamp=e_ts,
            source="process" if i % 2 == 0 else "syslog",
            event_type="process.exec" if i % 2 == 0 else "auth.login",
            action="execute" if i % 2 == 0 else "login",
            severity="info" if i % 4 != 0 else "high",
            uid=p.linux_user.uid if p.linux_user else 1001,
            username=p.linux_user.username if p.linux_user else "alice",
            pid=p.pid,
            ppid=p.ppid,
            command=p.command,
        )
        events.append(e)
    session.add_all(events)
    session.flush()

    # Detection Rules & Detections
    rule = DetectionRule(
        id=new_uuid(),
        rule_id=f"BENCH-RULE-{scale.upper()}",
        name="Benchmark Rule",
        description="Benchmark rule description",
        category="execution",
        severity="high",
        enabled=True,
        version=1,
        rule_type="single_event",
        conditions={"field": "severity", "operator": "equals", "value": "high"},
    )
    session.add(rule)
    session.flush()

    dets = []
    for i in range(cfg["detections"]):
        d_ts = base_time + timedelta(minutes=i * 2)
        d = Detection(
            id=new_uuid(),
            rule_id=rule.id,
            rule_version=1,
            host_id=host_id,
            event_id=events[i % len(events)].id,
            process_id=procs[i % len(procs)].id,
            timestamp=d_ts,
            severity="high" if i % 3 == 0 else "medium",
            title=f"Security Alert #{i}",
            description="Detected anomalous activity",
            category="execution",
            status="open" if i % 2 == 0 else "resolved",
            notification_status="sent",
            matched_conditions={},
            evidence={},
            dedup_hash=f"bench_hash_{scale}_{i:05d}",
        )
        dets.append(d)
    session.add_all(dets)
    session.flush()

    # FIM Baseline & Files
    baseline = FimBaseline(
        id=new_uuid(),
        host_id=host_id,
        version=1,
        status="completed",
        path_scope=["/etc", "/bin"],
        total_files=cfg["baseline_files"],
        total_bytes=1048576,
        baseline_at=base_time,
    )
    session.add(baseline)
    session.flush()

    bf_list = []
    for i in range(cfg["baseline_files"]):
        bf = FimBaselineFile(
            id=new_uuid(),
            baseline_id=baseline.id,
            host_id=host_id,
            file_path=f"/etc/config/file_{i:04d}.conf",
            file_name=f"file_{i:04d}.conf",
            file_type="file",
            hash_sha256=f"hash_sha256_{i:04d}" * 4,
            file_size=1024 + i,
            permissions="0644",
            mode=33188,
            owner_uid=0,
            owner_gid=0,
            created_at=base_time,
        )
        bf_list.append(bf)
    session.add_all(bf_list)
    session.flush()

    # FIM Deviations
    devs = []
    for i in range(cfg["deviations"]):
        dev = FimDeviation(
            id=new_uuid(),
            host_id=host_id,
            baseline_id=baseline.id,
            baseline_file_id=bf_list[i % len(bf_list)].id,
            file_path=bf_list[i % len(bf_list)].file_path,
            deviation_type="modified_file" if i % 2 == 0 else "new_file",
            severity="critical" if i % 4 == 0 else "medium",
            detected_at=base_time + timedelta(minutes=i * 5),
            summary=f"File {bf_list[i % len(bf_list)].file_path} checksum mismatch",
        )
        devs.append(dev)
    session.add_all(devs)
    session.flush()

    # Incidents & Evidence
    incidents = []
    for i in range(cfg["incidents"]):
        inc = Incident(
            id=new_uuid(),
            title=f"Security Incident #{i}",
            severity="critical" if i < 3 else "high",
            status="open" if i % 2 == 0 else "investigating",
            category="execution",
            host_id=host_id,
            created_by_id=app_admin.id,
            first_observed_at=base_time,
            last_observed_at=base_time + timedelta(hours=i),
            created_at=base_time + timedelta(hours=i),
        )
        incidents.append(inc)
    session.add_all(incidents)
    session.flush()

    for i in range(min(10, len(dets))):
        ie = IncidentEvidence(
            id=new_uuid(),
            incident_id=incidents[0].id,
            evidence_type="detection",
            source_id=str(dets[i].id),
            title=f"Correlated Alert {i}",
            provenance={"rule": rule.rule_id},
            detection_id=dets[i].id,
        )
        session.add(ie)

    # Workspace & Annotations
    tag = EvidenceTag(id=new_uuid(), name=f"threat-actor-{scale}", category="threat_actor", color="#ef4444")
    session.add(tag)
    session.flush()

    ws = Workspace(
        id=new_uuid(),
        name=f"Forensic Analysis {scale}",
        owner_id=app_admin.id,
        host_id=host_id,
        incident_id=incidents[0].id,
        status="active",
        configuration={"panels": ["graph", "timeline"]},
    )
    session.add(ws)
    session.flush()

    assoc = EvidenceTagAssociation(
        id=new_uuid(),
        tag_id=tag.id,
        evidence_type="incident",
        evidence_id=str(incidents[0].id),
        host_id=host_id,
    )
    session.add(assoc)

    annot = EvidenceAnnotation(
        id=new_uuid(),
        evidence_type="incident",
        evidence_id=str(incidents[0].id),
        host_id=host_id,
        workspace_id=ws.id,
        author_id=app_admin.id,
        annotation_text="Identified anomalous execution chain",
    )
    session.add(annot)
    session.flush()

    return {
        "host_id": host_id,
        "incident_id": incidents[0].id,
        "user_id": user_alice.id,
        "app_admin_id": app_admin.id,
        "baseline_id": baseline.id,
        "workspace_id": ws.id,
        "total_events": cfg["events"],
        "total_procs": cfg["processes"],
        "total_dets": cfg["detections"],
        "total_files": cfg["baseline_files"],
        "total_devs": cfg["deviations"],
        "total_incidents": cfg["incidents"],
    }


def run_benchmarks(engine: sa.Engine, scale: str = "small") -> list[BenchmarkResult]:
    """Execute forensic benchmark suite and collect performance metrics."""
    results: list[BenchmarkResult] = []

    # Connection and transaction
    conn = engine.connect()
    trans = conn.begin()
    db = Session(bind=conn, join_transaction_mode="create_savepoint")

    try:
        entities = populate_benchmark_data(db, scale=scale)
        host_id = entities["host_id"]
        incident_id = entities["incident_id"]
        baseline_id = entities["baseline_id"]

        # 1. Timeline Reconstruction & N+1 Elimination
        timeline_svc = TimelineService(session=db)
        with QueryCounter(engine) as counter:
            t0 = time.perf_counter()
            entries, total = timeline_svc.reconstruct_timeline(
                host_id=host_id,
                limit=50,
                offset=0,
            )
            elapsed = (time.perf_counter() - t0) * 1000

        results.append(
            BenchmarkResult(
                category="Forensic Timeline",
                benchmark_name="Unified Timeline Reconstruction",
                target_operation="reconstruct_timeline(limit=50)",
                dataset_scale=scale,
                total_records=entities["total_events"],
                execution_time_ms=round(elapsed, 2),
                query_count=counter.count,
                sla_threshold_ms=500.0,
                status="PASS" if elapsed < 500.0 and counter.count <= 15 else "FAIL",
                notes=f"Retrieved {len(entries)} entries, {counter.count} queries (N+1 eliminated)",
            )
        )

        # 2. Detections Filtered by Host & Status
        det_svc = DetectionService()
        with QueryCounter(engine) as counter:
            t0 = time.perf_counter()
            items, det_total = det_svc.get_detections(
                db=db,
                host_id=host_id,
                status="open",
                limit=25,
            )
            elapsed = (time.perf_counter() - t0) * 1000

        results.append(
            BenchmarkResult(
                category="Detections",
                benchmark_name="Host & Status Filtered Detections",
                target_operation="get_detections(status='open', limit=25)",
                dataset_scale=scale,
                total_records=entities["total_dets"],
                execution_time_ms=round(elapsed, 2),
                query_count=counter.count,
                sla_threshold_ms=200.0,
                status="PASS" if elapsed < 200.0 and counter.count == 2 else "FAIL",
                notes=f"Retrieved {len(items)} items in {counter.count} queries via composite index",
            )
        )

        # 3. FIM Baseline Inventory & Deviations
        fim_svc = FimService()
        with QueryCounter(engine) as counter:
            t0 = time.perf_counter()
            bf_items, bf_total = fim_svc.get_baseline_files(
                db=db,
                baseline_id=baseline_id,
                path_prefix="/etc/config",
                limit=50,
            )
            dev_items, dev_total = fim_svc.get_deviations(
                db=db,
                host_id=host_id,
                severity="critical",
                limit=50,
            )
            elapsed = (time.perf_counter() - t0) * 1000

        results.append(
            BenchmarkResult(
                category="FIM",
                benchmark_name="FIM Baseline & Deviation Lookups",
                target_operation="get_baseline_files + get_deviations",
                dataset_scale=scale,
                total_records=entities["total_files"] + entities["total_devs"],
                execution_time_ms=round(elapsed, 2),
                query_count=counter.count,
                sla_threshold_ms=200.0,
                status="PASS" if elapsed < 200.0 and counter.count == 4 else "FAIL",
                notes=f"Retrieved {len(bf_items)} files, {len(dev_items)} critical deviations in {counter.count} queries",
            )
        )

        # 4. Incident Concurrency & Row Locking
        inc_svc = IncidentService()
        with QueryCounter(engine) as counter:
            t0 = time.perf_counter()
            inc = inc_svc.get_incident(db, incident_id)
            updated_inc = inc_svc.transition_status(
                db=db,
                incident_id=incident_id,
                new_status="contained",
                notes="Contained suspicious process tree",
                containment_summary="Host isolated",
            )
            elapsed = (time.perf_counter() - t0) * 1000

        results.append(
            BenchmarkResult(
                category="Incidents",
                benchmark_name="Incident Transition & Locking",
                target_operation="get_incident + transition_status(for_update=True)",
                dataset_scale=scale,
                total_records=entities["total_incidents"],
                execution_time_ms=round(elapsed, 2),
                query_count=counter.count,
                sla_threshold_ms=200.0,
                status="PASS" if elapsed < 200.0 and counter.count <= 6 else "FAIL",
                notes=f"Eager load skipped on status update with row lock in {counter.count} queries",
            )
        )

        # 5. Entity Graph 1-Hop Expansion
        graph_svc = EntityGraphService()
        with QueryCounter(engine) as counter:
            t0 = time.perf_counter()
            graph = graph_svc.build_initial_graph(db, host_id=host_id, max_nodes=50)
            elapsed = (time.perf_counter() - t0) * 1000

        results.append(
            BenchmarkResult(
                category="Graph Expansion",
                benchmark_name="Entity Graph 1-Hop Expansion",
                target_operation="build_initial_graph(max_nodes=50)",
                dataset_scale=scale,
                total_records=len(graph.nodes) + len(graph.edges),
                execution_time_ms=round(elapsed, 2),
                query_count=counter.count,
                sla_threshold_ms=300.0,
                status="PASS" if elapsed < 300.0 else "FAIL",
                notes=f"Generated {len(graph.nodes)} nodes, {len(graph.edges)} edges in {round(elapsed, 2)}ms",
            )
        )

        # 6. Advanced Forensic Multi-Entity Search
        search_svc = AdvancedSearchService()
        criteria = SearchFilter(
            host_id=host_id,
            query="service",
            entity_types=["processes", "events", "incidents"],
            limit=20,
            offset=0,
        )
        with QueryCounter(engine) as counter:
            t0 = time.perf_counter()
            search_res = search_svc.execute_search(db, criteria)
            elapsed = (time.perf_counter() - t0) * 1000

        results.append(
            BenchmarkResult(
                category="Forensic Search",
                benchmark_name="Multi-Entity Full Search",
                target_operation="execute_search(query='service', limit=20)",
                dataset_scale=scale,
                total_records=search_res.total,
                execution_time_ms=round(elapsed, 2),
                query_count=counter.count,
                sla_threshold_ms=300.0,
                status="PASS" if elapsed < 300.0 else "FAIL",
                notes=f"Found {search_res.total} matches across 3 entity types in {round(elapsed, 2)}ms",
            )
        )

        # 7. Forensic Optimized Database Views
        views_to_test = [
            ("view_active_detections", "SELECT COUNT(*) FROM view_active_detections WHERE host_id = :hid"),
            ("view_incident_summary", "SELECT COUNT(*) FROM view_incident_summary WHERE host_id = :hid"),
            ("view_fim_deviation_details", "SELECT COUNT(*) FROM view_fim_deviation_details WHERE host_id = :hid"),
            ("view_process_lineage", "SELECT COUNT(*) FROM view_process_lineage WHERE host_id = :hid"),
            ("view_session_overview", "SELECT COUNT(*) FROM view_session_overview WHERE host_id = :hid"),
        ]
        with QueryCounter(engine) as counter:
            t0 = time.perf_counter()
            view_counts = {}
            for v_name, v_sql in views_to_test:
                val = db.execute(text(v_sql), {"hid": host_id if engine.dialect.name == "postgresql" else str(host_id).replace("-", "")}).scalar()
                view_counts[v_name] = val
            elapsed = (time.perf_counter() - t0) * 1000

        results.append(
            BenchmarkResult(
                category="Database Views",
                benchmark_name="5 Forensic Views Aggregation",
                target_operation="SELECT FROM 5 forensic views",
                dataset_scale=scale,
                total_records=sum(view_counts.values()),
                execution_time_ms=round(elapsed, 2),
                query_count=counter.count,
                sla_threshold_ms=250.0,
                status="PASS" if elapsed < 250.0 else "FAIL",
                notes=f"Queried all 5 forensic views in {round(elapsed, 2)}ms ({counter.count} queries)",
            )
        )

    finally:
        db.close()
        if trans.is_active:
            trans.rollback()
        conn.close()

    return results


def format_markdown_table(results: list[BenchmarkResult]) -> str:
    """Format benchmark metrics into a GitHub-style markdown table."""
    headers = [
        "Category",
        "Benchmark / Operation",
        "Scale",
        "Records",
        "Time (ms)",
        "Queries",
        "SLA Threshold",
        "Status",
        "Notes",
    ]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for r in results:
        lines.append(
            f"| {r.category} | `{r.benchmark_name}` | {r.dataset_scale} | "
            f"{r.total_records:,} | {r.execution_time_ms:.2f}ms | {r.query_count} | "
            f"<{r.sla_threshold_ms:.0f}ms | **{r.status}** | {r.notes} |"
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Forensic Database Performance Benchmark Utility")
    parser.add_argument(
        "--scale",
        choices=["small", "medium", "large"],
        default="small",
        help="Dataset scale profile (default: small)",
    )
    parser.add_argument(
        "--db-url",
        default=None,
        help="Target database URL (defaults to PostgreSQL settings.database_url or in-memory SQLite)",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    args = parser.parse_args()

    db_url = args.db_url or settings.database_url
    try:
        engine = sa.create_engine(db_url)
        with engine.connect() as c:
            c.execute(text("SELECT 1"))
    except Exception as exc:
        print(f"Warning: Database at {db_url} unavailable ({exc}); falling back to SQLite in-memory.", file=sys.stderr)
        engine = sa.create_engine("sqlite:///:memory:")

    # Ensure schema exists on SQLite if in-memory
    if engine.dialect.name == "sqlite":
        Base.metadata.create_all(engine)
        # Create views on SQLite
        with engine.begin() as conn:
            conn.execute(
                text("""
                CREATE VIEW IF NOT EXISTS view_active_detections AS
                SELECT d.id AS detection_id, d.rule_id, dr.rule_id AS rule_identifier,
                       dr.name AS rule_name, dr.category, d.severity, d.title,
                       d.description, d.host_id, h.hostname, h.ip_address, d.status,
                       d.timestamp, d.event_id, d.process_id, d.session_id,
                       d.fim_deviation_id, d.dedup_hash, d.acknowledged_at,
                       d.acknowledged_by_id, d.created_at
                FROM detections d
                JOIN detection_rules dr ON d.rule_id = dr.id
                JOIN hosts h ON d.host_id = h.id
                WHERE d.status IN ('open', 'investigating');
            """)
            )
            conn.execute(
                text("""
                CREATE VIEW IF NOT EXISTS view_incident_summary AS
                SELECT i.id AS incident_id, i.title, i.severity, i.status, i.category,
                       i.host_id, h.hostname, i.assigned_to_id, u.username AS assigned_to_username,
                       i.created_by_id, i.first_observed_at, i.last_observed_at,
                       i.contained_at, i.resolved_at, i.closed_at, i.created_at, i.updated_at,
                       (SELECT COUNT(*) FROM incident_evidence ie WHERE ie.incident_id = i.id) AS evidence_count,
                       (SELECT COUNT(*) FROM incident_events iev WHERE iev.incident_id = i.id) AS event_count
                FROM incidents i
                LEFT JOIN hosts h ON i.host_id = h.id
                LEFT JOIN app_users u ON i.assigned_to_id = u.id;
            """)
            )
            conn.execute(
                text("""
                CREATE VIEW IF NOT EXISTS view_fim_deviation_details AS
                SELECT dev.id AS deviation_id, dev.host_id, h.hostname, dev.baseline_id,
                       fb.version AS baseline_version, dev.baseline_file_id, dev.file_path,
                       dev.file_type, dev.deviation_type, dev.severity, dev.is_content_modified,
                       dev.is_metadata_modified, dev.summary, dev.detected_at, dev.detection_id,
                       dev.created_at, bf.hash_sha256 AS expected_hash_sha256,
                       bf.permissions AS expected_permissions,
                       bf.file_size AS expected_file_size
                FROM fim_deviations dev
                JOIN hosts h ON dev.host_id = h.id
                JOIN fim_baselines fb ON dev.baseline_id = fb.id
                LEFT JOIN fim_baseline_files bf ON dev.baseline_file_id = bf.id;
            """)
            )
            conn.execute(
                text("""
                CREATE VIEW IF NOT EXISTS view_process_lineage AS
                SELECT p.id AS process_id, p.host_id, h.hostname, p.pid, p.ppid,
                       p.command, p.executable, p.linux_user_id, u.uid, u.username,
                       p.started_at, p.ended_at, p.created_at,
                       (
                           SELECT par.command FROM processes par
                           WHERE par.host_id = p.host_id
                             AND par.pid = p.ppid
                             AND par.started_at <= p.started_at
                             AND (par.ended_at IS NULL OR par.ended_at >= p.started_at)
                           ORDER BY par.started_at DESC
                           LIMIT 1
                       ) AS parent_command,
                       (
                           SELECT par.executable FROM processes par
                           WHERE par.host_id = p.host_id
                             AND par.pid = p.ppid
                             AND par.started_at <= p.started_at
                             AND (par.ended_at IS NULL OR par.ended_at >= p.started_at)
                           ORDER BY par.started_at DESC
                           LIMIT 1
                       ) AS parent_executable
                FROM processes p
                JOIN hosts h ON p.host_id = h.id
                LEFT JOIN linux_users u ON p.linux_user_id = u.id;
            """)
            )
            conn.execute(
                text("""
                CREATE VIEW IF NOT EXISTS view_session_overview AS
                SELECT s.id AS session_id, s.host_id, h.hostname, s.linux_user_id,
                       u.uid, u.username, s.session_type, s.terminal, s.remote_host,
                       s.started_at, s.ended_at, s.created_at
                FROM sessions s
                JOIN hosts h ON s.host_id = h.id
                LEFT JOIN linux_users u ON s.linux_user_id = u.id;
            """)
            )

    results = run_benchmarks(engine, scale=args.scale)

    if args.format == "json":
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        print("\n### Forensic Query Performance Benchmarks (Milestone 2.8)\n")
        print(f"**Dialect:** `{engine.dialect.name}` | **Scale Profile:** `{args.scale}`\n")
        print(format_markdown_table(results))
        print()

    engine.dispose()


if __name__ == "__main__":
    main()
