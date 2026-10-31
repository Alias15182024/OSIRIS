"""Forensic database query performance and N+1 elimination benchmarks (Phase 2 Milestone 2.8).

Validates:
- Multi-source timeline queries and avoidance of N+1 query patterns.
- Declarative detection queries and deduplication lookups.
- FIM baseline file inventory and deviation queries.
- Incident detail retrieval and concurrency handling.
- Investigation workspace graph expansion.
- Advanced forensic multi-entity search.
- Session-process correlation efficiency.
- Snapshot listing and process retrieval.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Generator

import pytest
import sqlalchemy as sa
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from backend.api.schemas.search import SearchFilter
from backend.db.base import Base, new_uuid, utcnow
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
from backend.db.models.incident_event import IncidentEvent
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
    """SQLAlchemy query execution counter."""

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


@pytest.fixture
def synthetic_forensic_db(db_engine: sa.Engine) -> Generator[tuple[Session, dict[str, uuid.UUID]], None, None]:
    """Populate an isolated database with synthetic forensic dataset for benchmarking."""
    connection = db_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")

    base_time = datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc)
    host_id = new_uuid()
    host = Host(
        id=host_id,
        hostname="benchmark-srv",
        os_info="Linux 6.8.0-benchmark",
        ip_address="10.0.0.100",
        created_at=base_time,
    )
    session.add(host)

    # 1. Users
    user_root = LinuxUser(id=new_uuid(), host_id=host_id, uid=0, username="root", first_seen_at=base_time)
    user_alice = LinuxUser(id=new_uuid(), host_id=host_id, uid=1001, username="alice", first_seen_at=base_time)
    app_admin = AppUser(id=new_uuid(), username="admin_bench", password_hash="hash", role="admin")
    session.add_all([user_root, user_alice, app_admin])
    session.flush()

    # 2. Processes (100 processes)
    procs = []
    for i in range(100):
        p_ts = base_time + timedelta(seconds=i * 10)
        p = Process(
            id=new_uuid(),
            host_id=host_id,
            pid=1000 + i,
            ppid=1000 if i > 0 else 1,
            command=f"/usr/bin/service_{i} --worker",
            executable=f"/usr/bin/service_{i}",
            linux_user_id=user_alice.id if i % 2 == 0 else user_root.id,
            started_at=p_ts,
            ended_at=p_ts + timedelta(seconds=600) if i % 3 == 0 else None,
        )
        procs.append(p)
    session.add_all(procs)
    session.flush()

    # 3. Sessions (10 sessions)
    sessions = []
    for i in range(10):
        s_ts = base_time + timedelta(minutes=i * 15)
        s = UserSession(
            id=new_uuid(),
            host_id=host_id,
            linux_user_id=user_alice.id if i % 2 == 0 else user_root.id,
            session_type="ssh",
            terminal=f"pts/{i}",
            remote_host=f"192.168.1.{10 + i}",
            started_at=s_ts,
            ended_at=s_ts + timedelta(minutes=60) if i < 8 else None,
        )
        sessions.append(s)
    session.add_all(sessions)
    session.flush()

    # 3.5. Files (50 observed files)
    bench_files = []
    for i in range(50):
        f = File(
            id=new_uuid(),
            host_id=host_id,
            path=f"/etc/config/file_{i:03d}.conf",
            inode=100000 + i,
            file_type="file",
            first_seen_at=base_time,
            created_at=base_time,
        )
        bench_files.append(f)
    session.add_all(bench_files)
    session.flush()

    # 4. Events (200 heterogeneous events including processes, filesystem, and syslog)
    events = []
    for i in range(200):
        e_ts = base_time + timedelta(seconds=i * 15)
        p = procs[i % len(procs)]
        source_type = "process" if i % 3 == 0 else ("fs" if i % 3 == 1 else "syslog")
        ev_type = "process.exec" if i % 3 == 0 else ("file.modify" if i % 3 == 1 else "auth.login")
        action = "execute" if i % 3 == 0 else ("write" if i % 3 == 1 else "login")
        obj_path = f"/etc/config/file_{i % 50:03d}.conf" if source_type == "fs" else None
        proc_id_val = p.id if i % 4 != 0 else None
        e = Event(
            id=new_uuid(),
            host_id=host_id,
            process_id=proc_id_val,
            timestamp=e_ts,
            source=source_type,
            event_type=ev_type,
            action=action,
            severity="info" if i % 4 != 0 else "high",
            uid=p.linux_user.uid if p.linux_user else 1001,
            username=p.linux_user.username if p.linux_user else "alice",
            pid=p.pid,
            ppid=p.ppid,
            command=p.command,
            object_type="file" if source_type == "fs" else None,
            object_path=obj_path,
        )
        events.append(e)
    session.add_all(events)
    session.flush()

    # 5. Detection Rule and Detections (30 detections)
    rule = DetectionRule(
        id=new_uuid(),
        rule_id="BENCH-RULE-001",
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
    for i in range(30):
        d_ts = base_time + timedelta(minutes=i * 5)
        d = Detection(
            id=new_uuid(),
            rule_id=rule.id,
            rule_version=1,
            host_id=host_id,
            event_id=events[i].id,
            process_id=procs[i].id,
            timestamp=d_ts,
            severity="high",
            title=f"Security Alert #{i}",
            description="Detected anomalous activity",
            category="execution",
            status="open" if i % 2 == 0 else "resolved",
            notification_status="sent",
            matched_conditions={},
            evidence={},
            dedup_hash=f"bench_hash_{i:04d}",
        )
        dets.append(d)
    session.add_all(dets)
    session.flush()

    # 6. FIM Baseline and Files (100 baseline files)
    baseline = FimBaseline(
        id=new_uuid(),
        host_id=host_id,
        version=1,
        status="completed",
        path_scope=["/etc", "/bin"],
        total_files=100,
        total_bytes=1048576,
        baseline_at=base_time,
    )
    session.add(baseline)
    session.flush()

    bf_list = []
    for i in range(100):
        bf = FimBaselineFile(
            id=new_uuid(),
            baseline_id=baseline.id,
            host_id=host_id,
            file_path=f"/etc/config/file_{i:03d}.conf",
            file_name=f"file_{i:03d}.conf",
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

    # 7. FIM Deviations (20 deviations)
    devs = []
    for i in range(20):
        dev = FimDeviation(
            id=new_uuid(),
            host_id=host_id,
            baseline_id=baseline.id,
            baseline_file_id=bf_list[i].id,
            file_path=bf_list[i].file_path,
            deviation_type="modified_file",
            severity="critical" if i < 5 else "medium",
            detected_at=base_time + timedelta(minutes=i * 10),
            summary=f"File {bf_list[i].file_path} checksum mismatch",
        )
        devs.append(dev)
    session.add_all(devs)
    session.flush()

    # 8. Incident and Evidence (10 incidents)
    incidents = []
    for i in range(10):
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

    # Add evidence to first incident
    for i in range(5):
        ie = IncidentEvidence(
            id=new_uuid(),
            incident_id=incidents[0].id,
            evidence_type="detection",
            source_id=str(dets[i].id),
            title=f"Correlated Alert {i}",
            provenance={"rule": "BENCH-RULE-001"},
            detection_id=dets[i].id,
        )
        session.add(ie)

    # 9. Workspace, Tag, Association, Annotation
    tag = EvidenceTag(id=new_uuid(), name="apt-actor", category="threat_actor", color="#ef4444")
    session.add(tag)
    session.flush()

    ws = Workspace(
        id=new_uuid(),
        name="Forensic Analysis WS",
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
        annotation_text="Identified lateral movement artifacts",
    )
    session.add(annot)
    session.flush()

    entities = {
        "host_id": host_id,
        "incident_id": incidents[0].id,
        "user_id": user_alice.id,
        "app_admin_id": app_admin.id,
        "baseline_id": baseline.id,
        "workspace_id": ws.id,
    }

    yield session, entities

    session.close()
    if transaction.is_active:
        transaction.rollback()
    connection.close()


class TestDatabaseOptimizationBenchmarks:
    """Benchmark suite validating query performance and N+1 elimination."""

    def test_timeline_query_efficiency_and_n_plus_one_elimination(
        self, db_engine: sa.Engine, synthetic_forensic_db: tuple[Session, dict[str, uuid.UUID]]
    ) -> None:
        """Verify timeline reconstruction is bounded in queries and executes efficiently."""
        session, entities = synthetic_forensic_db
        host_id = entities["host_id"]

        timeline_service = TimelineService(session=session)

        # Execute timeline query with query counting
        with QueryCounter(db_engine) as counter:
            start_t = time.perf_counter()
            entries, total = timeline_service.reconstruct_timeline(
                host_id=host_id,
                limit=50,
                offset=0,
            )
            elapsed_ms = (time.perf_counter() - start_t) * 1000

        assert total > 0
        assert len(entries) == 50
        # N+1 elimination check:
        # Instead of 50 individual user queries + 50 resource queries + 50 snapshot queries (150+ queries),
        # the entire page must hydrate in bounded queries (<= 15 queries total).
        assert counter.count <= 15
        assert elapsed_ms < 500  # Sub-second execution

    def test_detection_filtering_performance(
        self, db_engine: sa.Engine, synthetic_forensic_db: tuple[Session, dict[str, uuid.UUID]]
    ) -> None:
        """Verify detection listing with host/status composite index."""
        session, entities = synthetic_forensic_db
        host_id = entities["host_id"]

        service = DetectionService()

        with QueryCounter(db_engine) as counter:
            start_t = time.perf_counter()
            items, total = service.get_detections(
                db=session,
                host_id=host_id,
                status="open",
                limit=25,
            )
            elapsed_ms = (time.perf_counter() - start_t) * 1000

        assert total > 0
        assert len(items) <= 25
        # 1 count query + 1 paginated items query = 2 queries exactly
        assert counter.count == 2
        assert elapsed_ms < 200

    def test_fim_inventory_and_deviation_queries(
        self, db_engine: sa.Engine, synthetic_forensic_db: tuple[Session, dict[str, uuid.UUID]]
    ) -> None:
        """Verify FIM baseline files and deviation queries with path/host indexes."""
        session, entities = synthetic_forensic_db
        baseline_id = entities["baseline_id"]
        host_id = entities["host_id"]

        fim_service = FimService()

        with QueryCounter(db_engine) as counter:
            start_t = time.perf_counter()
            files, total_files = fim_service.get_baseline_files(
                db=session,
                baseline_id=baseline_id,
                path_prefix="/etc/config",
                limit=50,
            )
            devs, total_devs = fim_service.get_deviations(
                db=session,
                host_id=host_id,
                severity="critical",
                limit=50,
            )
            elapsed_ms = (time.perf_counter() - start_t) * 1000

        assert total_files == 100
        assert len(files) == 50
        assert total_devs == 5
        assert len(devs) == 5
        assert counter.count == 4  # 2 count queries + 2 data queries
        assert elapsed_ms < 200

    def test_incident_detail_and_concurrency_locking(
        self, db_engine: sa.Engine, synthetic_forensic_db: tuple[Session, dict[str, uuid.UUID]]
    ) -> None:
        """Verify incident retrieval and row-level locking concurrency handling."""
        session, entities = synthetic_forensic_db
        incident_id = entities["incident_id"]

        incident_service = IncidentService()

        with QueryCounter(db_engine) as counter:
            # 1. Fetch incident with relations
            inc = incident_service.get_incident(session, incident_id)
            assert inc is not None
            assert len(inc.evidence) == 5

            # 2. Status transition with row-level locking (eager_load=False)
            updated_inc = incident_service.transition_status(
                db=session,
                incident_id=incident_id,
                new_status="contained",
                notes="Contained suspicious process tree",
                containment_summary="Host isolated",
            )
            assert updated_inc.status == "contained"
            assert updated_inc.contained_at is not None

        # Bounded query count
        assert counter.count <= 6

    def test_workspace_graph_expansion_performance(
        self, db_engine: sa.Engine, synthetic_forensic_db: tuple[Session, dict[str, uuid.UUID]]
    ) -> None:
        """Verify entity graph expansion from host root."""
        session, entities = synthetic_forensic_db
        host_id = entities["host_id"]

        graph_service = EntityGraphService()

        with QueryCounter(db_engine) as counter:
            start_t = time.perf_counter()
            graph = graph_service.build_initial_graph(session, host_id=host_id, max_nodes=50)
            elapsed_ms = (time.perf_counter() - start_t) * 1000

        assert len(graph.nodes) > 0
        assert len(graph.edges) > 0
        assert elapsed_ms < 300

    def test_advanced_forensic_search_performance(
        self, db_engine: sa.Engine, synthetic_forensic_db: tuple[Session, dict[str, uuid.UUID]]
    ) -> None:
        """Verify multi-entity search across forensic records."""
        session, entities = synthetic_forensic_db
        host_id = entities["host_id"]

        search_service = AdvancedSearchService()
        criteria = SearchFilter(
            host_id=host_id,
            query="suspicious",
            entity_types=["processes", "events", "incidents"],
            limit=20,
            offset=0,
        )

        with QueryCounter(db_engine) as counter:
            start_t = time.perf_counter()
            res = search_service.execute_search(session, criteria)
            elapsed_ms = (time.perf_counter() - start_t) * 1000

        assert res.total >= 0
        assert elapsed_ms < 300

    def test_session_process_correlation_performance(
        self, db_engine: sa.Engine, synthetic_forensic_db: tuple[Session, dict[str, uuid.UUID]]
    ) -> None:
        """Verify session-process correlation bounded execution."""
        session, entities = synthetic_forensic_db
        host_id = entities["host_id"]

        sess_service = SessionReconstructionService()

        total, sessions = sess_service.list_sessions(session, host_id=host_id, limit=5)
        assert total > 0

        with QueryCounter(db_engine) as counter:
            start_t = time.perf_counter()
            procs = sess_service.get_session_processes(session, sessions[0].id)
            elapsed_ms = (time.perf_counter() - start_t) * 1000

        assert isinstance(procs, list)
        assert counter.count <= 5
        assert elapsed_ms < 200

    def test_snapshot_active_process_collection(
        self, db_engine: sa.Engine, synthetic_forensic_db: tuple[Session, dict[str, uuid.UUID]]
    ) -> None:
        """Verify active process retrieval with host_id / ended_at index."""
        session, entities = synthetic_forensic_db
        host_id = entities["host_id"]

        snap_service = SnapshotService(session=session)

        with QueryCounter(db_engine) as counter:
            start_t = time.perf_counter()
            active_procs = snap_service._collect_active_processes(host_id)
            elapsed_ms = (time.perf_counter() - start_t) * 1000

        assert len(active_procs) > 0
        assert counter.count == 1
        assert elapsed_ms < 100
