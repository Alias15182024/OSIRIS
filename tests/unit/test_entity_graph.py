"""Unit tests for EntityGraphService (Phase 2 Milestone 2.7)."""

from __future__ import annotations

from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy.orm import Session

from backend.db.base import utcnow
from backend.db.models.detection import Detection
from backend.db.models.detection_rule import DetectionRule
from backend.db.models.event import Event
from backend.db.models.file import File
from backend.db.models.fim_baseline import FimBaseline
from backend.db.models.fim_deviation import FimDeviation
from backend.db.models.host import Host
from backend.db.models.incident import Incident
from backend.db.models.incident_evidence import IncidentEvidence
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession
from backend.services.workspace import EntityGraphService


@pytest.fixture
def graph_service() -> EntityGraphService:
    return EntityGraphService()


@pytest.fixture
def host_a(contract_db_session: Session) -> Host:
    host = Host(hostname="victim-host-a", ip_address="192.168.1.50")
    contract_db_session.add(host)
    contract_db_session.flush()
    return host


@pytest.fixture
def host_b(contract_db_session: Session) -> Host:
    host = Host(hostname="foreign-host-b", ip_address="10.0.0.99")
    contract_db_session.add(host)
    contract_db_session.flush()
    return host


@pytest.fixture
def user_a(contract_db_session: Session, host_a: Host) -> LinuxUser:
    user = LinuxUser(
        host_id=host_a.id,
        uid=1000,
        username="alice",
        first_seen_at=utcnow(),
    )
    contract_db_session.add(user)
    contract_db_session.flush()
    return user


@pytest.fixture
def session_a(contract_db_session: Session, host_a: Host, user_a: LinuxUser) -> UserSession:
    sess = UserSession(
        host_id=host_a.id,
        linux_user_id=user_a.id,
        session_type="ssh",
        terminal="pts/1",
        remote_host="192.168.1.200",
        started_at=datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc),
        ended_at=datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc),
    )
    contract_db_session.add(sess)
    contract_db_session.flush()
    return sess


class TestEntityGraph:
    """Validate graph creation, expansion, isolation, provenance, and pivoting."""

    def test_build_initial_host_graph(
        self,
        contract_db_session: Session,
        graph_service: EntityGraphService,
        host_a: Host,
        user_a: LinuxUser,
        session_a: UserSession,
    ) -> None:
        graph = graph_service.build_initial_graph(contract_db_session, host_id=host_a.id, max_nodes=50)

        assert graph.total_nodes >= 3
        node_ids = {n.id for n in graph.nodes}
        assert f"host:{host_a.id}" in node_ids
        assert f"user:{user_a.id}" in node_ids
        assert f"session:{session_a.id}" in node_ids

        # Verify edges exist with provenance
        assert graph.total_edges >= 2
        for edge in graph.edges:
            assert edge.edge_type in ("direct_database", "inferred_correlation")
            assert "source_table" in edge.provenance or "rule" in edge.provenance

    def test_process_expansion_hierarchy_and_events(
        self,
        contract_db_session: Session,
        graph_service: EntityGraphService,
        host_a: Host,
        user_a: LinuxUser,
        session_a: UserSession,
    ) -> None:
        t_base = datetime(2026, 10, 31, 10, 15, 0, tzinfo=timezone.utc)

        # Parent process (bash)
        parent_proc = Process(
            host_id=host_a.id,
            pid=2000,
            ppid=1,
            command="/bin/bash",
            linux_user_id=user_a.id,
            started_at=t_base,
        )
        contract_db_session.add(parent_proc)
        contract_db_session.flush()

        # Child process (python)
        child_proc = Process(
            host_id=host_a.id,
            pid=2005,
            ppid=2000,
            command="python3 -m http.server",
            linux_user_id=user_a.id,
            started_at=datetime(2026, 10, 31, 10, 20, 0, tzinfo=timezone.utc),
        )
        contract_db_session.add(child_proc)
        contract_db_session.flush()

        # Event referencing child process
        evt = Event(
            host_id=host_a.id,
            process_id=child_proc.id,
            timestamp=datetime(2026, 10, 31, 10, 21, 0, tzinfo=timezone.utc),
            source="process_collector",
            event_type="network_listen",
            action="listen",
            severity="info",
            command="python3 -m http.server",
        )
        contract_db_session.add(evt)
        contract_db_session.flush()

        # Expand child process
        subgraph = graph_service.expand_node(
            db=contract_db_session,
            node_type="process",
            node_id=str(child_proc.id),
            host_id=host_a.id,
            depth=1,
            max_nodes=30,
        )

        node_types = {n.entity_type for n in subgraph.nodes}
        assert "process" in node_types
        assert "host" in node_types
        assert "user" in node_types
        assert "session" in node_types
        assert "event" in node_types

        # Verify parent edge
        edge_rels = {e.relationship for e in subgraph.edges}
        assert "process_spawns_process" in edge_rels
        assert "user_owns_process" in edge_rels
        assert "host_owns_process" in edge_rels
        assert "process_in_session" in edge_rels
        assert "event_references_process" in edge_rels

    def test_fim_deviation_and_detection_expansion(
        self,
        contract_db_session: Session,
        graph_service: EntityGraphService,
        host_a: Host,
    ) -> None:
        # File
        f = File(
            host_id=host_a.id,
            path="/etc/pam.d/common-auth",
            file_type="file",
            first_seen_at=utcnow(),
        )
        contract_db_session.add(f)
        contract_db_session.flush()

        # FIM Baseline
        baseline = FimBaseline(
            host_id=host_a.id,
            path_scope=["/etc"],
            status="completed",
            version=1,
        )
        contract_db_session.add(baseline)
        contract_db_session.flush()

        # FIM Deviation
        dev = FimDeviation(
            host_id=host_a.id,
            baseline_id=baseline.id,
            file_path="/etc/pam.d/common-auth",
            deviation_type="modified_file",
            severity="critical",
            detected_at=utcnow(),
        )
        contract_db_session.add(dev)
        contract_db_session.flush()

        # Detection linked to deviation
        rule_fim = DetectionRule(
            id=uuid.uuid4(),
            rule_id="OSIRIS-FIM-001",
            name="Protected Configuration File Tampering",
            severity="critical",
            category="file_integrity",
            enabled=True,
            version=1,
            rule_type="single_event",
            conditions={},
        )
        contract_db_session.add(rule_fim)
        contract_db_session.flush()

        det = Detection(
            host_id=host_a.id,
            rule_id=rule_fim.id,
            rule_version=1,
            title="Protected Configuration File Tampering",
            severity="critical",
            category="file_integrity",
            status="open",
            fim_deviation_id=dev.id,
            timestamp=utcnow(),
            matched_conditions={"matched": True},
            evidence={"file": "/etc/pam.d/common-auth"},
        )
        contract_db_session.add(det)
        contract_db_session.flush()

        # Also set deviation.detection_id
        dev.detection_id = det.id
        contract_db_session.flush()

        # Expand detection
        det_graph = graph_service.expand_node(
            db=contract_db_session,
            node_type="detection",
            node_id=str(det.id),
            host_id=host_a.id,
        )
        det_node_ids = {n.id for n in det_graph.nodes}
        assert f"detection:{det.id}" in det_node_ids
        assert f"fim_deviation:{dev.id}" in det_node_ids
        assert f"host:{host_a.id}" in det_node_ids

        # Expand deviation
        dev_graph = graph_service.expand_node(
            db=contract_db_session,
            node_type="fim_deviation",
            node_id=str(dev.id),
            host_id=host_a.id,
        )
        dev_node_ids = {n.id for n in dev_graph.nodes}
        assert f"fim_deviation:{dev.id}" in dev_node_ids
        assert f"detection:{det.id}" in dev_node_ids
        assert f"file:{f.id}" in dev_node_ids

    def test_incident_evidence_expansion(
        self,
        contract_db_session: Session,
        graph_service: EntityGraphService,
        host_a: Host,
    ) -> None:
        inc = Incident(
            title="Root Compromise Incident",
            severity="critical",
            status="investigating",
            host_id=host_a.id,
        )
        contract_db_session.add(inc)
        contract_db_session.flush()

        rule_priv = DetectionRule(
            id=uuid.uuid4(),
            rule_id="OSIRIS-PRIV-001",
            name="Sudo Breakout Detected",
            severity="high",
            category="privilege_escalation",
            enabled=True,
            version=1,
            rule_type="single_event",
            conditions={},
        )
        contract_db_session.add(rule_priv)
        contract_db_session.flush()

        det = Detection(
            host_id=host_a.id,
            rule_id=rule_priv.id,
            rule_version=1,
            title="Sudo Breakout Detected",
            severity="high",
            category="privilege_escalation",
            timestamp=utcnow(),
            matched_conditions={"matched": True},
            evidence={"cmd": "sudo -i"},
        )
        contract_db_session.add(det)
        contract_db_session.flush()

        ev = IncidentEvidence(
            incident_id=inc.id,
            evidence_type="detection",
            source_id=str(det.id),
            title="Trigger Detection",
            provenance={"subsystem": "detection_engine"},
            detection_id=det.id,
        )
        contract_db_session.add(ev)
        contract_db_session.flush()

        inc_graph = graph_service.expand_node(
            db=contract_db_session,
            node_type="incident",
            node_id=str(inc.id),
            host_id=host_a.id,
        )
        node_ids = {n.id for n in inc_graph.nodes}
        assert f"incident:{inc.id}" in node_ids
        assert f"detection:{det.id}" in node_ids
        assert f"host:{host_a.id}" in node_ids

        rels = {e.relationship for e in inc_graph.edges}
        assert "incident_contains_evidence" in rels
        assert "incident_on_host" in rels

    def test_cross_host_isolation_enforced(
        self,
        contract_db_session: Session,
        graph_service: EntityGraphService,
        host_a: Host,
        host_b: Host,
    ) -> None:
        """Entities on Host B must never appear in Host A's graph."""
        user_b = LinuxUser(host_id=host_b.id, uid=1001, username="bob", first_seen_at=utcnow())
        contract_db_session.add(user_b)
        contract_db_session.flush()

        # Expanding Host A
        graph_a = graph_service.build_initial_graph(contract_db_session, host_id=host_a.id)
        node_ids = {n.id for n in graph_a.nodes}
        assert f"user:{user_b.id}" not in node_ids
        assert f"host:{host_b.id}" not in node_ids

    def test_bounded_expansion_limits(
        self,
        contract_db_session: Session,
        graph_service: EntityGraphService,
        host_a: Host,
    ) -> None:
        """Graph expansion stops when max_nodes limit is reached."""
        # Create 15 processes
        for i in range(15):
            p = Process(
                host_id=host_a.id,
                pid=3000 + i,
                command=f"worker_{i}",
                started_at=utcnow(),
            )
            contract_db_session.add(p)
        contract_db_session.flush()

        # Limit to 6 nodes max
        graph = graph_service.build_initial_graph(contract_db_session, host_id=host_a.id, max_nodes=6)
        assert graph.total_nodes <= 6
        assert graph.max_limit_reached is True
        assert graph.truncated is True

    def test_entity_pivoting_api(
        self,
        contract_db_session: Session,
        graph_service: EntityGraphService,
        host_a: Host,
    ) -> None:
        proc = Process(
            host_id=host_a.id,
            pid=4000,
            ppid=1,
            command="apt-get install malware",
            started_at=utcnow(),
        )
        contract_db_session.add(proc)
        contract_db_session.flush()

        pivot = graph_service.get_entity_pivots(
            contract_db_session, entity_type="process", entity_id=str(proc.id)
        )
        assert pivot.entity_type == "process"
        assert pivot.entity_id == str(proc.id)
        assert pivot.host_id == host_a.id
        assert len(pivot.breadcrumbs) >= 1

    def test_snapshot_expansion_and_pivot(
        self,
        contract_db_session: Session,
        graph_service: EntityGraphService,
        host_a: Host,
    ) -> None:
        t_now = utcnow()
        snap = Snapshot(
            host_id=host_a.id,
            timestamp=t_now,
            snapshot_type="system_state",
            data={},
        )
        proc = Process(
            host_id=host_a.id,
            pid=5555,
            command="/usr/sbin/sshd -D",
            started_at=t_now,
        )
        contract_db_session.add_all([snap, proc])
        contract_db_session.flush()

        graph = graph_service.expand_node(
            db=contract_db_session,
            node_type="snapshot",
            node_id=str(snap.id),
            host_id=host_a.id,
        )
        node_ids = {n.id for n in graph.nodes}
        assert f"snapshot:{snap.id}" in node_ids
        assert f"host:{host_a.id}" in node_ids

        pivot = graph_service.get_entity_pivots(
            contract_db_session,
            entity_type="snapshot",
            entity_id=str(snap.id),
        )
        assert pivot.entity_type == "snapshot"
        assert pivot.host_id == host_a.id
        assert "host" in pivot.related_entities
        assert "captured_processes" in pivot.related_entities

    def test_pid_reuse_protection_for_parent_and_child_processes(
        self,
        contract_db_session: Session,
        graph_service: EntityGraphService,
        host_a: Host,
    ) -> None:
        """Processes from earlier terminated lifetimes or post-termination births must not be misattributed."""
        from datetime import datetime, timezone
        t1 = datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 10, 31, 10, 5, 0, tzinfo=timezone.utc)
        t3 = datetime(2026, 10, 31, 11, 0, 0, tzinfo=timezone.utc)
        t4 = datetime(2026, 10, 31, 11, 1, 0, tzinfo=timezone.utc)

        # 1. Child PID reuse scenario:
        # P1 ran 10:00 - 10:05 with PID 1234
        p1 = Process(
            host_id=host_a.id,
            pid=1234,
            command="terminated_early_service",
            started_at=t1,
            ended_at=t2,
        )
        # P2 ran at 11:00 with reused PID 1234
        p2 = Process(
            host_id=host_a.id,
            pid=1234,
            command="reused_pid_service",
            started_at=t3,
        )
        # P3 spawned at 11:01 with PPID 1234 (child of P2, NOT P1!)
        p3 = Process(
            host_id=host_a.id,
            pid=7777,
            ppid=1234,
            command="child_of_p2",
            started_at=t4,
        )
        contract_db_session.add_all([p1, p2, p3])
        contract_db_session.flush()

        # Expanding P1 must NOT attach P3 as a child
        g1 = graph_service.expand_node(contract_db_session, node_type="process", node_id=str(p1.id))
        g1_node_ids = {n.id for n in g1.nodes}
        assert f"process:{p3.id}" not in g1_node_ids

        # Pivoting P1 must NOT list P3 in child_processes
        piv1 = graph_service.get_entity_pivots(contract_db_session, entity_type="process", entity_id=str(p1.id))
        child_ids = [c["id"] for c in piv1.related_entities.get("child_processes", [])]
        assert str(p3.id) not in child_ids

        # 2. Parent PID reuse scenario:
        # P_dead ran 09:00 - 09:05 with PID 8888
        p_dead = Process(
            host_id=host_a.id,
            pid=8888,
            command="dead_parent_process",
            started_at=datetime(2026, 10, 31, 9, 0, 0, tzinfo=timezone.utc),
            ended_at=datetime(2026, 10, 31, 9, 5, 0, tzinfo=timezone.utc),
        )
        # P_orphan started at 10:00 with PPID 8888 (parent already dead before orphan started)
        p_orphan = Process(
            host_id=host_a.id,
            pid=9999,
            ppid=8888,
            command="orphan_or_new_parent_proc",
            started_at=t1,
        )
        contract_db_session.add_all([p_dead, p_orphan])
        contract_db_session.flush()

        # Expanding P_orphan must NOT attach P_dead as parent
        g2 = graph_service.expand_node(contract_db_session, node_type="process", node_id=str(p_orphan.id))
        g2_node_ids = {n.id for n in g2.nodes}
        assert f"process:{p_dead.id}" not in g2_node_ids

        # Pivoting P_orphan must NOT list P_dead as parent_process
        piv2 = graph_service.get_entity_pivots(contract_db_session, entity_type="process", entity_id=str(p_orphan.id))
        parent_ids = [p["id"] for p in piv2.related_entities.get("parent_process", [])]
        assert str(p_dead.id) not in parent_ids

    def test_dangling_edges_pruned_on_max_nodes_boundary(
        self,
        contract_db_session: Session,
        graph_service: EntityGraphService,
        host_a: Host,
    ) -> None:
        """When max_nodes truncates node expansion, edges pointing to dropped nodes must be pruned."""
        proc = Process(
            host_id=host_a.id,
            pid=4321,
            command="/usr/bin/python3 -m worker",
            started_at=utcnow(),
        )
        contract_db_session.add(proc)
        contract_db_session.flush()

        # Expand with max_nodes=1: only the root process node is preserved; host node is truncated
        graph = graph_service.expand_node(
            db=contract_db_session,
            node_type="process",
            node_id=str(proc.id),
            max_nodes=1,
        )
        assert len(graph.nodes) == 1
        node_id_set = {n.id for n in graph.nodes}
        # All edges must connect to nodes present in graph
        for e in graph.edges:
            assert e.source in node_id_set
            assert e.target in node_id_set


