"""Unit tests for Advanced Forensic Search Service (Phase 2 Milestone 2.7)."""

from __future__ import annotations

from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy.orm import Session

from backend.api.schemas.search import SearchFilter
from backend.db.base import utcnow
from backend.db.models.detection import Detection
from backend.db.models.detection_rule import DetectionRule
from backend.db.models.event import Event
from backend.db.models.file import File
from backend.db.models.fim_baseline import FimBaseline
from backend.db.models.fim_deviation import FimDeviation
from backend.db.models.host import Host
from backend.db.models.incident import Incident
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession
from backend.services.workspace import AdvancedSearchService, AnnotationService


@pytest.fixture
def search_service() -> AdvancedSearchService:
    return AdvancedSearchService()


@pytest.fixture
def annotation_service() -> AnnotationService:
    return AnnotationService()


@pytest.fixture
def host_alpha(contract_db_session: Session) -> Host:
    host = Host(hostname="alpha-sensor.corp", ip_address="10.1.1.10", os_info="Linux 5.15")
    contract_db_session.add(host)
    contract_db_session.flush()
    return host


@pytest.fixture
def host_beta(contract_db_session: Session) -> Host:
    host = Host(hostname="beta-server.corp", ip_address="10.2.2.20", os_info="Linux 6.1")
    contract_db_session.add(host)
    contract_db_session.flush()
    return host


@pytest.fixture
def populate_forensic_data(
    contract_db_session: Session,
    host_alpha: Host,
    host_beta: Host,
    annotation_service: AnnotationService,
) -> dict:
    t1 = datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 31, 10, 30, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 10, 31, 11, 0, 0, tzinfo=timezone.utc)

    # Users
    user1 = LinuxUser(host_id=host_alpha.id, uid=1000, username="jdoe", first_seen_at=t1)
    user2 = LinuxUser(host_id=host_alpha.id, uid=0, username="root", first_seen_at=t1)
    contract_db_session.add_all([user1, user2])
    contract_db_session.flush()

    # Processes
    proc1 = Process(
        host_id=host_alpha.id,
        pid=1001,
        command="/usr/bin/python3 -m c2_beacon",
        executable="/usr/bin/python3",
        linux_user_id=user1.id,
        started_at=t1,
    )
    proc2 = Process(
        host_id=host_alpha.id,
        pid=1002,
        command="sudo rm -rf /var/log/audit",
        executable="/usr/bin/sudo",
        linux_user_id=user2.id,
        started_at=t2,
    )
    # Process on Host Beta
    proc_beta = Process(
        host_id=host_beta.id,
        pid=9999,
        command="/usr/bin/python3 secret_script.py",
        executable="/usr/bin/python3",
        started_at=t2,
    )
    contract_db_session.add_all([proc1, proc2, proc_beta])
    contract_db_session.flush()

    # Events
    evt1 = Event(
        host_id=host_alpha.id,
        process_id=proc1.id,
        timestamp=t1,
        source="process_collector",
        event_type="network_connect",
        action="connect",
        severity="high",
        command="/usr/bin/python3 -m c2_beacon",
        uid=1000,
        username="jdoe",
        pid=1001,
    )
    evt2 = Event(
        host_id=host_alpha.id,
        process_id=proc2.id,
        timestamp=t2,
        source="process_collector",
        event_type="file_deletion",
        action="unlink",
        severity="critical",
        command="sudo rm -rf /var/log/audit",
        object_path="/var/log/audit",
        uid=0,
        username="root",
        pid=1002,
    )
    contract_db_session.add_all([evt1, evt2])
    contract_db_session.flush()

    # Sessions
    sess1 = UserSession(
        host_id=host_alpha.id,
        linux_user_id=user1.id,
        session_type="ssh",
        terminal="pts/0",
        remote_host="192.168.100.5",
        started_at=t1,
    )
    contract_db_session.add(sess1)
    contract_db_session.flush()

    # Detection
    rule = DetectionRule(
        id=uuid.uuid4(),
        rule_id="OSIRIS-TEST-001",
        name="Suspicious C2 Beacon",
        severity="high",
        category="c2",
        enabled=True,
        version=1,
        rule_type="single_event",
        conditions={},
    )
    contract_db_session.add(rule)
    contract_db_session.flush()

    det1 = Detection(
        host_id=host_alpha.id,
        rule_id=rule.id,
        rule_version=1,
        title="Outbound C2 Connection",
        severity="high",
        category="c2",
        status="open",
        timestamp=t1,
        matched_conditions={"matched": True},
        evidence={"command": "/usr/bin/python3 -m c2_beacon"},
    )
    contract_db_session.add(det1)
    contract_db_session.flush()

    # FIM
    base = FimBaseline(host_id=host_alpha.id, path_scope=["/etc"], status="completed", version=1)
    contract_db_session.add(base)
    contract_db_session.flush()

    dev1 = FimDeviation(
        host_id=host_alpha.id,
        baseline_id=base.id,
        file_path="/etc/shadow",
        deviation_type="modified_file",
        severity="critical",
        detected_at=t3,
    )
    contract_db_session.add(dev1)
    contract_db_session.flush()

    # Incident
    inc1 = Incident(
        title="C2 Intrusion Alpha",
        description="Active intrusion detected on Alpha",
        severity="critical",
        status="open",
        category="intrusion",
        host_id=host_alpha.id,
        created_at=t1,
    )
    contract_db_session.add(inc1)
    contract_db_session.flush()

    # Files
    f1 = File(
        host_id=host_alpha.id,
        path="/etc/shadow",
        file_type="file",
        first_seen_at=t1,
    )
    contract_db_session.add(f1)
    contract_db_session.flush()

    # Tagging: tag proc1 with 'malware'
    tag = annotation_service.create_tag(contract_db_session, name="malware", category="threat")
    annotation_service.associate_tag(
        contract_db_session, evidence_type="process", evidence_id=str(proc1.id), tag_id=tag.id
    )

    return {
        "proc1": proc1,
        "proc2": proc2,
        "proc_beta": proc_beta,
        "evt1": evt1,
        "evt2": evt2,
        "det1": det1,
        "dev1": dev1,
        "inc1": inc1,
        "tag": tag,
    }


class TestAdvancedSearch:
    """Validate multi-entity searching, filters, pagination, and host isolation."""

    def test_search_by_query_text(
        self,
        contract_db_session: Session,
        search_service: AdvancedSearchService,
        host_alpha: Host,
        populate_forensic_data: dict,
    ) -> None:
        filt = SearchFilter(
            host_id=host_alpha.id,
            query="c2_beacon",
        )
        res = search_service.execute_search(contract_db_session, filt)
        assert res.total >= 2  # process + event + detection
        entity_types = {item.entity_type for item in res.items}
        assert "process" in entity_types
        assert "event" in entity_types

    def test_search_by_tag(
        self,
        contract_db_session: Session,
        search_service: AdvancedSearchService,
        host_alpha: Host,
        populate_forensic_data: dict,
    ) -> None:
        filt = SearchFilter(
            host_id=host_alpha.id,
            tags=["malware"],
        )
        res = search_service.execute_search(contract_db_session, filt)
        assert res.total >= 1
        item = res.items[0]
        assert item.entity_type == "process"
        assert item.entity_id == str(populate_forensic_data["proc1"].id)
        assert "malware" in item.tags

    def test_search_by_command_and_severity(
        self,
        contract_db_session: Session,
        search_service: AdvancedSearchService,
        host_alpha: Host,
        populate_forensic_data: dict,
    ) -> None:
        filt = SearchFilter(
            host_id=host_alpha.id,
            command="sudo rm -rf",
            entity_types=["processes", "events"],
        )
        res = search_service.execute_search(contract_db_session, filt)
        assert res.total >= 2
        for item in res.items:
            assert "sudo rm -rf" in item.title or "sudo rm -rf" in (item.description or "")

    def test_search_by_file_path(
        self,
        contract_db_session: Session,
        search_service: AdvancedSearchService,
        host_alpha: Host,
        populate_forensic_data: dict,
    ) -> None:
        filt = SearchFilter(
            host_id=host_alpha.id,
            file_path="/etc/shadow",
        )
        res = search_service.execute_search(contract_db_session, filt)
        assert res.total >= 1
        types = {i.entity_type for i in res.items}
        assert "file" in types or "fim_deviation" in types

    def test_host_boundary_isolation(
        self,
        contract_db_session: Session,
        search_service: AdvancedSearchService,
        host_alpha: Host,
        host_beta: Host,
        populate_forensic_data: dict,
    ) -> None:
        # Search on Host Alpha for python3
        filt_alpha = SearchFilter(
            host_id=host_alpha.id,
            query="secret_script",
        )
        res_alpha = search_service.execute_search(contract_db_session, filt_alpha)
        assert res_alpha.total == 0

        # Search on Host Beta for secret_script
        filt_beta = SearchFilter(
            host_id=host_beta.id,
            query="secret_script",
        )
        res_beta = search_service.execute_search(contract_db_session, filt_beta)
        assert res_beta.total == 1
        assert res_beta.items[0].host_id == host_beta.id

    def test_time_range_filtering(
        self,
        contract_db_session: Session,
        search_service: AdvancedSearchService,
        host_alpha: Host,
        populate_forensic_data: dict,
    ) -> None:
        # Window covers only t1 (10:00 to 10:15)
        filt = SearchFilter(
            host_id=host_alpha.id,
            start_time=datetime(2026, 10, 31, 9, 50, 0, tzinfo=timezone.utc),
            end_time=datetime(2026, 10, 31, 10, 15, 0, tzinfo=timezone.utc),
            entity_types=["events"],
        )
        res = search_service.execute_search(contract_db_session, filt)
        assert res.total == 1
        assert res.items[0].entity_id == str(populate_forensic_data["evt1"].id)

    def test_pagination_and_sorting(
        self,
        contract_db_session: Session,
        search_service: AdvancedSearchService,
        host_alpha: Host,
        populate_forensic_data: dict,
    ) -> None:
        filt = SearchFilter(
            host_id=host_alpha.id,
            limit=2,
            offset=0,
        )
        res = search_service.execute_search(contract_db_session, filt)
        assert len(res.items) == 2
        assert res.total > 2

        # Second page
        filt2 = SearchFilter(
            host_id=host_alpha.id,
            limit=2,
            offset=2,
        )
        res2 = search_service.execute_search(contract_db_session, filt2)
        assert len(res2.items) >= 1
        # No overlap between page 1 and page 2
        p1_ids = {it.entity_id for it in res.items}
        p2_ids = {it.entity_id for it in res2.items}
        assert p1_ids.isdisjoint(p2_ids)

    def test_empty_search_results(
        self,
        contract_db_session: Session,
        search_service: AdvancedSearchService,
        host_alpha: Host,
        populate_forensic_data: dict,
    ) -> None:
        filt = SearchFilter(
            host_id=host_alpha.id,
            query="nonexistent_string_1234567890",
        )
        res = search_service.execute_search(contract_db_session, filt)
        assert res.total == 0
        assert len(res.items) == 0

    def test_search_snapshots(
        self,
        contract_db_session: Session,
        search_service: AdvancedSearchService,
        host_alpha: Host,
    ) -> None:
        t_snap = datetime(2026, 10, 31, 10, 15, 0, tzinfo=timezone.utc)
        snap = Snapshot(
            host_id=host_alpha.id,
            timestamp=t_snap,
            snapshot_type="memory_dump",
            data={"mem_used_pct": 82.5},
        )
        contract_db_session.add(snap)
        contract_db_session.flush()

        filt = SearchFilter(
            host_id=host_alpha.id,
            query="memory",
            entity_types=["snapshots"],
        )
        res = search_service.execute_search(contract_db_session, filt)
        assert res.total >= 1
        item = next(it for it in res.items if it.entity_id == str(snap.id))
        assert item.entity_type == "snapshot"
        assert "Memory" in item.title
        assert item.host_id == host_alpha.id

    def test_search_or_logic_preserves_host_isolation(
        self,
        contract_db_session: Session,
        search_service: AdvancedSearchService,
        host_alpha: Host,
        host_beta: Host,
        populate_forensic_data: dict,
    ) -> None:
        """OR logic must never bypass the host scoping boundary or leak cross-host data."""
        # Searching on Host Alpha for a string that exists only on Host Beta
        filt = SearchFilter(
            host_id=host_alpha.id,
            query="secret_script",
            logic="or",
            entity_types=["processes"],
        )
        res = search_service.execute_search(contract_db_session, filt)
        # Should NOT return Beta's process and should NOT match all Alpha's processes
        assert res.total == 0

    def test_search_nonexistent_tag_with_or_logic_returns_no_unfiltered_items(
        self,
        contract_db_session: Session,
        search_service: AdvancedSearchService,
        host_alpha: Host,
        populate_forensic_data: dict,
    ) -> None:
        """Filtering by an empty or non-existent tag under OR logic must not return unfiltered rows."""
        filt = SearchFilter(
            host_id=host_alpha.id,
            tags=["nonexistent_threat_tag_9999"],
            logic="or",
            entity_types=["processes"],
        )
        res = search_service.execute_search(contract_db_session, filt)
        assert res.total == 0


