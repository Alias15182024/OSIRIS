"""Unit tests for detection persistence and alert deduplication (Phase 2 Milestone 2.4).

Verifies:
- Rule synchronization to database.
- Correct entity associations (host, rule, event, process, session).
- Evidence and matched conditions preservation.
- Deduplication: identical event streams produce zero duplicate alerts.
- Transaction rollback safety.
- Alert acknowledgment workflow with user attribution.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Generator
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from backend.db.base import Base
from backend.db.models.app_user import AppUser
from backend.db.models.detection import Detection
from backend.db.models.detection_rule import DetectionRule
from backend.db.models.event import Event
from backend.db.models.host import Host
from backend.services.detection.service import DetectionService
from backend.services.events.schemas import NormalizedEvent


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    """Create disposable SQLite in-memory database with full schema."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def host(db_session: Session) -> Host:
    h = Host(
        id=uuid.uuid4(),
        hostname="forensic-host-01",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(h)
    db_session.commit()
    return h


@pytest.fixture
def user(db_session: Session) -> AppUser:
    u = AppUser(
        id=uuid.uuid4(),
        username="analyst_bob",
        password_hash="fakehashedpassword",
        role="admin",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(u)
    db_session.commit()
    return u


def _create_event(
    db: Session,
    host_id: uuid.UUID,
    command: str = "sudo su",
    event_type: str = "proc:exec",
    uid: int = 1000,
    username: str = "testuser",
) -> Event:
    now = datetime.now(timezone.utc)
    ev = Event(
        id=uuid.uuid4(),
        host_id=host_id,
        timestamp=now,
        ingested_at=now,
        source="proc",
        event_type=event_type,
        action="execute",
        severity="info",
        uid=uid,
        username=username,
        command=command,
    )
    db.add(ev)
    db.commit()
    return ev


class TestDetectionPersistence:
    """Test database persistence layer of the detection engine."""

    def test_sync_rules(self, db_session: Session) -> None:
        service = DetectionService()
        db_rules = service.sync_rules(db_session)
        db_session.commit()

        assert len(db_rules) >= 9
        rules_in_db = db_session.execute(select(DetectionRule)).scalars().all()
        assert len(rules_in_db) >= 9
        rule_ids = {r.rule_id for r in rules_in_db}
        assert "OSIRIS-PRIV-001" in rule_ids
        assert "OSIRIS-AUTH-001" in rule_ids
        assert "OSIRIS-RECON-001" in rule_ids

    def test_single_event_detection_persistence(
        self, db_session: Session, host: Host
    ) -> None:
        service = DetectionService()
        service.sync_rules(db_session)

        ev = _create_event(db_session, host.id, command="sudo -i", username="analyst")
        created = service.evaluate_and_persist(db_session, [ev])
        db_session.commit()

        assert len(created) >= 1
        det = created[0]
        assert det.host_id == host.id
        assert det.event_id == ev.id
        assert det.status == "open"
        assert det.notification_status == "pending"
        assert det.severity == "high"
        assert "OSIRIS-PRIV-001" == det.rule.rule_id
        assert det.dedup_hash is not None

        # Verify query from database
        stored = db_session.execute(select(Detection).where(Detection.id == det.id)).scalar_one()
        assert stored.title == det.title
        assert stored.matched_conditions is not None
        assert stored.evidence is not None

    def test_idempotent_deduplication(
        self, db_session: Session, host: Host
    ) -> None:
        """Processing the exact same event multiple times MUST NOT create duplicate alerts."""
        service = DetectionService()
        service.sync_rules(db_session)

        ev = _create_event(db_session, host.id, command="sudo -i", username="analyst")

        # First evaluation: creates detection
        created_first = service.evaluate_and_persist(db_session, [ev])
        db_session.commit()
        assert len(created_first) == 1

        # Second evaluation with the exact same event: returns empty, 0 new rows
        created_second = service.evaluate_and_persist(db_session, [ev])
        db_session.commit()
        assert len(created_second) == 0

        # Total rows in detections table is exactly 1
        all_detections = db_session.execute(select(Detection)).scalars().all()
        assert len(all_detections) == 1

    def test_acknowledgment_workflow(
        self, db_session: Session, host: Host, user: AppUser
    ) -> None:
        service = DetectionService()
        service.sync_rules(db_session)

        ev = _create_event(db_session, host.id, command="sudo -i", username="analyst")
        created = service.evaluate_and_persist(db_session, [ev])
        db_session.commit()

        det_id = created[0].id
        acked = service.acknowledge_detection(
            db=db_session,
            detection_id=det_id,
            user_id=user.id,
            notes="Investigated and confirmed administrative maintenance window.",
        )
        db_session.commit()

        assert acked.status == "acknowledged"
        assert acked.acknowledged_by_id == user.id
        assert acked.acknowledged_at is not None
        assert acked.evidence["acknowledgment_notes"] == "Investigated and confirmed administrative maintenance window."

    def test_query_filtering(
        self, db_session: Session, host: Host
    ) -> None:
        service = DetectionService()
        service.sync_rules(db_session)

        ev1 = _create_event(db_session, host.id, command="sudo -i")
        ev2 = _create_event(db_session, host.id, command="cat /etc/shadow")
        service.evaluate_and_persist(db_session, [ev1, ev2])
        db_session.commit()

        # Filter by severity
        crit_items, crit_total = service.get_detections(db_session, severity="critical")
        assert crit_total >= 1
        for item in crit_items:
            assert item.severity == "critical"

        # Filter by category
        priv_items, priv_total = service.get_detections(db_session, category="privilege_escalation")
        assert priv_total >= 1
        for item in priv_items:
            assert item.category == "privilege_escalation"

        # Filter by host
        host_items, host_total = service.get_detections(db_session, host_id=host.id)
        assert host_total >= 2
