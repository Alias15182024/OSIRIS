"""Unit tests for the OSIRIS Event Processing Layer.

Tests cover validation, normalization, timestamp handling, enrichment,
and the end-to-end processor pipeline.  These tests do NOT require a
database — they test the processing logic in isolation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from backend.services.events.enricher import enrich
from backend.services.events.normalizer import normalize_observation, normalize_timestamp
from backend.services.events.processor import EventProcessor
from backend.services.events.repository import EventRepository
from backend.services.events.schemas import NormalizedEvent, RawObservation, VALID_SEVERITIES
from backend.services.events.validator import validate_raw_observation
from tests.fixtures.event_fixtures import (
    FIXTURE_HOST_ID,
    FIXTURE_PROCESS_ID,
    FIXTURE_TS,
    FIXTURE_TS_IST,
    make_process_start_observation,
    make_process_end_observation,
    make_filesystem_modify_observation,
    make_resource_cpu_observation,
)


# ── Fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def processor() -> EventProcessor:
    return EventProcessor()


# ── 1. Valid observation normalizes successfully ───────────────────

class TestNormalization:

    def test_valid_observation_normalizes(self, processor: EventProcessor):
        obs = make_process_start_observation()
        result = processor.process(obs)
        assert result.success
        assert result.event is not None
        assert result.event.source == "proc"
        assert result.event.event_type == "process.start"
        assert result.event.action == "start"

    def test_all_fixture_types_normalize(self, processor: EventProcessor):
        """All four fixture types produce valid normalized events."""
        fixtures = [
            make_process_start_observation(),
            make_process_end_observation(),
            make_filesystem_modify_observation(),
            make_resource_cpu_observation(),
        ]
        for obs in fixtures:
            result = processor.process(obs)
            assert result.success, f"Failed for {obs.event_type}: {result.errors}"


# ── 2. Event ID generation ────────────────────────────────────────

class TestEventId:

    def test_event_id_is_uuid(self, processor: EventProcessor):
        obs = make_process_start_observation()
        result = processor.process(obs)
        assert result.success
        assert isinstance(result.event.id, uuid.UUID)

    def test_each_event_gets_unique_id(self, processor: EventProcessor):
        obs = make_process_start_observation()
        r1 = processor.process(obs)
        r2 = processor.process(obs)
        assert r1.event.id != r2.event.id


# ── 3-6. Timestamp handling ───────────────────────────────────────

class TestTimestamp:

    def test_utc_timestamp_stays_utc(self):
        result = normalize_timestamp(FIXTURE_TS)
        assert result.tzinfo is not None
        assert result.utcoffset() == timedelta(0)
        assert result == FIXTURE_TS

    def test_non_utc_converts_to_utc(self):
        """IST timestamp converts to the equivalent UTC instant."""
        result = normalize_timestamp(FIXTURE_TS_IST)
        assert result.utcoffset() == timedelta(0)
        # Must represent the same instant
        assert result == FIXTURE_TS

    def test_iso_string_parses_to_utc(self):
        result = normalize_timestamp("2026-01-15T10:30:00+00:00")
        assert result.tzinfo is not None
        assert result == FIXTURE_TS

    def test_iso_string_with_offset(self):
        """ISO string with non-UTC offset converts correctly."""
        result = normalize_timestamp("2026-01-15T16:00:00+05:30")
        assert result == FIXTURE_TS

    def test_naive_timestamp_raises(self):
        naive = datetime(2026, 1, 15, 10, 30, 0)
        with pytest.raises(ValueError, match="timezone-aware"):
            normalize_timestamp(naive)

    def test_none_timestamp_raises(self):
        with pytest.raises(ValueError, match="required"):
            normalize_timestamp(None)

    def test_invalid_string_raises(self):
        with pytest.raises(ValueError, match="not a valid"):
            normalize_timestamp("not-a-timestamp")

    def test_naive_in_observation_rejected(self, processor: EventProcessor):
        """Naive datetime in RawObservation is caught by the validator."""
        obs = make_process_start_observation(
            observed_at=datetime(2026, 1, 15, 10, 30)
        )
        result = processor.process(obs)
        assert not result.success
        assert any("timezone-aware" in e for e in result.errors)


# ── 7-9. Validation ──────────────────────────────────────────────

class TestValidation:

    def test_missing_source(self):
        obs = make_process_start_observation(source="")
        errors = validate_raw_observation(obs)
        assert any("source" in e for e in errors)

    def test_missing_event_type(self):
        obs = make_process_start_observation(event_type="")
        errors = validate_raw_observation(obs)
        assert any("event_type" in e for e in errors)

    def test_missing_action(self):
        obs = make_process_start_observation(action="")
        errors = validate_raw_observation(obs)
        assert any("action" in e for e in errors)

    def test_missing_timestamp(self):
        obs = make_process_start_observation(observed_at=None)
        errors = validate_raw_observation(obs)
        assert any("observed_at" in e or "timestamp" in e for e in errors)

    def test_invalid_severity(self):
        obs = make_process_start_observation(severity="emergency")
        errors = validate_raw_observation(obs)
        assert any("severity" in e for e in errors)

    def test_valid_severities_accepted(self, processor: EventProcessor):
        for sev in VALID_SEVERITIES:
            obs = make_process_start_observation(severity=sev)
            result = processor.process(obs)
            assert result.success, f"severity={sev} should be valid"

    def test_negative_uid(self):
        obs = make_process_start_observation(uid=-1)
        errors = validate_raw_observation(obs)
        assert any("uid" in e for e in errors)

    def test_negative_pid(self):
        obs = make_process_start_observation(pid=-5)
        errors = validate_raw_observation(obs)
        assert any("pid" in e for e in errors)

    def test_negative_ppid(self):
        obs = make_process_start_observation(ppid=-2)
        errors = validate_raw_observation(obs)
        assert any("ppid" in e for e in errors)

    def test_valid_observation_no_errors(self):
        obs = make_process_start_observation()
        errors = validate_raw_observation(obs)
        assert errors == []

    def test_multiple_errors_collected(self):
        """Multiple invalid fields produce multiple errors."""
        obs = make_process_start_observation(
            source="", event_type="", action="", severity="bad",
            observed_at=None, uid=-1, pid=-1,
        )
        errors = validate_raw_observation(obs)
        assert len(errors) >= 5


# ── 10-12. Identity and payload semantics ─────────────────────────

class TestIdentitySemantics:

    def test_process_id_distinct_from_pid(self, processor: EventProcessor):
        """process_id (OSIRIS UUID) and pid (Linux int) are separate."""
        obs = make_process_start_observation(
            pid=4567, process_id=FIXTURE_PROCESS_ID
        )
        result = processor.process(obs)
        assert result.success
        assert result.event.pid == 4567
        assert result.event.process_id == FIXTURE_PROCESS_ID
        assert isinstance(result.event.process_id, uuid.UUID)
        assert isinstance(result.event.pid, int)

    def test_username_supplementary_to_uid(self, processor: EventProcessor):
        """uid is the primary identity; username is supplementary."""
        obs = make_process_start_observation(uid=1000, username=None)
        result = processor.process(obs)
        assert result.success
        assert result.event.uid == 1000
        assert result.event.username is None

    def test_event_without_process_context(self, processor: EventProcessor):
        """Events without process info still normalize."""
        obs = make_resource_cpu_observation()
        result = processor.process(obs)
        assert result.success
        assert result.event.pid is None
        assert result.event.process_id is None

    def test_payload_preserved(self, processor: EventProcessor):
        obs = make_process_start_observation(
            payload={"executable": "/usr/bin/python3", "state": "running"}
        )
        result = processor.process(obs)
        assert result.success
        assert result.event.payload == {
            "executable": "/usr/bin/python3",
            "state": "running",
        }


# ── 13-14. Enrichment ─────────────────────────────────────────────

class TestEnrichment:

    def test_enrichment_deterministic(self, processor: EventProcessor):
        """Same input produces same output."""
        obs = make_process_start_observation()
        r1 = processor.process(obs)
        r2 = processor.process(obs)
        # Same fields (IDs differ because they're generated)
        assert r1.event.source == r2.event.source
        assert r1.event.event_type == r2.event.event_type
        assert r1.event.timestamp == r2.event.timestamp

    def test_source_lowercased(self):
        obs = make_process_start_observation(source="  PROC  ")
        normalized = normalize_observation(obs)
        enriched = enrich(normalized)
        assert enriched.source == "proc"

    def test_event_type_lowercased(self):
        obs = make_process_start_observation(event_type=" Process.Start ")
        normalized = normalize_observation(obs)
        enriched = enrich(normalized)
        assert enriched.event_type == "process.start"

    def test_username_whitespace_stripped(self):
        obs = make_process_start_observation(username="  student  ")
        normalized = normalize_observation(obs)
        enriched = enrich(normalized)
        assert enriched.username == "student"

    def test_empty_username_becomes_none(self):
        obs = make_process_start_observation(username="   ")
        normalized = normalize_observation(obs)
        enriched = enrich(normalized)
        assert enriched.username is None

    def test_command_copied_from_payload(self):
        obs = make_process_start_observation(
            command=None,
            payload={"command": "/usr/bin/python3 app.py"},
        )
        normalized = normalize_observation(obs)
        enriched = enrich(normalized)
        assert enriched.command == "/usr/bin/python3 app.py"


# ── 15. NormalizedEvent maps to Event model ───────────────────────

class TestModelMapping:

    def test_normalized_event_has_all_db_fields(self, processor: EventProcessor):
        """Every column in Event ORM has a matching NormalizedEvent field."""
        from backend.db.models.event import Event

        orm_columns = {c.key for c in Event.__table__.columns}
        # created_at is a DB-side default not part of the processing contract
        orm_columns.discard("created_at")

        obs = make_process_start_observation()
        result = processor.process(obs)
        assert result.success
        event_fields = set(NormalizedEvent.model_fields.keys())

        missing = orm_columns - event_fields
        assert not missing, f"NormalizedEvent is missing fields: {missing}"


# ── 16-18. Batch processing ──────────────────────────────────────

class TestBatchProcessing:

    def test_batch_all_valid(self, processor: EventProcessor):
        observations = [
            make_process_start_observation(),
            make_process_end_observation(),
            make_filesystem_modify_observation(),
            make_resource_cpu_observation(),
        ]
        result = processor.process_batch(observations)
        assert result.succeeded == 4
        assert result.failed == 0
        assert result.total == 4

    def test_batch_partial_failure(self, processor: EventProcessor):
        """Invalid observations don't corrupt valid ones."""
        observations = [
            make_process_start_observation(),
            make_process_start_observation(source="", observed_at=None),
            make_filesystem_modify_observation(),
        ]
        result = processor.process_batch(observations)
        assert result.succeeded == 2
        assert result.failed == 1
        assert result.errors[0][0] == 1  # index of failed observation

    def test_batch_all_invalid(self, processor: EventProcessor):
        observations = [
            make_process_start_observation(source=""),
            make_process_start_observation(observed_at=None),
        ]
        result = processor.process_batch(observations)
        assert result.succeeded == 0
        assert result.failed == 2

    def test_batch_unique_ids(self, processor: EventProcessor):
        observations = [
            make_process_start_observation(),
            make_process_start_observation(),
        ]
        result = processor.process_batch(observations)
        ids = [e.id for e in result.events]
        assert len(set(ids)) == 2


# ── 19-20. NormalizedEvent Pydantic validators ────────────────────

class TestNormalizedEventValidation:

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValueError, match="severity"):
            NormalizedEvent(
                id=uuid.uuid4(),
                host_id=FIXTURE_HOST_ID,
                timestamp=FIXTURE_TS,
                ingested_at=FIXTURE_TS,
                source="proc",
                event_type="process.start",
                action="start",
                severity="emergency",
            )

    def test_negative_pid_rejected(self):
        with pytest.raises(ValueError, match="pid"):
            NormalizedEvent(
                id=uuid.uuid4(),
                host_id=FIXTURE_HOST_ID,
                timestamp=FIXTURE_TS,
                ingested_at=FIXTURE_TS,
                source="proc",
                event_type="process.start",
                action="start",
                severity="info",
                pid=-1,
            )

    def test_negative_uid_rejected(self):
        with pytest.raises(ValueError, match="uid"):
            NormalizedEvent(
                id=uuid.uuid4(),
                host_id=FIXTURE_HOST_ID,
                timestamp=FIXTURE_TS,
                ingested_at=FIXTURE_TS,
                source="proc",
                event_type="process.start",
                action="start",
                severity="info",
                uid=-1,
            )

    def test_negative_ppid_rejected(self):
        with pytest.raises(ValueError, match="pid/ppid"):
            NormalizedEvent(
                id=uuid.uuid4(),
                host_id=FIXTURE_HOST_ID,
                timestamp=FIXTURE_TS,
                ingested_at=FIXTURE_TS,
                source="proc",
                event_type="process.start",
                action="start",
                severity="info",
                ppid=-1,
            )


# ── 21. EventRepository unit tests (SQLite) ───────────────────────

class TestEventRepository:

    def test_save_single_event(
        self, db_session, sample_host, processor: EventProcessor
    ):
        """Persist a single normalized event using the repository."""
        from backend.db.models.event import Event

        obs = make_process_start_observation(
            host_id=sample_host.id, process_id=None
        )
        res = processor.process(obs)
        assert res.success

        repo = EventRepository(db_session)
        orm_event = repo.save(res.event)

        assert orm_event.id == res.event.id
        # Verify it can be retrieved from the session
        fetched = db_session.get(Event, res.event.id)
        assert fetched is not None
        assert fetched.source == "proc"
        assert fetched.event_type == "process.start"
        assert fetched.host_id == sample_host.id
        assert fetched.process_id is None

    def test_save_event_with_process_reference(
        self, db_session, sample_host, sample_process, processor: EventProcessor
    ):
        """Persist an event referencing an existing process."""
        from backend.db.models.event import Event

        obs = make_process_start_observation(
            host_id=sample_host.id, process_id=sample_process.id
        )
        res = processor.process(obs)
        assert res.success

        repo = EventRepository(db_session)
        repo.save(res.event)

        fetched = db_session.get(Event, res.event.id)
        assert fetched is not None
        assert fetched.process_id == sample_process.id
        assert fetched.process.id == sample_process.id

    def test_save_batch_events(
        self, db_session, sample_host, processor: EventProcessor
    ):
        """Persist multiple events via save_batch."""
        from backend.db.models.event import Event

        obs1 = make_filesystem_modify_observation(host_id=sample_host.id)
        obs2 = make_resource_cpu_observation(host_id=sample_host.id)
        events = [processor.process(obs1).event, processor.process(obs2).event]

        repo = EventRepository(db_session)
        saved = repo.save_batch(events)

        assert len(saved) == 2
        for e in events:
            assert db_session.get(Event, e.id) is not None

    def test_save_invalid_host_fails_and_rolls_back(
        self, db_session, processor: EventProcessor
    ):
        """Saving an event with an unknown host_id raises IntegrityError."""
        from sqlalchemy.exc import IntegrityError

        non_existent_host = uuid.uuid4()
        obs = make_process_start_observation(
            host_id=non_existent_host, process_id=None
        )
        res = processor.process(obs)
        assert res.success

        repo = EventRepository(db_session)
        with pytest.raises(IntegrityError):
            repo.save(res.event)
        db_session.rollback()


