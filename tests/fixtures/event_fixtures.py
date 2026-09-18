"""Deterministic test fixtures for raw observations.

These represent the kind of data future collectors will produce.
They are FIXTURES ONLY — no collector is implemented here.

Every fixture returns a ``RawObservation`` (or the kwargs dict for one)
with reproducible, deterministic values.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

from backend.services.events.schemas import RawObservation

# Fixed UUIDs for reproducible tests (match conftest.py where applicable)
FIXTURE_HOST_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
FIXTURE_PROCESS_ID = uuid.UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")

# Fixed timestamp: 2026-01-15 10:30:00 UTC
FIXTURE_TS = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

# Same instant expressed in IST (UTC+5:30)
FIXTURE_TS_IST = FIXTURE_TS.astimezone(
    timezone(timedelta(hours=5, minutes=30))
)


def make_process_start_observation(**overrides) -> RawObservation:
    """A ``process.start`` observation from the process collector."""
    defaults = dict(
        source="proc",
        host_id=FIXTURE_HOST_ID,
        event_type="process.start",
        action="start",
        severity="info",
        observed_at=FIXTURE_TS,
        uid=1000,
        username="student",
        pid=4567,
        ppid=1,
        command="/usr/bin/python3 app.py",
        process_id=FIXTURE_PROCESS_ID,
        payload={"executable": "/usr/bin/python3", "state": "running"},
    )
    defaults.update(overrides)
    return RawObservation(**defaults)


def make_process_end_observation(**overrides) -> RawObservation:
    """A ``process.end`` observation from the process collector."""
    defaults = dict(
        source="proc",
        host_id=FIXTURE_HOST_ID,
        event_type="process.end",
        action="exit",
        severity="info",
        observed_at=FIXTURE_TS + timedelta(minutes=5),
        uid=1000,
        username="student",
        pid=4567,
        ppid=1,
        command="/usr/bin/python3 app.py",
        process_id=FIXTURE_PROCESS_ID,
        payload={"exit_code": 0},
    )
    defaults.update(overrides)
    return RawObservation(**defaults)


def make_filesystem_modify_observation(**overrides) -> RawObservation:
    """A ``filesystem.modify`` observation from the filesystem collector."""
    defaults = dict(
        source="fs",
        host_id=FIXTURE_HOST_ID,
        event_type="filesystem.modify",
        action="modify",
        severity="info",
        observed_at=FIXTURE_TS,
        uid=1000,
        username="student",
        pid=4567,
        object_type="file",
        object_path="/home/student/project/data.csv",
        success=True,
        payload={"inode": 123456, "size_bytes": 2048},
    )
    defaults.update(overrides)
    return RawObservation(**defaults)


def make_resource_cpu_observation(**overrides) -> RawObservation:
    """A ``resource.cpu`` observation from the resource collector."""
    defaults = dict(
        source="resource",
        host_id=FIXTURE_HOST_ID,
        event_type="resource.cpu",
        action="snapshot",
        severity="info",
        observed_at=FIXTURE_TS,
        payload={
            "cpu_percent": 45.2,
            "load_avg_1m": 1.5,
            "load_avg_5m": 1.2,
            "load_avg_15m": 0.9,
        },
    )
    defaults.update(overrides)
    return RawObservation(**defaults)
