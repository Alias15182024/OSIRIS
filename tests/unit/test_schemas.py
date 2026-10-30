"""Unit tests for OSIRIS Phase 1.5 Pydantic API schemas.

Tests:
- Valid construction for all model groups (auth, events, processes, resources, files, status, error).
- ORM-style serialization (from_attributes=True) for response models.
- UUID and datetime string parsing and validation.
- Nullable field handling according to DB schema contracts.
- Pagination defaults and validation (limit >= 1, offset >= 0).
- Rejection of invalid inputs and missing required fields.
- Arbitrary payload JSON handling in event schemas.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from backend.api.schemas import (
    ErrorDetail,
    EventQueryParams,
    EventResponse,
    FileQueryParams,
    FileResponse,
    LoginRequest,
    PaginatedEventResponse,
    PaginatedFileResponse,
    PaginatedProcessResponse,
    PaginatedResourceSnapshotResponse,
    PaginatedSessionResponse,
    PaginatedSnapshotResponse,
    PaginatedTimelineResponse,
    ProcessContext,
    ProcessQueryParams,
    ProcessResponse,
    ProcessSummary,
    ResourceContext,
    ResourceSnapshotQueryParams,
    ResourceSnapshotResponse,
    SessionContext,
    SessionDetailResponse,
    SessionQueryParams,
    SessionResponse,
    SnapshotContext,
    SnapshotQueryParams,
    SnapshotResponse,
    StatusResponse,
    TimelineEntryResponse,
    TimelineQueryParams,
    TokenResponse,
    UserContext,
    UserResponse,
)
from backend.db.models.app_user import AppUser
from backend.db.models.event import Event
from backend.db.models.file import File
from backend.db.models.process import Process
from backend.db.models.resource_snapshot import ResourceSnapshot
from backend.db.models.snapshot import Snapshot


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================================
# Auth Schemas Tests
# ============================================================================


class TestAuthSchemas:
    """Tests for authentication and user schemas."""

    def test_login_request_valid(self) -> None:
        req = LoginRequest(username="admin", password="SecretPassword123")
        assert req.username == "admin"
        assert req.password == "SecretPassword123"

    def test_login_request_missing_fields_raises(self) -> None:
        with pytest.raises(ValidationError):
            LoginRequest(username="admin")  # Missing password

        with pytest.raises(ValidationError):
            LoginRequest(password="password")  # Missing username

    def test_user_response_valid(self) -> None:
        user_id = uuid.uuid4()
        now = utcnow()
        res = UserResponse(
            id=user_id,
            username="investigator1",
            display_name="Investigator One",
            role="admin",
            is_active=True,
            created_at=now,
        )
        assert res.id == user_id
        assert res.username == "investigator1"
        assert res.display_name == "Investigator One"
        assert res.role == "admin"
        assert res.is_active is True
        assert res.created_at == now

    def test_user_response_nullable_display_name(self) -> None:
        res = UserResponse(
            id=uuid.uuid4(),
            username="analyst",
            role="viewer",
            is_active=True,
            created_at=utcnow(),
        )
        assert res.display_name is None

    def test_user_response_orm_serialization(self) -> None:
        user_id = uuid.uuid4()
        now = utcnow()
        orm_user = AppUser(
            id=user_id,
            username="db_user",
            password_hash="pbkdf2_sha256$...",
            display_name="DB User",
            role="viewer",
            is_active=True,
            created_at=now,
        )
        res = UserResponse.model_validate(orm_user)
        assert res.id == user_id
        assert res.username == "db_user"
        assert res.display_name == "DB User"
        assert res.role == "viewer"
        assert res.is_active is True
        assert res.created_at == now

    def test_token_response_valid(self) -> None:
        user_res = UserResponse(
            id=uuid.uuid4(),
            username="analyst",
            role="viewer",
            is_active=True,
            created_at=utcnow(),
        )
        token_res = TokenResponse(
            access_token="fake.signed.token",
            user=user_res,
        )
        assert token_res.access_token == "fake.signed.token"
        assert token_res.token_type == "bearer"
        assert token_res.user.username == "analyst"


# ============================================================================
# Event Schemas Tests
# ============================================================================


class TestEventSchemas:
    """Tests for event query, response, and pagination schemas."""

    def test_event_query_params_defaults(self) -> None:
        params = EventQueryParams()
        assert params.limit == 50
        assert params.offset == 0
        assert params.host_id is None
        assert params.start_time is None
        assert params.end_time is None
        assert params.source is None
        assert params.event_type is None
        assert params.severity is None
        assert params.process_id is None
        assert params.pid is None

    def test_event_query_params_custom(self) -> None:
        h_id = uuid.uuid4()
        p_id = uuid.uuid4()
        t0 = utcnow()
        params = EventQueryParams(
            host_id=h_id,
            start_time=t0,
            source="proc",
            event_type="process.start",
            severity="info",
            process_id=p_id,
            pid=1234,
            limit=100,
            offset=20,
        )
        assert params.host_id == h_id
        assert params.process_id == p_id
        assert params.limit == 100
        assert params.offset == 20

    def test_event_query_params_pagination(self) -> None:
        # valid limits
        assert EventQueryParams().limit == 50
        assert EventQueryParams(limit=1).limit == 1
        assert EventQueryParams(limit=100).limit == 100

        # invalid limits
        with pytest.raises(ValidationError):
            EventQueryParams(limit=0)

        with pytest.raises(ValidationError):
            EventQueryParams(limit=-5)

        with pytest.raises(ValidationError):
            EventQueryParams(limit=101)

        with pytest.raises(ValidationError):
            EventQueryParams(offset=-1)

    def test_event_response_all_fields(self) -> None:
        ev_id = uuid.uuid4()
        h_id = uuid.uuid4()
        p_id = uuid.uuid4()
        now = utcnow()

        res = EventResponse(
            id=ev_id,
            host_id=h_id,
            process_id=p_id,
            timestamp=now,
            ingested_at=now,
            source="proc",
            event_type="process.start",
            action="start",
            severity="info",
            uid=1000,
            username="student",
            pid=4321,
            ppid=1,
            command="/usr/bin/python script.py",
            object_type="process",
            object_path=None,
            success=True,
            result="started",
            payload={"cpu": 1.5, "tags": ["prod"]},
            created_at=now,
        )
        assert res.id == ev_id
        assert res.uid == 1000
        assert res.payload == {"cpu": 1.5, "tags": ["prod"]}

    def test_event_response_nullable_fields_default_to_none(self) -> None:
        res = EventResponse(
            id=uuid.uuid4(),
            host_id=uuid.uuid4(),
            timestamp=utcnow(),
            ingested_at=utcnow(),
            source="fs",
            event_type="filesystem.create",
            action="create",
            severity="info",
            created_at=utcnow(),
        )
        assert res.process_id is None
        assert res.uid is None
        assert res.username is None
        assert res.pid is None
        assert res.ppid is None
        assert res.command is None
        assert res.object_type is None
        assert res.object_path is None
        assert res.success is None
        assert res.result is None
        assert res.payload is None

    def test_event_response_orm_serialization(self) -> None:
        ev_id = uuid.uuid4()
        h_id = uuid.uuid4()
        now = utcnow()
        orm_event = Event(
            id=ev_id,
            host_id=h_id,
            process_id=None,
            timestamp=now,
            ingested_at=now,
            source="resource",
            event_type="resource.snapshot",
            action="snapshot",
            severity="info",
            uid=None,
            username=None,
            pid=None,
            ppid=None,
            command=None,
            object_type="system",
            object_path=None,
            success=True,
            result=None,
            payload={"cpu_percent": 12.5, "mem_percent": 45.0},
            created_at=now,
        )
        res = EventResponse.model_validate(orm_event)
        assert res.id == ev_id
        assert res.source == "resource"
        assert res.payload == {"cpu_percent": 12.5, "mem_percent": 45.0}

    def test_paginated_event_response(self) -> None:
        now = utcnow()
        item = EventResponse(
            id=uuid.uuid4(),
            host_id=uuid.uuid4(),
            timestamp=now,
            ingested_at=now,
            source="proc",
            event_type="process.start",
            action="start",
            severity="info",
            created_at=now,
        )
        paginated = PaginatedEventResponse(
            total=1,
            items=[item],
            limit=50,
            offset=0,
        )
        assert paginated.total == 1
        assert len(paginated.items) == 1
        assert paginated.items[0].id == item.id


# ============================================================================
# Process Schemas Tests
# ============================================================================


class TestProcessSchemas:
    """Tests for process query, response, and pagination schemas."""

    def test_process_query_params_defaults(self) -> None:
        params = ProcessQueryParams()
        assert params.limit == 50
        assert params.offset == 0
        assert params.host_id is None
        assert params.pid is None
        assert params.is_active is None

    def test_process_query_params_validation(self) -> None:
        # valid limits
        assert ProcessQueryParams().limit == 50
        assert ProcessQueryParams(limit=1).limit == 1
        assert ProcessQueryParams(limit=100).limit == 100

        # invalid limits
        with pytest.raises(ValidationError):
            ProcessQueryParams(limit=0)

        with pytest.raises(ValidationError):
            ProcessQueryParams(limit=-5)

        with pytest.raises(ValidationError):
            ProcessQueryParams(limit=101)

        with pytest.raises(ValidationError):
            ProcessQueryParams(offset=-1)

    def test_process_response_valid(self) -> None:
        p_id = uuid.uuid4()
        h_id = uuid.uuid4()
        u_id = uuid.uuid4()
        now = utcnow()

        res = ProcessResponse(
            id=p_id,
            host_id=h_id,
            pid=100,
            ppid=1,
            command="/usr/bin/daemon --verbose",
            executable="/usr/bin/daemon",
            linux_user_id=u_id,
            started_at=now,
            ended_at=None,
            created_at=now,
        )
        assert res.id == p_id
        assert res.pid == 100
        assert res.ended_at is None

    def test_process_response_orm_serialization(self) -> None:
        p_id = uuid.uuid4()
        h_id = uuid.uuid4()
        now = utcnow()
        orm_proc = Process(
            id=p_id,
            host_id=h_id,
            pid=200,
            ppid=None,
            command="bash",
            executable="/bin/bash",
            linux_user_id=None,
            started_at=now,
            ended_at=None,
            created_at=now,
        )
        res = ProcessResponse.model_validate(orm_proc)
        assert res.id == p_id
        assert res.pid == 200
        assert res.command == "bash"

    def test_paginated_process_response(self) -> None:
        paginated = PaginatedProcessResponse(
            total=0,
            items=[],
            limit=25,
            offset=10,
        )
        assert paginated.total == 0
        assert paginated.items == []
        assert paginated.limit == 25
        assert paginated.offset == 10


# ============================================================================
# Resource Schemas Tests
# ============================================================================


class TestResourceSchemas:
    """Tests for resource snapshot query, response, and pagination schemas."""

    def test_resource_query_params_defaults(self) -> None:
        params = ResourceSnapshotQueryParams()
        assert params.limit == 50
        assert params.offset == 0
        assert params.host_id is None
        assert params.start_time is None
        assert params.end_time is None

    def test_resource_query_params_validation(self) -> None:
        # valid limits
        assert ResourceSnapshotQueryParams().limit == 50
        assert ResourceSnapshotQueryParams(limit=1).limit == 1
        assert ResourceSnapshotQueryParams(limit=100).limit == 100

        # invalid limits
        with pytest.raises(ValidationError):
            ResourceSnapshotQueryParams(limit=0)

        with pytest.raises(ValidationError):
            ResourceSnapshotQueryParams(limit=-5)

        with pytest.raises(ValidationError):
            ResourceSnapshotQueryParams(limit=101)

        with pytest.raises(ValidationError):
            ResourceSnapshotQueryParams(offset=-1)

    def test_resource_snapshot_response_all_fields(self) -> None:
        snap_id = uuid.uuid4()
        h_id = uuid.uuid4()
        now = utcnow()

        res = ResourceSnapshotResponse(
            id=snap_id,
            host_id=h_id,
            timestamp=now,
            cpu_percent=15.5,
            memory_total=16000000000,
            memory_used=8000000000,
            memory_percent=50.0,
            disk_read_bytes=1048576,
            disk_write_bytes=2097152,
            disk_usage_percent=33.3,
            created_at=now,
        )
        assert res.id == snap_id
        assert res.cpu_percent == 15.5
        assert res.memory_total == 16000000000

    def test_resource_snapshot_nullable_metrics(self) -> None:
        res = ResourceSnapshotResponse(
            id=uuid.uuid4(),
            host_id=uuid.uuid4(),
            timestamp=utcnow(),
            created_at=utcnow(),
        )
        assert res.cpu_percent is None
        assert res.memory_total is None
        assert res.disk_usage_percent is None

    def test_resource_snapshot_orm_serialization(self) -> None:
        snap_id = uuid.uuid4()
        h_id = uuid.uuid4()
        now = utcnow()
        orm_snap = ResourceSnapshot(
            id=snap_id,
            host_id=h_id,
            timestamp=now,
            cpu_percent=25.0,
            memory_total=8000000000,
            memory_used=4000000000,
            memory_percent=50.0,
            disk_read_bytes=None,
            disk_write_bytes=None,
            disk_usage_percent=75.0,
            created_at=now,
        )
        res = ResourceSnapshotResponse.model_validate(orm_snap)
        assert res.id == snap_id
        assert res.cpu_percent == 25.0
        assert res.disk_read_bytes is None

    def test_paginated_resource_response(self) -> None:
        paginated = PaginatedResourceSnapshotResponse(
            total=0,
            items=[],
            limit=50,
            offset=0,
        )
        assert paginated.total == 0
        assert paginated.items == []


# ============================================================================
# File Schemas Tests
# ============================================================================


class TestFileSchemas:
    """Tests for file monitoring query, response, and pagination schemas."""

    def test_file_query_params_defaults(self) -> None:
        params = FileQueryParams()
        assert params.limit == 50
        assert params.offset == 0
        assert params.host_id is None
        assert params.path is None
        assert params.file_type is None

    def test_file_query_params_validation(self) -> None:
        # valid limits
        assert FileQueryParams().limit == 50
        assert FileQueryParams(limit=1).limit == 1
        assert FileQueryParams(limit=100).limit == 100
        # valid file types
        assert FileQueryParams(file_type="file").file_type == "file"
        assert FileQueryParams(file_type="directory").file_type == "directory"
        assert FileQueryParams(file_type="symlink").file_type == "symlink"

        # invalid limits
        with pytest.raises(ValidationError):
            FileQueryParams(limit=0)
        with pytest.raises(ValidationError):
            FileQueryParams(limit=-1)
        with pytest.raises(ValidationError):
            FileQueryParams(limit=101)

        # invalid file type
        with pytest.raises(ValidationError):
            FileQueryParams(file_type="regular")
        with pytest.raises(ValidationError):
            FileQueryParams(file_type="invalid_type")

    def test_file_response_valid(self) -> None:
        f_id = uuid.uuid4()
        h_id = uuid.uuid4()
        now = utcnow()

        res = FileResponse(
            id=f_id,
            host_id=h_id,
            path="/etc/passwd",
            inode=123456,
            file_type="file",
            first_seen_at=now,
            last_seen_at=now,
            created_at=now,
        )
        assert res.id == f_id
        assert res.path == "/etc/passwd"
        assert res.inode == 123456

    def test_file_response_nullable_fields(self) -> None:
        res = FileResponse(
            id=uuid.uuid4(),
            host_id=uuid.uuid4(),
            path="/var/log/syslog",
            first_seen_at=utcnow(),
            created_at=utcnow(),
        )
        assert res.inode is None
        assert res.file_type is None
        assert res.last_seen_at is None

    def test_file_response_normalizes_legacy_file_types(self) -> None:
        now = utcnow()
        res_reg = FileResponse(
            id=uuid.uuid4(),
            host_id=uuid.uuid4(),
            path="/etc/passwd",
            file_type="regular",
            first_seen_at=now,
            created_at=now,
        )
        assert res_reg.file_type == "file"

        res_reg_alt = FileResponse(
            id=uuid.uuid4(),
            host_id=uuid.uuid4(),
            path="/etc/passwd.old",
            file_type="regular_file",
            first_seen_at=now,
            created_at=now,
        )
        assert res_reg_alt.file_type == "file"

        res_sym = FileResponse(
            id=uuid.uuid4(),
            host_id=uuid.uuid4(),
            path="/bin/sh",
            file_type="symlink",
            first_seen_at=now,
            created_at=now,
        )
        assert res_sym.file_type == "symlink"

    def test_file_response_orm_serialization(self) -> None:
        f_id = uuid.uuid4()
        h_id = uuid.uuid4()
        now = utcnow()
        orm_file = File(
            id=f_id,
            host_id=h_id,
            path="/tmp/test.txt",
            inode=9999,
            file_type="file",
            first_seen_at=now,
            last_seen_at=None,
            created_at=now,
        )
        res = FileResponse.model_validate(orm_file)
        assert res.id == f_id
        assert res.path == "/tmp/test.txt"
        assert res.inode == 9999
        assert res.last_seen_at is None

    def test_paginated_file_response(self) -> None:
        paginated = PaginatedFileResponse(
            total=0,
            items=[],
            limit=50,
            offset=0,
        )
        assert paginated.total == 0
        assert paginated.items == []


# ============================================================================
# Status and Error Schemas Tests
# ============================================================================


class TestStatusAndErrorSchemas:
    """Tests for system status and error detail schemas."""

    def test_status_response_valid(self) -> None:
        res = StatusResponse(
            status="healthy",
            system="osiris",
            database="connected",
            host_id="osiris-dev-host",
        )
        assert res.status == "healthy"
        assert res.system == "osiris"
        assert res.database == "connected"
        assert res.host_id == "osiris-dev-host"

    def test_status_response_missing_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            StatusResponse(status="healthy", system="osiris")

    def test_error_detail_valid(self) -> None:
        err = ErrorDetail(
            detail="Resource not found",
            error_code="NOT_FOUND",
        )
        assert err.detail == "Resource not found"
        assert err.error_code == "NOT_FOUND"

    def test_error_detail_missing_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            ErrorDetail(detail="Failed")


# ============================================================================
# Snapshot Schemas Tests
# ============================================================================


class TestSnapshotSchemas:
    """Tests for Phase 2 Milestone 2.1 snapshot schemas."""

    def test_snapshot_query_params_defaults(self) -> None:
        params = SnapshotQueryParams()
        assert params.host_id is None
        assert params.snapshot_type is None
        assert params.start_time is None
        assert params.end_time is None
        assert params.limit == 50
        assert params.offset == 0

    def test_snapshot_query_params_valid(self) -> None:
        hid = uuid.uuid4()
        t0 = utcnow()
        params = SnapshotQueryParams(
            host_id=hid,
            snapshot_type="system_state",
            start_time=t0,
            end_time=t0,
            limit=25,
            offset=10,
        )
        assert params.host_id == hid
        assert params.snapshot_type == "system_state"
        assert params.start_time == t0
        assert params.end_time == t0
        assert params.limit == 25
        assert params.offset == 10

    def test_snapshot_query_params_limit_zero_raises(self) -> None:
        with pytest.raises(ValidationError):
            SnapshotQueryParams(limit=0)

    def test_snapshot_query_params_limit_above_max_raises(self) -> None:
        with pytest.raises(ValidationError):
            SnapshotQueryParams(limit=101)

    def test_snapshot_query_params_offset_negative_raises(self) -> None:
        with pytest.raises(ValidationError):
            SnapshotQueryParams(offset=-1)

    def test_snapshot_response_valid(self) -> None:
        sid = uuid.uuid4()
        hid = uuid.uuid4()
        t = utcnow()
        payload = {"processes": [{"pid": 1, "cmd": "init"}], "resources": {"cpu": 10.5}}
        resp = SnapshotResponse(
            id=sid,
            host_id=hid,
            timestamp=t,
            snapshot_type="system_state",
            data=payload,
            created_at=t,
        )
        assert resp.id == sid
        assert resp.host_id == hid
        assert resp.timestamp == t
        assert resp.snapshot_type == "system_state"
        assert resp.data == payload
        assert resp.created_at == t

    def test_snapshot_response_orm_validation(self) -> None:
        sid = uuid.uuid4()
        hid = uuid.uuid4()
        t = utcnow()
        data = {"processes": [], "resources": None}
        orm_snap = Snapshot(
            id=sid,
            host_id=hid,
            timestamp=t,
            snapshot_type="system_state",
            data=data,
            created_at=t,
        )
        resp = SnapshotResponse.model_validate(orm_snap)
        assert resp.id == sid
        assert resp.host_id == hid
        assert resp.timestamp == t
        assert resp.snapshot_type == "system_state"
        assert resp.data == data
        assert resp.created_at == t

    def test_snapshot_response_empty_data(self) -> None:
        resp = SnapshotResponse(
            id=uuid.uuid4(),
            host_id=uuid.uuid4(),
            timestamp=utcnow(),
            snapshot_type="system_state",
            data={},
            created_at=utcnow(),
        )
        assert resp.data == {}

    def test_paginated_snapshot_response_valid(self) -> None:
        paginated = PaginatedSnapshotResponse(
            total=0,
            items=[],
            limit=50,
            offset=0,
        )
        assert paginated.total == 0
        assert paginated.items == []
        assert paginated.limit == 50
        assert paginated.offset == 0


# ============================================================================
# Timeline Schemas Tests (Phase 2 Milestone 2.2)
# ============================================================================


class TestTimelineSchemas:
    """Test suite for Phase 2 Milestone 2.2 Timeline Pydantic v2 schemas."""

    def test_process_context_valid(self) -> None:
        pid_uuid = uuid.uuid4()
        ctx = ProcessContext(
            process_id=pid_uuid,
            pid=123,
            ppid=1,
            command="/bin/ls",
            executable="/bin/ls",
        )
        assert ctx.process_id == pid_uuid
        assert ctx.pid == 123
        assert ctx.ppid == 1
        assert ctx.command == "/bin/ls"
        assert ctx.executable == "/bin/ls"

    def test_user_context_valid(self) -> None:
        uid_uuid = uuid.uuid4()
        ctx = UserContext(user_id=uid_uuid, uid=1000, username="alice")
        assert ctx.user_id == uid_uuid
        assert ctx.uid == 1000
        assert ctx.username == "alice"

    def test_session_context_valid(self) -> None:
        sid_uuid = uuid.uuid4()
        ctx = SessionContext(
            session_id=sid_uuid,
            session_type="ssh",
            terminal="pts/2",
            remote_host="192.168.1.100",
        )
        assert ctx.session_id == sid_uuid
        assert ctx.session_type == "ssh"
        assert ctx.terminal == "pts/2"
        assert ctx.remote_host == "192.168.1.100"

    def test_timeline_query_params_defaults(self) -> None:
        params = TimelineQueryParams()
        assert params.host_id is None
        assert params.start_time is None
        assert params.end_time is None
        assert params.record_type is None
        assert params.order == "asc"
        assert params.limit == 50
        assert params.offset == 0

    def test_timeline_query_params_validation(self) -> None:
        with pytest.raises(ValidationError):
            TimelineQueryParams(limit=0)
        with pytest.raises(ValidationError):
            TimelineQueryParams(limit=101)
        with pytest.raises(ValidationError):
            TimelineQueryParams(offset=-1)
        with pytest.raises(ValidationError):
            TimelineQueryParams(order="invalid_order")
        with pytest.raises(ValidationError):
            TimelineQueryParams(pid=-1)
        with pytest.raises(ValidationError):
            TimelineQueryParams(uid=-1)

    def test_timeline_entry_response_valid(self) -> None:
        eid = uuid.uuid4()
        hid = uuid.uuid4()
        sid = uuid.uuid4()
        t = utcnow()
        entry = TimelineEntryResponse(
            id=eid,
            timestamp=t,
            host_id=hid,
            source="proc",
            source_id=sid,
            record_type="event",
            event_type="process.start",
            action="start",
            severity="info",
            description="Process started: /usr/bin/bash (PID 100)",
            process_context=ProcessContext(pid=100, command="/usr/bin/bash"),
            user_context=UserContext(uid=1000, username="alice"),
            session_context=SessionContext(terminal="pts/0"),
            file_context=None,
            resource_context=None,
            snapshot_context=None,
            payload={"comm": "bash"},
        )
        assert entry.id == eid
        assert entry.timestamp == t
        assert entry.host_id == hid
        assert entry.source == "proc"
        assert entry.source_id == sid
        assert entry.record_type == "event"
        assert entry.process_context.pid == 100  # type: ignore[union-attr]
        assert entry.user_context.username == "alice"  # type: ignore[union-attr]
        assert entry.payload == {"comm": "bash"}

    def test_paginated_timeline_response_valid(self) -> None:
        paginated = PaginatedTimelineResponse(
            total=0,
            items=[],
            limit=50,
            offset=0,
        )
        assert paginated.total == 0
        assert paginated.items == []
        assert paginated.limit == 50
        assert paginated.offset == 0


class TestSessionSchemas:
    """Tests for Phase 2 Milestone 2.3 User Session schemas."""

    def test_session_query_params_defaults(self) -> None:
        params = SessionQueryParams()
        assert params.host_id is None
        assert params.linux_user_id is None
        assert params.username is None
        assert params.session_type is None
        assert params.terminal is None
        assert params.remote_host is None
        assert params.start_time is None
        assert params.end_time is None
        assert params.is_active is None
        assert params.limit == 50
        assert params.offset == 0

    def test_session_query_params_bounds(self) -> None:
        with pytest.raises(ValidationError):
            SessionQueryParams(limit=0)
        with pytest.raises(ValidationError):
            SessionQueryParams(limit=101)
        with pytest.raises(ValidationError):
            SessionQueryParams(offset=-1)

    def test_session_response_from_dict(self) -> None:
        sid = uuid.uuid4()
        hid = uuid.uuid4()
        uid = uuid.uuid4()
        t_start = utcnow()
        resp = SessionResponse(
            id=sid,
            host_id=hid,
            linux_user_id=uid,
            username="alice",
            uid=1000,
            session_type="ssh",
            terminal="pts/0",
            remote_host="192.168.1.100",
            started_at=t_start,
            ended_at=None,
            is_active=True,
            duration_seconds=None,
            created_at=t_start,
        )
        assert resp.id == sid
        assert resp.host_id == hid
        assert resp.username == "alice"
        assert resp.is_active is True
        assert resp.duration_seconds is None

    def test_session_detail_response_with_processes(self) -> None:
        sid = uuid.uuid4()
        hid = uuid.uuid4()
        pid = uuid.uuid4()
        t = utcnow()
        proc = ProcessSummary(
            id=pid,
            pid=1234,
            ppid=1000,
            command="/bin/bash",
            started_at=t,
            ended_at=None,
        )
        detail = SessionDetailResponse(
            id=sid,
            host_id=hid,
            started_at=t,
            created_at=t,
            process_count=1,
            processes=[proc],
        )
        assert detail.id == sid
        assert detail.process_count == 1
        assert len(detail.processes) == 1
        assert detail.processes[0].pid == 1234

    def test_paginated_session_response_valid(self) -> None:
        paginated = PaginatedSessionResponse(
            total=0,
            items=[],
            limit=50,
            offset=0,
        )
        assert paginated.total == 0
        assert paginated.items == []
        assert paginated.limit == 50
        assert paginated.offset == 0
