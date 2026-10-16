"""Tests for OSIRIS Desktop authenticated events REST API client.

Covers:
A. Event and EventCollection model validation and error handling.
B. APIClient.get_events() listing, filtering, and pagination.
C. APIClient.get_event() single event retrieval.
D. Security, authentication lifecycle, and transport exception regressions.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import pytest
import respx

from desktop.client import (
    VALID_SEVERITIES,
    APIClient,
    AuthenticationError,
    AuthorizationError,
    ClientConnectionError,
    ConnectionTimeoutError,
    Event,
    EventCollection,
    HTTPResponseError,
    ValidationError,
)

# Representative test UUIDs and timestamps
SAMPLE_EVENT_ID = "11111111-1111-4111-8111-111111111111"
SAMPLE_HOST_ID = "22222222-2222-4222-8222-222222222222"
SAMPLE_PROCESS_ID = "33333333-3333-4333-8333-333333333333"
SAMPLE_TIMESTAMP = "2026-03-01T12:00:00Z"
SAMPLE_INGESTED_AT = "2026-03-01T12:00:00.010000Z"
SAMPLE_CREATED_AT = "2026-03-01T12:00:00Z"

SAMPLE_EVENT_DICT: dict[str, Any] = {
    "id": SAMPLE_EVENT_ID,
    "host_id": SAMPLE_HOST_ID,
    "process_id": SAMPLE_PROCESS_ID,
    "timestamp": SAMPLE_TIMESTAMP,
    "ingested_at": SAMPLE_INGESTED_AT,
    "source": "proc",
    "event_type": "process.start",
    "action": "start",
    "severity": "info",
    "uid": 1000,
    "username": "sec_analyst",
    "pid": 1001,
    "ppid": 1,
    "command": "/usr/bin/python worker.py",
    "object_type": "process",
    "object_path": None,
    "success": True,
    "result": "started",
    "payload": {"args": ["worker.py"]},
    "created_at": SAMPLE_CREATED_AT,
}

SAMPLE_MINIMAL_EVENT_DICT: dict[str, Any] = {
    "id": SAMPLE_EVENT_ID,
    "host_id": SAMPLE_HOST_ID,
    "timestamp": SAMPLE_TIMESTAMP,
    "ingested_at": SAMPLE_INGESTED_AT,
    "source": "resource",
    "event_type": "resource.snapshot",
    "action": "snapshot",
    "severity": "low",
    "created_at": SAMPLE_CREATED_AT,
}

SAMPLE_COLLECTION_DICT: dict[str, Any] = {
    "total": 1,
    "items": [SAMPLE_EVENT_DICT],
    "limit": 50,
    "offset": 0,
}


def _authenticated_client() -> APIClient:
    """Return an APIClient initialized with an in-memory session token."""
    client = APIClient(base_url="http://127.0.0.1:8001")
    client._token = "test.secret.bearer.token"
    return client


# ==============================================================================
# A. Event & EventCollection Model Tests
# ==============================================================================


class TestEventModel:
    """Tests for Event and EventCollection dataclasses."""

    def test_event_from_dict_full(self) -> None:
        """Event parses all valid fields matching the backend schema."""
        event = Event.from_dict(SAMPLE_EVENT_DICT)
        assert event.id == SAMPLE_EVENT_ID
        assert event.host_id == SAMPLE_HOST_ID
        assert event.process_id == SAMPLE_PROCESS_ID
        assert event.timestamp == SAMPLE_TIMESTAMP
        assert event.ingested_at == SAMPLE_INGESTED_AT
        assert event.source == "proc"
        assert event.event_type == "process.start"
        assert event.action == "start"
        assert event.severity == "info"
        assert event.uid == 1000
        assert event.username == "sec_analyst"
        assert event.pid == 1001
        assert event.ppid == 1
        assert event.command == "/usr/bin/python worker.py"
        assert event.object_type == "process"
        assert event.object_path is None
        assert event.success is True
        assert event.result == "started"
        assert event.payload == {"args": ["worker.py"]}
        assert event.created_at == SAMPLE_CREATED_AT

    def test_event_from_dict_minimal(self) -> None:
        """Event handles missing nullable fields with None defaults."""
        event = Event.from_dict(SAMPLE_MINIMAL_EVENT_DICT)
        assert event.id == SAMPLE_EVENT_ID
        assert event.host_id == SAMPLE_HOST_ID
        assert event.process_id is None
        assert event.uid is None
        assert event.username is None
        assert event.pid is None
        assert event.ppid is None
        assert event.command is None
        assert event.object_type is None
        assert event.object_path is None
        assert event.success is None
        assert event.result is None
        assert event.payload is None

    def test_event_to_dict_roundtrip(self) -> None:
        """Event.to_dict converts dataclass to standard dictionary."""
        event = Event.from_dict(SAMPLE_EVENT_DICT)
        d = event.to_dict()
        assert isinstance(d, dict)
        assert d["id"] == SAMPLE_EVENT_ID
        assert d["severity"] == "info"

    def test_event_rejects_non_dict(self) -> None:
        """Event.from_dict rejects non-dictionary data."""
        with pytest.raises(ValidationError, match="Expected JSON object"):
            Event.from_dict(["not", "a", "dict"])

    @pytest.mark.parametrize(
        "missing_field",
        [
            "id",
            "host_id",
            "timestamp",
            "ingested_at",
            "source",
            "event_type",
            "action",
            "severity",
            "created_at",
        ],
    )
    def test_event_rejects_missing_required_fields(self, missing_field: str) -> None:
        """Event.from_dict rejects payloads missing any required field."""
        bad_data = dict(SAMPLE_EVENT_DICT)
        del bad_data[missing_field]
        with pytest.raises(
            ValidationError, match=f"Missing required field.*{missing_field}"
        ):
            Event.from_dict(bad_data)

    def test_event_validates_severities(self) -> None:
        """Event normalizes supported severities and rejects unsupported ones."""
        for sev in VALID_SEVERITIES:
            data = dict(SAMPLE_MINIMAL_EVENT_DICT)
            data["severity"] = sev.upper()  # Case normalization
            event = Event.from_dict(data)
            assert event.severity == sev.lower()

        bad_data = dict(SAMPLE_MINIMAL_EVENT_DICT)
        bad_data["severity"] = "disaster"
        with pytest.raises(ValidationError, match="Invalid severity 'disaster'"):
            Event.from_dict(bad_data)

    def test_event_validates_uuid_fields(self) -> None:
        """Event validates id, host_id, and process_id UUID formats."""
        bad_data = dict(SAMPLE_MINIMAL_EVENT_DICT)
        bad_data["id"] = "not-a-valid-uuid"
        with pytest.raises(ValidationError, match="Field 'id' must be a valid UUID"):
            Event.from_dict(bad_data)

        bad_data2 = dict(SAMPLE_MINIMAL_EVENT_DICT)
        bad_data2["host_id"] = "not-a-valid-uuid"
        with pytest.raises(
            ValidationError, match="Field 'host_id' must be a valid UUID"
        ):
            Event.from_dict(bad_data2)

        bad_data3 = dict(SAMPLE_MINIMAL_EVENT_DICT)
        bad_data3["process_id"] = "not-a-valid-uuid"
        with pytest.raises(
            ValidationError, match="Field 'process_id' must be a valid UUID"
        ):
            Event.from_dict(bad_data3)

    def test_event_validates_timestamp_formats(self) -> None:
        """Event validates ISO 8601 timestamp representations."""
        bad_data = dict(SAMPLE_MINIMAL_EVENT_DICT)
        bad_data["timestamp"] = "invalid-date-string"
        with pytest.raises(
            ValidationError, match="Field 'timestamp' must be a valid ISO 8601"
        ):
            Event.from_dict(bad_data)

    def test_event_validates_integer_fields(self) -> None:
        """Event rejects negative integers or booleans for uid, pid, ppid."""
        bad_data = dict(SAMPLE_MINIMAL_EVENT_DICT)
        bad_data["pid"] = -1
        with pytest.raises(
            ValidationError, match="Field 'pid' must be a non-negative integer"
        ):
            Event.from_dict(bad_data)

        bad_data["pid"] = True  # bool is subclass of int in Python
        with pytest.raises(
            ValidationError, match="Field 'pid' must be a non-negative integer"
        ):
            Event.from_dict(bad_data)

    def test_event_supports_pid_zero(self) -> None:
        """PID 0 (idle/swapper) is valid and preserved."""
        data = dict(SAMPLE_MINIMAL_EVENT_DICT)
        data["pid"] = 0
        event = Event.from_dict(data)
        assert event.pid == 0

    def test_event_collection_from_dict_success(self) -> None:
        """EventCollection parses collection payload and pagination metadata."""
        col = EventCollection.from_dict(SAMPLE_COLLECTION_DICT)
        assert col.total == 1
        assert len(col.items) == 1
        assert col.limit == 50
        assert col.offset == 0
        assert col.items[0].id == SAMPLE_EVENT_ID

    def test_event_collection_empty(self) -> None:
        """EventCollection parses empty results with total 0."""
        empty_data = {"total": 0, "items": [], "limit": 50, "offset": 0}
        col = EventCollection.from_dict(empty_data)
        assert col.total == 0
        assert col.items == ()
        assert col.limit == 50
        assert col.offset == 0

    @pytest.mark.parametrize(
        "bad_col, err_match",
        [
            ("not a dict", "Expected JSON object"),
            (
                {"items": [], "limit": 50, "offset": 0},
                "Missing required field.*total",
            ),
            (
                {"total": -1, "items": [], "limit": 50, "offset": 0},
                "non-negative integer",
            ),
            (
                {"total": 0, "items": [], "limit": 0, "offset": 0},
                "positive integer",
            ),
            (
                {"total": 0, "items": [], "limit": 50, "offset": -1},
                "non-negative integer",
            ),
            (
                {"total": 0, "items": "not a list", "limit": 50, "offset": 0},
                "must be a list",
            ),
        ],
    )
    def test_event_collection_validation_errors(
        self, bad_col: object, err_match: str
    ) -> None:
        """EventCollection rejects malformed shapes and invalid metadata."""
        with pytest.raises(ValidationError, match=err_match):
            EventCollection.from_dict(bad_col)


# ==============================================================================
# B. APIClient.get_events() Tests
# ==============================================================================


class TestGetEventsEndpoint:
    """Tests for APIClient.get_events()."""

    @respx.mock
    def test_get_events_success_default_pagination(self) -> None:
        """get_events() sends authenticated GET request with default limit & offset."""
        route = respx.get("http://127.0.0.1:8001/api/events").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()
        events = client.get_events()

        assert route.called
        req = route.calls.last.request
        assert req.headers["Authorization"] == "Bearer test.secret.bearer.token"
        assert req.url.query.decode() == "limit=50&offset=0"
        assert events.total == 1
        assert len(events.items) == 1
        assert events.items[0].id == SAMPLE_EVENT_ID
        client.close()

    @respx.mock
    def test_get_events_custom_pagination(self) -> None:
        """get_events() passes custom limit and offset."""
        route = respx.get("http://127.0.0.1:8001/api/events").respond(
            status_code=200,
            json={"total": 100, "items": [], "limit": 20, "offset": 40},
        )

        client = _authenticated_client()
        events = client.get_events(limit=20, offset=40)

        assert route.called
        req = route.calls.last.request
        assert "limit=20" in req.url.query.decode()
        assert "offset=40" in req.url.query.decode()
        assert events.limit == 20
        assert events.offset == 40
        client.close()

    @respx.mock
    def test_get_events_all_filters(self) -> None:
        """get_events() correctly encodes all supported backend filters."""
        route = respx.get("http://127.0.0.1:8001/api/events").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()
        client.get_events(
            host_id=SAMPLE_HOST_ID,
            start_time="2026-03-01T12:00:00Z",
            end_time="2026-03-01T12:30:00Z",
            source="proc",
            event_type="process.start",
            severity="INFO",
            process_id=SAMPLE_PROCESS_ID,
            pid=0,  # Ensure zero is preserved
            limit=10,
            offset=5,
        )

        assert route.called
        req = route.calls.last.request
        query = req.url.query.decode()
        assert f"host_id={SAMPLE_HOST_ID}" in query
        assert (
            "start_time=2026-03-01T12%3A00%3A00Z" in query
            or "start_time=2026-03-01T12:00:00Z" in query
        )
        assert "source=proc" in query
        assert "event_type=process.start" in query
        assert "severity=info" in query
        assert f"process_id={SAMPLE_PROCESS_ID}" in query
        assert "pid=0" in query
        assert "limit=10" in query
        assert "offset=5" in query
        client.close()

    @respx.mock
    def test_get_events_with_datetime_objects(self) -> None:
        """get_events() accepts datetime objects and converts to ISO strings."""
        route = respx.get("http://127.0.0.1:8001/api/events").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        dt_start = datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc)
        dt_end = datetime(2026, 3, 1, 11, 0, 0, tzinfo=timezone.utc)

        client = _authenticated_client()
        client.get_events(start_time=dt_start, end_time=dt_end)

        assert route.called
        query = route.calls.last.request.url.query.decode()
        assert "2026-03-01T10%3A00%3A00" in query or "2026-03-01T10:00:00" in query
        assert "2026-03-01T11%3A00%3A00" in query or "2026-03-01T11:00:00" in query
        client.close()

    def test_get_events_rejects_reversed_time_range(self) -> None:
        """get_events() rejects start_time > end_time before making request."""
        client = _authenticated_client()
        with pytest.raises(
            ValidationError, match="start_time must be less than or equal to end_time"
        ):
            client.get_events(
                start_time="2026-03-02T00:00:00Z",
                end_time="2026-03-01T00:00:00Z",
            )
        client.close()

    @pytest.mark.parametrize(
        "limit_val",
        [0, -1, 101, "50", 1.5, True],
    )
    def test_get_events_rejects_invalid_limit(self, limit_val: object) -> None:
        """get_events() validates limit is integer between 1 and 100."""
        client = _authenticated_client()
        with pytest.raises(
            ValidationError, match="limit must be an integer between 1 and 100"
        ):
            client.get_events(limit=limit_val)  # type: ignore[arg-type]
        client.close()

    @pytest.mark.parametrize(
        "offset_val",
        [-1, "0", 1.5, True],
    )
    def test_get_events_rejects_invalid_offset(self, offset_val: object) -> None:
        """get_events() validates offset is non-negative integer."""
        client = _authenticated_client()
        with pytest.raises(
            ValidationError, match="offset must be a non-negative integer"
        ):
            client.get_events(offset=offset_val)  # type: ignore[arg-type]
        client.close()

    def test_get_events_requires_authentication(self) -> None:
        """get_events() raises AuthenticationError if client has no token."""
        client = APIClient(base_url="http://127.0.0.1:8001")
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.get_events()
        client.close()

    @respx.mock
    def test_get_events_401_clears_token(self) -> None:
        """HTTP 401 from /api/events clears token and raises AuthenticationError."""
        respx.get("http://127.0.0.1:8001/api/events").respond(
            status_code=401,
            json={"detail": "Token expired"},
        )

        client = _authenticated_client()
        assert client.is_authenticated is True

        with pytest.raises(AuthenticationError, match="Token expired"):
            client.get_events()

        assert client.is_authenticated is False
        client.close()

    @respx.mock
    def test_get_events_403_preserves_token(self) -> None:
        """HTTP 403 raises AuthorizationError without clearing token."""
        respx.get("http://127.0.0.1:8001/api/events").respond(
            status_code=403,
            json={"detail": "Insufficient permissions"},
        )

        client = _authenticated_client()
        with pytest.raises(AuthorizationError, match="Insufficient permissions"):
            client.get_events()

        assert client.is_authenticated is True
        client.close()


# ==============================================================================
# C. APIClient.get_event() Tests
# ==============================================================================


class TestGetEventEndpoint:
    """Tests for APIClient.get_event()."""

    @respx.mock
    def test_get_event_success_with_uuid_str(self) -> None:
        """get_event() retrieves event by UUID string."""
        route = respx.get(
            f"http://127.0.0.1:8001/api/events/{SAMPLE_EVENT_ID}"
        ).respond(
            status_code=200,
            json=SAMPLE_EVENT_DICT,
        )

        client = _authenticated_client()
        event = client.get_event(SAMPLE_EVENT_ID)

        assert route.called
        req = route.calls.last.request
        assert req.headers["Authorization"] == "Bearer test.secret.bearer.token"
        assert event.id == SAMPLE_EVENT_ID
        assert event.event_type == "process.start"
        client.close()

    @respx.mock
    def test_get_event_success_with_uuid_object(self) -> None:
        """get_event() accepts a uuid.UUID instance."""
        event_uuid = uuid.UUID(SAMPLE_EVENT_ID)
        route = respx.get(
            f"http://127.0.0.1:8001/api/events/{SAMPLE_EVENT_ID}"
        ).respond(
            status_code=200,
            json=SAMPLE_EVENT_DICT,
        )

        client = _authenticated_client()
        event = client.get_event(event_uuid)

        assert route.called
        assert event.id == SAMPLE_EVENT_ID
        client.close()

    def test_get_event_rejects_invalid_uuid(self) -> None:
        """get_event() rejects malformed UUID string before issuing request."""
        client = _authenticated_client()
        with pytest.raises(ValidationError, match="Invalid event_id UUID"):
            client.get_event("invalid-not-a-uuid")
        client.close()

    def test_get_event_requires_authentication(self) -> None:
        """get_event() raises AuthenticationError if unauthenticated."""
        client = APIClient(base_url="http://127.0.0.1:8001")
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.get_event(SAMPLE_EVENT_ID)
        client.close()

    @respx.mock
    def test_get_event_not_found_404(self) -> None:
        """HTTP 404 raises HTTPResponseError with status_code=404."""
        nonexistent_id = "99999999-9999-4999-8999-999999999999"
        respx.get(
            f"http://127.0.0.1:8001/api/events/{nonexistent_id}"
        ).respond(
            status_code=404,
            json={"detail": "Event not found"},
        )

        client = _authenticated_client()
        with pytest.raises(HTTPResponseError) as exc_info:
            client.get_event(nonexistent_id)

        assert exc_info.value.status_code == 404
        assert "Event not found" in str(exc_info.value)
        client.close()

    @respx.mock
    def test_get_event_malformed_json_response(self) -> None:
        """Malformed JSON response raises ValidationError."""
        respx.get(
            f"http://127.0.0.1:8001/api/events/{SAMPLE_EVENT_ID}"
        ).respond(
            status_code=200,
            text="<html>Not JSON</html>",
            headers={"Content-Type": "text/html"},
        )

        client = _authenticated_client()
        with pytest.raises(ValidationError, match="not valid JSON"):
            client.get_event(SAMPLE_EVENT_ID)
        client.close()


# ==============================================================================
# D. Transport & Security Regressions
# ==============================================================================


class TestEventsTransportAndSecurity:
    """Tests error sanitization, timeout, and network failures."""

    @respx.mock
    def test_get_events_timeout_maps_to_connection_timeout_error(self) -> None:
        """Timeout mapping preserved for event endpoints."""
        respx.get("http://127.0.0.1:8001/api/events").mock(
            side_effect=httpx.TimeoutException("Read timeout")
        )

        client = _authenticated_client()
        with pytest.raises(ConnectionTimeoutError, match="timed out"):
            client.get_events()
        client.close()

    @respx.mock
    def test_get_events_network_error_maps_to_client_connection_error(self) -> None:
        """Network error mapping preserved for event endpoints."""
        respx.get("http://127.0.0.1:8001/api/events").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        client = _authenticated_client()
        with pytest.raises(ClientConnectionError, match="connection failure"):
            client.get_events()
        client.close()

    def test_client_init_does_not_issue_requests(self) -> None:
        """Instantiating APIClient does not perform network operations."""
        client = APIClient(base_url="http://127.0.0.1:8001")
        assert client.is_authenticated is False
        assert client.base_url == "http://127.0.0.1:8001"
        client.close()
