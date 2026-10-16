"""Tests for OSIRIS Desktop authenticated processes REST API client.

Covers:
A. Process and ProcessCollection model validation and error handling.
B. APIClient.get_processes() listing, filtering, and pagination.
C. APIClient.get_process() single process retrieval.
D. Security, authentication lifecycle, and transport exception regressions.
"""

from __future__ import annotations

import dataclasses
import uuid
from typing import Any

import httpx
import pytest
import respx

from desktop.client import (
    APIClient,
    AuthenticationError,
    AuthorizationError,
    ClientConnectionError,
    ConnectionTimeoutError,
    Event,
    EventCollection,
    HTTPResponseError,
    OSIRISClientError,
    Process,
    ProcessCollection,
    ValidationError,
)

# Representative test UUIDs and timestamps
SAMPLE_PROCESS_ID = "11111111-1111-4111-8111-111111111111"
SAMPLE_HOST_ID = "22222222-2222-4222-8222-222222222222"
SAMPLE_LINUX_USER_ID = "33333333-3333-4333-8333-333333333333"
SAMPLE_STARTED_AT = "2026-03-01T10:00:00Z"
SAMPLE_ENDED_AT = "2026-03-01T10:15:00Z"
SAMPLE_CREATED_AT = "2026-03-01T10:00:00Z"

SAMPLE_ACTIVE_PROCESS_DICT: dict[str, Any] = {
    "id": SAMPLE_PROCESS_ID,
    "host_id": SAMPLE_HOST_ID,
    "pid": 1001,
    "ppid": 1,
    "command": "/usr/bin/python worker.py",
    "executable": "/usr/bin/python",
    "linux_user_id": SAMPLE_LINUX_USER_ID,
    "started_at": SAMPLE_STARTED_AT,
    "ended_at": None,
    "created_at": SAMPLE_CREATED_AT,
}

SAMPLE_TERMINATED_PROCESS_DICT: dict[str, Any] = {
    "id": SAMPLE_PROCESS_ID,
    "host_id": SAMPLE_HOST_ID,
    "pid": 500,
    "ppid": 0,
    "command": "ls -la /tmp",
    "executable": "/bin/ls",
    "linux_user_id": None,
    "started_at": SAMPLE_STARTED_AT,
    "ended_at": SAMPLE_ENDED_AT,
    "created_at": SAMPLE_CREATED_AT,
}

SAMPLE_MINIMAL_PROCESS_DICT: dict[str, Any] = {
    "id": SAMPLE_PROCESS_ID,
    "host_id": SAMPLE_HOST_ID,
    "pid": 0,
    "command": "idle_worker",
    "started_at": SAMPLE_STARTED_AT,
    "created_at": SAMPLE_CREATED_AT,
}

SAMPLE_PROCESS_COLLECTION_DICT: dict[str, Any] = {
    "total": 1,
    "items": [SAMPLE_ACTIVE_PROCESS_DICT],
    "limit": 50,
    "offset": 0,
}


def _authenticated_client() -> APIClient:
    """Return an APIClient initialized with an in-memory session token."""
    client = APIClient(base_url="http://127.0.0.1:8001")
    client._token = "test.secret.bearer.token"
    return client


# ==============================================================================
# A. Process & ProcessCollection Model Tests
# ==============================================================================


class TestProcessModel:
    """Tests for Process and ProcessCollection dataclasses."""

    def test_process_from_dict_active(self) -> None:
        """Process correctly parses active process with ended_at=None."""
        proc = Process.from_dict(SAMPLE_ACTIVE_PROCESS_DICT)
        assert proc.id == SAMPLE_PROCESS_ID
        assert proc.host_id == SAMPLE_HOST_ID
        assert proc.pid == 1001
        assert proc.ppid == 1
        assert proc.command == "/usr/bin/python worker.py"
        assert proc.executable == "/usr/bin/python"
        assert proc.linux_user_id == SAMPLE_LINUX_USER_ID
        assert proc.started_at == SAMPLE_STARTED_AT
        assert proc.ended_at is None
        assert proc.created_at == SAMPLE_CREATED_AT
        assert proc.is_active is True

    def test_process_from_dict_terminated(self) -> None:
        """Process correctly parses terminated process with ended_at set."""
        proc = Process.from_dict(SAMPLE_TERMINATED_PROCESS_DICT)
        assert proc.id == SAMPLE_PROCESS_ID
        assert proc.host_id == SAMPLE_HOST_ID
        assert proc.pid == 500
        assert proc.ppid == 0
        assert proc.command == "ls -la /tmp"
        assert proc.executable == "/bin/ls"
        assert proc.linux_user_id is None
        assert proc.started_at == SAMPLE_STARTED_AT
        assert proc.ended_at == SAMPLE_ENDED_AT
        assert proc.created_at == SAMPLE_CREATED_AT
        assert proc.is_active is False

    def test_process_from_dict_minimal(self) -> None:
        """Process handles missing nullable fields with None defaults."""
        proc = Process.from_dict(SAMPLE_MINIMAL_PROCESS_DICT)
        assert proc.id == SAMPLE_PROCESS_ID
        assert proc.host_id == SAMPLE_HOST_ID
        assert proc.pid == 0
        assert proc.command == "idle_worker"
        assert proc.ppid is None
        assert proc.executable is None
        assert proc.linux_user_id is None
        assert proc.ended_at is None
        assert proc.is_active is True

    def test_process_pid_and_ppid_zero_preserved(self) -> None:
        """PID 0 and PPID 0 are valid and preserved."""
        data = dict(SAMPLE_MINIMAL_PROCESS_DICT)
        data["pid"] = 0
        data["ppid"] = 0
        proc = Process.from_dict(data)
        assert proc.pid == 0
        assert proc.ppid == 0

    def test_process_to_dict_roundtrip(self) -> None:
        """Process.to_dict converts dataclass to standard dictionary."""
        proc = Process.from_dict(SAMPLE_ACTIVE_PROCESS_DICT)
        d = proc.to_dict()
        assert isinstance(d, dict)
        assert d["id"] == SAMPLE_PROCESS_ID
        assert d["pid"] == 1001
        assert d["command"] == "/usr/bin/python worker.py"
        assert d["ended_at"] is None
        assert "is_active" not in d

    def test_process_rejects_non_dict(self) -> None:
        """Process.from_dict rejects non-dictionary data."""
        with pytest.raises(ValidationError, match="Expected JSON object"):
            Process.from_dict(["not", "a", "dict"])

    @pytest.mark.parametrize(
        "missing_field",
        [
            "id",
            "host_id",
            "pid",
            "command",
            "started_at",
            "created_at",
        ],
    )
    def test_process_rejects_missing_required_fields(
        self, missing_field: str
    ) -> None:
        """Process.from_dict rejects payloads missing any required field."""
        bad_data = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        del bad_data[missing_field]
        with pytest.raises(
            ValidationError, match=f"Missing required field.*{missing_field}"
        ):
            Process.from_dict(bad_data)

    def test_process_validates_uuid_fields(self) -> None:
        """Process validates id, host_id, and linux_user_id UUID formats."""
        bad_id = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_id["id"] = "not-a-valid-uuid"
        with pytest.raises(ValidationError, match="Field 'id' must be a valid UUID"):
            Process.from_dict(bad_id)

        bad_id_bool = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_id_bool["id"] = True
        with pytest.raises(ValidationError, match="Field 'id' must be a valid UUID"):
            Process.from_dict(bad_id_bool)

        bad_id_int = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_id_int["id"] = 123
        with pytest.raises(ValidationError, match="Field 'id' must be a valid UUID"):
            Process.from_dict(bad_id_int)

        bad_host = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_host["host_id"] = "not-a-valid-uuid"
        with pytest.raises(
            ValidationError, match="Field 'host_id' must be a valid UUID"
        ):
            Process.from_dict(bad_host)

        bad_host_bool = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_host_bool["host_id"] = False
        with pytest.raises(
            ValidationError, match="Field 'host_id' must be a valid UUID"
        ):
            Process.from_dict(bad_host_bool)

        bad_user = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_user["linux_user_id"] = "not-a-valid-uuid"
        with pytest.raises(
            ValidationError, match="Field 'linux_user_id' must be a valid UUID"
        ):
            Process.from_dict(bad_user)

        bad_user_bool = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_user_bool["linux_user_id"] = True
        with pytest.raises(
            ValidationError, match="Field 'linux_user_id' must be a valid UUID"
        ):
            Process.from_dict(bad_user_bool)

        bad_user_int = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_user_int["linux_user_id"] = 1000
        with pytest.raises(
            ValidationError, match="Field 'linux_user_id' must be a valid UUID"
        ):
            Process.from_dict(bad_user_int)

    def test_process_from_dict_with_uuid_instances(self) -> None:
        """Process parses id, host_id, and linux_user_id as uuid.UUID objects."""
        data = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        data["id"] = uuid.UUID(SAMPLE_PROCESS_ID)
        data["host_id"] = uuid.UUID(SAMPLE_HOST_ID)
        data["linux_user_id"] = uuid.UUID(SAMPLE_LINUX_USER_ID)
        proc = Process.from_dict(data)
        assert proc.id == SAMPLE_PROCESS_ID
        assert proc.host_id == SAMPLE_HOST_ID
        assert proc.linux_user_id == SAMPLE_LINUX_USER_ID

    def test_process_validates_timestamp_formats(self) -> None:
        """Process validates ISO 8601 timestamp representations."""
        bad_start = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_start["started_at"] = "invalid-date-string"
        with pytest.raises(
            ValidationError, match="Field 'started_at' must be a valid ISO 8601"
        ):
            Process.from_dict(bad_start)

        bad_start_empty = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_start_empty["started_at"] = "   "
        with pytest.raises(
            ValidationError, match="Field 'started_at' must be a non-empty ISO 8601"
        ):
            Process.from_dict(bad_start_empty)

        bad_start_bool = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_start_bool["started_at"] = True
        with pytest.raises(
            ValidationError, match="Field 'started_at' must be a non-empty ISO 8601"
        ):
            Process.from_dict(bad_start_bool)

        bad_end = dict(SAMPLE_TERMINATED_PROCESS_DICT)
        bad_end["ended_at"] = "invalid-date-string"
        with pytest.raises(
            ValidationError, match="Field 'ended_at' must be a valid ISO 8601"
        ):
            Process.from_dict(bad_end)

        bad_end_bool = dict(SAMPLE_TERMINATED_PROCESS_DICT)
        bad_end_bool["ended_at"] = False
        with pytest.raises(
            ValidationError, match="Field 'ended_at' must be an ISO 8601 string or None"
        ):
            Process.from_dict(bad_end_bool)

        bad_end_ws = dict(SAMPLE_TERMINATED_PROCESS_DICT)
        bad_end_ws["ended_at"] = "   "
        with pytest.raises(
            ValidationError, match="Field 'ended_at' must be an ISO 8601 string or None"
        ):
            Process.from_dict(bad_end_ws)

        bad_created = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_created["created_at"] = "invalid-date-string"
        with pytest.raises(
            ValidationError, match="Field 'created_at' must be a valid ISO 8601"
        ):
            Process.from_dict(bad_created)

        bad_created_bool = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_created_bool["created_at"] = True
        with pytest.raises(
            ValidationError, match="Field 'created_at' must be a non-empty ISO 8601"
        ):
            Process.from_dict(bad_created_bool)

    def test_process_validates_integer_fields(self) -> None:
        """Process rejects negative numbers, floats, strings, or booleans."""
        bad_pid_neg = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_pid_neg["pid"] = -1
        with pytest.raises(
            ValidationError, match="Field 'pid' must be a non-negative integer"
        ):
            Process.from_dict(bad_pid_neg)

        bad_pid_bool = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_pid_bool["pid"] = True
        with pytest.raises(
            ValidationError, match="Field 'pid' must be a non-negative integer"
        ):
            Process.from_dict(bad_pid_bool)

        bad_pid_float = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_pid_float["pid"] = 1.5
        with pytest.raises(
            ValidationError, match="Field 'pid' must be a non-negative integer"
        ):
            Process.from_dict(bad_pid_float)

        bad_pid_str = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_pid_str["pid"] = "100"
        with pytest.raises(
            ValidationError, match="Field 'pid' must be a non-negative integer"
        ):
            Process.from_dict(bad_pid_str)

        bad_ppid_neg = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_ppid_neg["ppid"] = -5
        with pytest.raises(
            ValidationError, match="Field 'ppid' must be a non-negative integer"
        ):
            Process.from_dict(bad_ppid_neg)

        bad_ppid_bool = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_ppid_bool["ppid"] = False
        with pytest.raises(
            ValidationError, match="Field 'ppid' must be a non-negative integer"
        ):
            Process.from_dict(bad_ppid_bool)

        bad_ppid_float = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_ppid_float["ppid"] = 2.5
        with pytest.raises(
            ValidationError, match="Field 'ppid' must be a non-negative integer"
        ):
            Process.from_dict(bad_ppid_float)

        bad_ppid_str = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_ppid_str["ppid"] = "1"
        with pytest.raises(
            ValidationError, match="Field 'ppid' must be a non-negative integer"
        ):
            Process.from_dict(bad_ppid_str)

    def test_process_validates_string_fields(self) -> None:
        """Process rejects invalid string types or empty required strings."""
        bad_cmd_empty = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_cmd_empty["command"] = ""
        with pytest.raises(
            ValidationError, match="Field 'command' must be a non-empty string"
        ):
            Process.from_dict(bad_cmd_empty)

        bad_cmd_ws = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_cmd_ws["command"] = "   "
        with pytest.raises(
            ValidationError, match="Field 'command' must be a non-empty string"
        ):
            Process.from_dict(bad_cmd_ws)

        bad_cmd_bool = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_cmd_bool["command"] = True
        with pytest.raises(
            ValidationError, match="Field 'command' must be a non-empty string"
        ):
            Process.from_dict(bad_cmd_bool)

        bad_cmd_type = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_cmd_type["command"] = 12345
        with pytest.raises(
            ValidationError, match="Field 'command' must be a non-empty string"
        ):
            Process.from_dict(bad_cmd_type)

        bad_exe = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_exe["executable"] = 12345
        with pytest.raises(
            ValidationError, match="Field 'executable' must be a string or None"
        ):
            Process.from_dict(bad_exe)

        bad_exe_bool = dict(SAMPLE_ACTIVE_PROCESS_DICT)
        bad_exe_bool["executable"] = True
        with pytest.raises(
            ValidationError, match="Field 'executable' must be a string or None"
        ):
            Process.from_dict(bad_exe_bool)

    def test_process_frozen_immutability(self) -> None:
        """Process instances are frozen dataclasses and cannot be modified."""
        proc = Process.from_dict(SAMPLE_ACTIVE_PROCESS_DICT)
        with pytest.raises(dataclasses.FrozenInstanceError):
            proc.command = "/bin/bash"  # type: ignore[misc]

    def test_process_collection_from_dict_success(self) -> None:
        """ProcessCollection parses collection payload and pagination metadata."""
        col = ProcessCollection.from_dict(SAMPLE_PROCESS_COLLECTION_DICT)
        assert col.total == 1
        assert len(col.items) == 1
        assert col.limit == 50
        assert col.offset == 0
        assert col.items[0].id == SAMPLE_PROCESS_ID

    def test_process_collection_empty(self) -> None:
        """ProcessCollection parses empty results with total 0."""
        empty_data = {"total": 0, "items": [], "limit": 50, "offset": 0}
        col = ProcessCollection.from_dict(empty_data)
        assert col.total == 0
        assert col.items == ()
        assert col.limit == 50
        assert col.offset == 0

    def test_process_collection_to_dict(self) -> None:
        """ProcessCollection.to_dict converts collection to standard dictionary."""
        col = ProcessCollection.from_dict(SAMPLE_PROCESS_COLLECTION_DICT)
        d = col.to_dict()
        assert isinstance(d, dict)
        assert d["total"] == 1
        assert len(d["items"]) == 1
        assert d["items"][0]["id"] == SAMPLE_PROCESS_ID

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
                {"total": True, "items": [], "limit": 50, "offset": 0},
                "non-negative integer",
            ),
            (
                {"total": 0, "items": [], "limit": 0, "offset": 0},
                "positive integer",
            ),
            (
                {"total": 0, "items": [], "limit": True, "offset": 0},
                "positive integer",
            ),
            (
                {"total": 0, "items": [], "limit": 50, "offset": -1},
                "non-negative integer",
            ),
            (
                {"total": 0, "items": [], "limit": 50, "offset": False},
                "non-negative integer",
            ),
            (
                {"total": 0, "items": "not a list", "limit": 50, "offset": 0},
                "must be a list",
            ),
            (
                {"total": 0, "items": {}, "limit": 50, "offset": 0},
                "must be a list",
            ),
            (
                {"total": 1, "items": [123], "limit": 50, "offset": 0},
                "Expected JSON object for process",
            ),
            (
                {"total": 1, "items": [None], "limit": 50, "offset": 0},
                "Expected JSON object for process",
            ),
        ],
    )
    def test_process_collection_validation_errors(
        self, bad_col: object, err_match: str
    ) -> None:
        """ProcessCollection rejects malformed shapes and invalid metadata."""
        with pytest.raises(ValidationError, match=err_match):
            ProcessCollection.from_dict(bad_col)

    def test_process_collection_rejects_invalid_item_in_list(self) -> None:
        """ProcessCollection rejects payloads containing invalid process items."""
        bad_data = {
            "total": 1,
            "items": [{"id": "not-a-valid-process"}],
            "limit": 50,
            "offset": 0,
        }
        with pytest.raises(ValidationError):
            ProcessCollection.from_dict(bad_data)


# ==============================================================================
# B. APIClient.get_processes() Tests
# ==============================================================================


class TestGetProcessesEndpoint:
    """Tests for APIClient.get_processes()."""

    @respx.mock
    def test_get_processes_success_default_pagination(self) -> None:
        """get_processes() sends authenticated request with default pagination."""
        route = respx.get("http://127.0.0.1:8001/api/processes").respond(
            status_code=200,
            json=SAMPLE_PROCESS_COLLECTION_DICT,
        )

        client = _authenticated_client()
        processes = client.get_processes()

        assert route.called
        req = route.calls.last.request
        assert req.headers["Authorization"] == "Bearer test.secret.bearer.token"
        assert req.url.query.decode() == "limit=50&offset=0"
        assert processes.total == 1
        assert len(processes.items) == 1
        assert processes.items[0].id == SAMPLE_PROCESS_ID
        assert processes.items[0].is_active is True
        client.close()

    @respx.mock
    def test_get_processes_custom_pagination(self) -> None:
        """get_processes() passes custom limit and offset."""
        route = respx.get("http://127.0.0.1:8001/api/processes").respond(
            status_code=200,
            json={"total": 100, "items": [], "limit": 20, "offset": 40},
        )

        client = _authenticated_client()
        processes = client.get_processes(limit=20, offset=40)

        assert route.called
        req = route.calls.last.request
        assert "limit=20" in req.url.query.decode()
        assert "offset=40" in req.url.query.decode()
        assert processes.limit == 20
        assert processes.offset == 40
        client.close()

    @respx.mock
    def test_get_processes_all_filters(self) -> None:
        """get_processes() correctly encodes all supported backend filters."""
        route = respx.get("http://127.0.0.1:8001/api/processes").respond(
            status_code=200,
            json=SAMPLE_PROCESS_COLLECTION_DICT,
        )

        client = _authenticated_client()
        client.get_processes(
            host_id=SAMPLE_HOST_ID,
            pid=500,
            is_active=True,
            limit=10,
            offset=5,
        )

        assert route.called
        req = route.calls.last.request
        query = req.url.query.decode()
        assert f"host_id={SAMPLE_HOST_ID}" in query
        assert "pid=500" in query
        assert "is_active=true" in query
        assert "limit=10" in query
        assert "offset=5" in query
        client.close()

    @respx.mock
    def test_get_processes_preserves_is_active_false(self) -> None:
        """get_processes() correctly encodes is_active=False."""
        route = respx.get("http://127.0.0.1:8001/api/processes").respond(
            status_code=200,
            json=SAMPLE_PROCESS_COLLECTION_DICT,
        )

        client = _authenticated_client()
        client.get_processes(is_active=False)

        assert route.called
        query = route.calls.last.request.url.query.decode()
        assert "is_active=false" in query
        client.close()

    @respx.mock
    def test_get_processes_preserves_pid_zero(self) -> None:
        """get_processes() preserves pid=0 in query parameters."""
        route = respx.get("http://127.0.0.1:8001/api/processes").respond(
            status_code=200,
            json=SAMPLE_PROCESS_COLLECTION_DICT,
        )

        client = _authenticated_client()
        client.get_processes(pid=0)

        assert route.called
        query = route.calls.last.request.url.query.decode()
        assert "pid=0" in query
        client.close()

    @respx.mock
    def test_get_processes_omits_unset_optional_filters(self) -> None:
        """get_processes() omits optional filters when unset (None)."""
        route = respx.get("http://127.0.0.1:8001/api/processes").respond(
            status_code=200,
            json=SAMPLE_PROCESS_COLLECTION_DICT,
        )

        client = _authenticated_client()
        client.get_processes()

        assert route.called
        query = route.calls.last.request.url.query.decode()
        assert "host_id" not in query
        assert "pid" not in query
        assert "is_active" not in query
        assert query == "limit=50&offset=0"
        client.close()

    @pytest.mark.parametrize(
        "limit_val",
        [0, -1, 101, "50", 1.5, True, False],
    )
    def test_get_processes_rejects_invalid_limit(self, limit_val: object) -> None:
        """get_processes() validates limit is integer between 1 and 100."""
        client = _authenticated_client()
        with pytest.raises(
            ValidationError, match="limit must be an integer between 1 and 100"
        ):
            client.get_processes(limit=limit_val)  # type: ignore[arg-type]
        client.close()

    @pytest.mark.parametrize(
        "offset_val",
        [-1, "0", 1.5, True, False],
    )
    def test_get_processes_rejects_invalid_offset(self, offset_val: object) -> None:
        """get_processes() validates offset is non-negative integer."""
        client = _authenticated_client()
        with pytest.raises(
            ValidationError, match="offset must be a non-negative integer"
        ):
            client.get_processes(offset=offset_val)  # type: ignore[arg-type]
        client.close()

    @pytest.mark.parametrize(
        "pid_val",
        [-1, "0", 1.5, True, False],
    )
    def test_get_processes_rejects_invalid_pid(self, pid_val: object) -> None:
        """get_processes() validates pid is non-negative integer or None."""
        client = _authenticated_client()
        with pytest.raises(
            ValidationError, match="pid must be a non-negative integer"
        ):
            client.get_processes(pid=pid_val)  # type: ignore[arg-type]
        client.close()

    @pytest.mark.parametrize(
        "active_val",
        ["true", "false", 1, 0, 1.0],
    )
    def test_get_processes_rejects_invalid_is_active(
        self, active_val: object
    ) -> None:
        """get_processes() validates is_active is boolean or None."""
        client = _authenticated_client()
        with pytest.raises(
            ValidationError, match="is_active must be a boolean or None"
        ):
            client.get_processes(is_active=active_val)  # type: ignore[arg-type]
        client.close()

    def test_get_processes_rejects_invalid_host_id(self) -> None:
        """get_processes() validates host_id UUID."""
        client = _authenticated_client()
        with pytest.raises(ValidationError, match="Invalid host_id UUID"):
            client.get_processes(host_id="not-a-uuid")

        with pytest.raises(ValidationError, match="Invalid host_id UUID"):
            client.get_processes(host_id=True)  # type: ignore[arg-type]
        client.close()

    def test_get_processes_requires_authentication(self) -> None:
        """get_processes() raises AuthenticationError if client has no token."""
        client = APIClient(base_url="http://127.0.0.1:8001")
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.get_processes()
        client.close()

    @respx.mock
    def test_get_processes_401_clears_token(self) -> None:
        """HTTP 401 from /api/processes clears token and raises AuthenticationError."""
        respx.get("http://127.0.0.1:8001/api/processes").respond(
            status_code=401,
            json={"detail": "Token expired"},
        )

        client = _authenticated_client()
        assert client.is_authenticated is True

        with pytest.raises(AuthenticationError, match="Token expired"):
            client.get_processes()

        assert client.is_authenticated is False
        client.close()

    @respx.mock
    def test_get_processes_403_preserves_token(self) -> None:
        """HTTP 403 raises AuthorizationError without clearing token."""
        respx.get("http://127.0.0.1:8001/api/processes").respond(
            status_code=403,
            json={"detail": "Insufficient permissions"},
        )

        client = _authenticated_client()
        with pytest.raises(AuthorizationError, match="Insufficient permissions"):
            client.get_processes()

        assert client.is_authenticated is True
        client.close()

    @respx.mock
    def test_get_processes_timeout_maps_to_connection_timeout_error(self) -> None:
        """Timeout mapping preserved for get_processes."""
        respx.get("http://127.0.0.1:8001/api/processes").mock(
            side_effect=httpx.TimeoutException("Read timeout")
        )

        client = _authenticated_client()
        with pytest.raises(ConnectionTimeoutError, match="timed out"):
            client.get_processes()
        client.close()

    @respx.mock
    def test_get_processes_network_error_maps_to_client_connection_error(
        self,
    ) -> None:
        """Network error mapping preserved for get_processes."""
        respx.get("http://127.0.0.1:8001/api/processes").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        client = _authenticated_client()
        with pytest.raises(ClientConnectionError, match="connection failure"):
            client.get_processes()
        client.close()

    @respx.mock
    def test_get_processes_malformed_json_response(self) -> None:
        """Malformed JSON response raises ValidationError."""
        respx.get("http://127.0.0.1:8001/api/processes").respond(
            status_code=200,
            text="<html>Not JSON</html>",
            headers={"Content-Type": "text/html"},
        )

        client = _authenticated_client()
        with pytest.raises(ValidationError, match="not valid JSON"):
            client.get_processes()
        client.close()

    @respx.mock
    def test_get_processes_boundary_limits(self) -> None:
        """get_processes() accepts valid limit boundaries (1 and 100)."""
        route = respx.get("http://127.0.0.1:8001/api/processes").respond(
            status_code=200,
            json=SAMPLE_PROCESS_COLLECTION_DICT,
        )

        client = _authenticated_client()
        client.get_processes(limit=1, offset=0)
        assert "limit=1&offset=0" in route.calls.last.request.url.query.decode()

        client.get_processes(limit=100, offset=1000)
        assert "limit=100&offset=1000" in route.calls.last.request.url.query.decode()
        client.close()

    @respx.mock
    def test_get_processes_with_uuid_host_id_instance(self) -> None:
        """get_processes() correctly stringifies a uuid.UUID host_id instance."""
        route = respx.get("http://127.0.0.1:8001/api/processes").respond(
            status_code=200,
            json=SAMPLE_PROCESS_COLLECTION_DICT,
        )

        client = _authenticated_client()
        client.get_processes(host_id=uuid.UUID(SAMPLE_HOST_ID))
        assert (
            f"host_id={SAMPLE_HOST_ID}"
            in route.calls.last.request.url.query.decode()
        )
        client.close()

    @respx.mock
    def test_get_processes_combined_pid_zero_and_active_false(self) -> None:
        """get_processes() preserves pid=0 and is_active=false when combined."""
        route = respx.get("http://127.0.0.1:8001/api/processes").respond(
            status_code=200,
            json=SAMPLE_PROCESS_COLLECTION_DICT,
        )

        client = _authenticated_client()
        client.get_processes(pid=0, is_active=False)
        query = route.calls.last.request.url.query.decode()
        assert "pid=0" in query
        assert "is_active=false" in query
        client.close()

    def test_get_processes_closed_client_raises(self) -> None:
        """Calling get_processes() on closed client raises OSIRISClientError."""
        client = _authenticated_client()
        client.close()
        with pytest.raises(OSIRISClientError, match="APIClient is closed"):
            client.get_processes()


# ==============================================================================
# C. APIClient.get_process() Tests
# ==============================================================================


class TestGetProcessEndpoint:
    """Tests for APIClient.get_process()."""

    @respx.mock
    def test_get_process_success_with_uuid_str(self) -> None:
        """get_process() retrieves process by UUID string."""
        route = respx.get(
            f"http://127.0.0.1:8001/api/processes/{SAMPLE_PROCESS_ID}"
        ).respond(
            status_code=200,
            json=SAMPLE_ACTIVE_PROCESS_DICT,
        )

        client = _authenticated_client()
        proc = client.get_process(SAMPLE_PROCESS_ID)

        assert route.called
        req = route.calls.last.request
        assert req.headers["Authorization"] == "Bearer test.secret.bearer.token"
        assert proc.id == SAMPLE_PROCESS_ID
        assert proc.pid == 1001
        assert proc.command == "/usr/bin/python worker.py"
        assert proc.is_active is True
        client.close()

    @respx.mock
    def test_get_process_success_with_uuid_object(self) -> None:
        """get_process() accepts a uuid.UUID instance."""
        proc_uuid = uuid.UUID(SAMPLE_PROCESS_ID)
        route = respx.get(
            f"http://127.0.0.1:8001/api/processes/{SAMPLE_PROCESS_ID}"
        ).respond(
            status_code=200,
            json=SAMPLE_ACTIVE_PROCESS_DICT,
        )

        client = _authenticated_client()
        proc = client.get_process(proc_uuid)

        assert route.called
        assert proc.id == SAMPLE_PROCESS_ID
        client.close()

    def test_get_process_rejects_invalid_uuid(self) -> None:
        """get_process() rejects malformed UUID string before issuing request."""
        client = _authenticated_client()
        with pytest.raises(ValidationError, match="Invalid process_id UUID"):
            client.get_process("invalid-not-a-uuid")
        client.close()

    def test_get_process_rejects_integer_pid(self) -> None:
        """Passing an integer PID instead of OSIRIS UUID fails validation."""
        client = _authenticated_client()
        with pytest.raises(ValidationError, match="Invalid process_id UUID"):
            client.get_process(500)  # type: ignore[arg-type]
        client.close()

    def test_get_process_rejects_boolean(self) -> None:
        """get_process() rejects boolean input."""
        client = _authenticated_client()
        with pytest.raises(ValidationError, match="non-empty string or UUID"):
            client.get_process(True)  # type: ignore[arg-type]
        client.close()

    def test_get_process_requires_authentication(self) -> None:
        """get_process() raises AuthenticationError if unauthenticated."""
        client = APIClient(base_url="http://127.0.0.1:8001")
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.get_process(SAMPLE_PROCESS_ID)
        client.close()

    @respx.mock
    def test_get_process_not_found_404(self) -> None:
        """HTTP 404 raises HTTPResponseError with status_code=404."""
        nonexistent_id = "99999999-9999-4999-8999-999999999999"
        respx.get(
            f"http://127.0.0.1:8001/api/processes/{nonexistent_id}"
        ).respond(
            status_code=404,
            json={"detail": "Process not found"},
        )

        client = _authenticated_client()
        with pytest.raises(HTTPResponseError) as exc_info:
            client.get_process(nonexistent_id)

        assert exc_info.value.status_code == 404
        assert "Process not found" in str(exc_info.value)
        client.close()

    @respx.mock
    def test_get_process_401_clears_token(self) -> None:
        """HTTP 401 from GET /api/processes/{id} clears token and raises."""
        respx.get(
            f"http://127.0.0.1:8001/api/processes/{SAMPLE_PROCESS_ID}"
        ).respond(
            status_code=401,
            json={"detail": "Token expired"},
        )

        client = _authenticated_client()
        with pytest.raises(AuthenticationError, match="Token expired"):
            client.get_process(SAMPLE_PROCESS_ID)

        assert client.is_authenticated is False
        client.close()

    @respx.mock
    def test_get_process_403_preserves_token(self) -> None:
        """HTTP 403 raises AuthorizationError without clearing token."""
        respx.get(
            f"http://127.0.0.1:8001/api/processes/{SAMPLE_PROCESS_ID}"
        ).respond(
            status_code=403,
            json={"detail": "Insufficient permissions"},
        )

        client = _authenticated_client()
        with pytest.raises(AuthorizationError, match="Insufficient permissions"):
            client.get_process(SAMPLE_PROCESS_ID)

        assert client.is_authenticated is True
        client.close()

    @respx.mock
    def test_get_process_timeout_maps_to_connection_timeout_error(self) -> None:
        """Timeout mapping preserved for get_process."""
        respx.get(
            f"http://127.0.0.1:8001/api/processes/{SAMPLE_PROCESS_ID}"
        ).mock(side_effect=httpx.TimeoutException("Read timeout"))

        client = _authenticated_client()
        with pytest.raises(ConnectionTimeoutError, match="timed out"):
            client.get_process(SAMPLE_PROCESS_ID)
        client.close()

    @respx.mock
    def test_get_process_network_error_maps_to_client_connection_error(
        self,
    ) -> None:
        """Network error mapping preserved for get_process."""
        respx.get(
            f"http://127.0.0.1:8001/api/processes/{SAMPLE_PROCESS_ID}"
        ).mock(side_effect=httpx.ConnectError("Connection refused"))

        client = _authenticated_client()
        with pytest.raises(ClientConnectionError, match="connection failure"):
            client.get_process(SAMPLE_PROCESS_ID)
        client.close()

    @respx.mock
    def test_get_process_malformed_json_response(self) -> None:
        """Malformed JSON response raises ValidationError."""
        respx.get(
            f"http://127.0.0.1:8001/api/processes/{SAMPLE_PROCESS_ID}"
        ).respond(
            status_code=200,
            text="<html>Not JSON</html>",
            headers={"Content-Type": "text/html"},
        )

        client = _authenticated_client()
        with pytest.raises(ValidationError, match="not valid JSON"):
            client.get_process(SAMPLE_PROCESS_ID)
        client.close()

    def test_get_process_rejects_empty_and_none(self) -> None:
        """get_process() rejects None, empty, whitespace, and boolean process_id."""
        client = _authenticated_client()
        with pytest.raises(ValidationError, match="non-empty string or UUID"):
            client.get_process(None)  # type: ignore[arg-type]

        with pytest.raises(ValidationError, match="non-empty string or UUID"):
            client.get_process("")

        with pytest.raises(ValidationError, match="non-empty string or UUID"):
            client.get_process("   ")

        with pytest.raises(ValidationError, match="non-empty string or UUID"):
            client.get_process(False)  # type: ignore[arg-type]
        client.close()

    def test_get_process_closed_client_raises(self) -> None:
        """Calling get_process() on closed client raises OSIRISClientError."""
        client = _authenticated_client()
        client.close()
        with pytest.raises(OSIRISClientError, match="APIClient is closed"):
            client.get_process(SAMPLE_PROCESS_ID)


# ==============================================================================
# D. Regression Tests
# ==============================================================================


class TestProcessesRegression:
    """Regression tests verifying existing desktop client behavior is unaffected."""

    def test_public_client_imports(self) -> None:
        """Process, ProcessCollection, and APIClient are exposed via desktop.client."""
        import desktop.client as dc

        assert hasattr(dc, "Process")
        assert hasattr(dc, "ProcessCollection")
        assert hasattr(dc, "APIClient")
        assert dc.Process is Process
        assert dc.ProcessCollection is ProcessCollection

    def test_event_models_unaffected(self) -> None:
        """Event and EventCollection models remain functional and unaltered."""
        event_dict = {
            "id": SAMPLE_PROCESS_ID,
            "host_id": SAMPLE_HOST_ID,
            "timestamp": SAMPLE_STARTED_AT,
            "ingested_at": SAMPLE_STARTED_AT,
            "source": "proc",
            "event_type": "process.start",
            "action": "start",
            "severity": "info",
            "created_at": SAMPLE_CREATED_AT,
        }
        event = Event.from_dict(event_dict)
        assert event.id == SAMPLE_PROCESS_ID
        col = EventCollection.from_dict(
            {"total": 1, "items": [event_dict], "limit": 50, "offset": 0}
        )
        assert col.total == 1
        assert len(col.items) == 1

    def test_api_client_has_process_methods(self) -> None:
        """APIClient exposes get_processes and get_process."""
        client = APIClient(base_url="http://127.0.0.1:8001")
        assert callable(getattr(client, "get_processes", None))
        assert callable(getattr(client, "get_process", None))
        client.close()
