"""Tests for OSIRIS Desktop authenticated files REST API client and data models.

Covers:
A. FileRecord and FileCollection model validation, serialization, and immutability.
B. APIClient.get_files() listing, filtering, pagination, and local argument validation.
C. Security, authentication lifecycle, transport error mappings, and regression.
"""

from __future__ import annotations

import dataclasses
import uuid
from typing import Any

import httpx
import pytest
import respx

from desktop.client import (
    VALID_FILE_TYPES,
    APIClient,
    AuthenticationError,
    AuthorizationError,
    ClientConnectionError,
    ConnectionTimeoutError,
    Event,
    File,
    FileCollection,
    FileRecord,
    FileRecordCollection,
    HTTPResponseError,
    OSIRISClientError,
    Process,
    ResourceSnapshot,
    ValidationError,
)

SAMPLE_FILE_ID = "11111111-1111-4111-8111-111111111111"
SAMPLE_HOST_ID = "22222222-2222-4222-8222-222222222222"
SAMPLE_FIRST_SEEN = "2026-03-01T09:00:00Z"
SAMPLE_LAST_SEEN = "2026-03-01T10:00:00Z"
SAMPLE_CREATED_AT = "2026-03-01T09:00:00Z"

SAMPLE_FILE_DICT: dict[str, Any] = {
    "id": SAMPLE_FILE_ID,
    "host_id": SAMPLE_HOST_ID,
    "path": "/etc/hosts",
    "inode": 123456,
    "file_type": "file",
    "first_seen_at": SAMPLE_FIRST_SEEN,
    "last_seen_at": SAMPLE_LAST_SEEN,
    "created_at": SAMPLE_CREATED_AT,
}

SAMPLE_MINIMAL_FILE_DICT: dict[str, Any] = {
    "id": SAMPLE_FILE_ID,
    "host_id": SAMPLE_HOST_ID,
    "path": "/var/log",
    "first_seen_at": SAMPLE_FIRST_SEEN,
    "created_at": SAMPLE_CREATED_AT,
}

SAMPLE_COLLECTION_DICT: dict[str, Any] = {
    "total": 1,
    "items": [SAMPLE_FILE_DICT],
    "limit": 50,
    "offset": 0,
}


def _authenticated_client() -> APIClient:
    """Return an APIClient initialized with an in-memory session token."""
    client = APIClient(base_url="http://127.0.0.1:8001")
    client._token = "test.secret.bearer.token"
    return client


# ==============================================================================
# A. FileRecord & FileCollection Model Tests
# ==============================================================================


class TestFileRecordModel:
    """Tests for FileRecord dataclass validation and serialization."""

    def test_file_record_from_dict_full(self) -> None:
        """FileRecord correctly parses all fields matching backend schema."""
        rec = FileRecord.from_dict(SAMPLE_FILE_DICT)
        assert rec.id == SAMPLE_FILE_ID
        assert rec.host_id == SAMPLE_HOST_ID
        assert rec.path == "/etc/hosts"
        assert rec.inode == 123456
        assert rec.file_type == "file"
        assert rec.first_seen_at == SAMPLE_FIRST_SEEN
        assert rec.last_seen_at == SAMPLE_LAST_SEEN
        assert rec.created_at == SAMPLE_CREATED_AT

    def test_file_record_from_dict_minimal(self) -> None:
        """FileRecord defaults nullable fields to None."""
        rec = FileRecord.from_dict(SAMPLE_MINIMAL_FILE_DICT)
        assert rec.id == SAMPLE_FILE_ID
        assert rec.host_id == SAMPLE_HOST_ID
        assert rec.path == "/var/log"
        assert rec.first_seen_at == SAMPLE_FIRST_SEEN
        assert rec.created_at == SAMPLE_CREATED_AT
        assert rec.inode is None
        assert rec.file_type is None
        assert rec.last_seen_at is None

    def test_file_record_preserves_zero_inode(self) -> None:
        """FileRecord preserves valid inode=0."""
        data = dict(SAMPLE_FILE_DICT, inode=0)
        rec = FileRecord.from_dict(data)
        assert rec.inode == 0

    def test_file_record_to_dict_roundtrip(self) -> None:
        """FileRecord.to_dict produces dictionary that round-trips cleanly."""
        rec = FileRecord.from_dict(SAMPLE_FILE_DICT)
        d = rec.to_dict()
        assert isinstance(d, dict)
        assert d["id"] == SAMPLE_FILE_ID
        assert d["path"] == "/etc/hosts"
        roundtripped = FileRecord.from_dict(d)
        assert roundtripped == rec

    def test_file_record_frozen_immutability(self) -> None:
        """FileRecord is a frozen dataclass and prevents field mutations."""
        rec = FileRecord.from_dict(SAMPLE_FILE_DICT)
        with pytest.raises(dataclasses.FrozenInstanceError):
            rec.path = "/new/path"  # type: ignore[misc]

    def test_file_record_rejects_non_dict(self) -> None:
        """FileRecord.from_dict rejects non-dictionary inputs."""
        with pytest.raises(ValidationError, match="Expected JSON object"):
            FileRecord.from_dict("not-a-dict")
        with pytest.raises(ValidationError, match="Expected JSON object"):
            FileRecord.from_dict([SAMPLE_FILE_DICT])

    @pytest.mark.parametrize(
        "missing_field",
        ["id", "host_id", "path", "first_seen_at", "created_at"],
    )
    def test_file_record_rejects_missing_required_fields(
        self, missing_field: str
    ) -> None:
        """FileRecord rejects payloads missing any required schema field."""
        bad_data = dict(SAMPLE_FILE_DICT)
        del bad_data[missing_field]
        with pytest.raises(
            ValidationError, match=f"Missing required field.*'{missing_field}'"
        ):
            FileRecord.from_dict(bad_data)

    def test_file_record_validates_uuid_fields(self) -> None:
        """FileRecord validates id and host_id UUID representations."""
        bad_id = dict(SAMPLE_FILE_DICT, id="invalid-uuid")
        with pytest.raises(ValidationError, match="Field 'id' must be a valid UUID"):
            FileRecord.from_dict(bad_id)

        bad_id_bool = dict(SAMPLE_FILE_DICT, id=True)
        with pytest.raises(ValidationError, match="Field 'id' must be a valid UUID"):
            FileRecord.from_dict(bad_id_bool)

        bad_host = dict(SAMPLE_FILE_DICT, host_id="not-a-uuid")
        with pytest.raises(
            ValidationError, match="Field 'host_id' must be a valid UUID"
        ):
            FileRecord.from_dict(bad_host)

        bad_host_bool = dict(SAMPLE_FILE_DICT, host_id=False)
        with pytest.raises(
            ValidationError, match="Field 'host_id' must be a valid UUID"
        ):
            FileRecord.from_dict(bad_host_bool)

    def test_file_record_accepts_uuid_objects(self) -> None:
        """FileRecord parses UUID instances for id and host_id."""
        data = dict(SAMPLE_FILE_DICT)
        data["id"] = uuid.UUID(SAMPLE_FILE_ID)
        data["host_id"] = uuid.UUID(SAMPLE_HOST_ID)
        rec = FileRecord.from_dict(data)
        assert rec.id == SAMPLE_FILE_ID
        assert rec.host_id == SAMPLE_HOST_ID

    @pytest.mark.parametrize("bad_path", ["", "   ", True, 12345, None])
    def test_file_record_validates_path(self, bad_path: Any) -> None:
        """FileRecord rejects non-string or whitespace-only paths."""
        bad_data = dict(SAMPLE_FILE_DICT, path=bad_path)
        with pytest.raises(
            ValidationError, match="Field 'path' must be a non-empty string"
        ):
            FileRecord.from_dict(bad_data)

    def test_file_record_preserves_path_verbatim(self) -> None:
        """FileRecord preserves exact path including special characters and slashes."""
        paths = ["/", "/tmp/", "/var/log/app_100%/trace.log", "/var/run/d.sock"]
        for p in paths:
            data = dict(SAMPLE_FILE_DICT, path=p)
            rec = FileRecord.from_dict(data)
            assert rec.path == p

    @pytest.mark.parametrize("bad_inode", [-1, -100, 123.45, "123", True, False])
    def test_file_record_validates_inode(self, bad_inode: Any) -> None:
        """FileRecord rejects negative numbers, floats, strings, and bools for inode."""
        bad_data = dict(SAMPLE_FILE_DICT, inode=bad_inode)
        with pytest.raises(
            ValidationError,
            match="Field 'inode' must be a non-negative integer or None",
        ):
            FileRecord.from_dict(bad_data)

    @pytest.mark.parametrize("bad_ft", [123, True, ""])
    def test_file_record_validates_file_type(self, bad_ft: Any) -> None:
        """FileRecord rejects non-string or empty file_type when provided."""
        bad_data = dict(SAMPLE_FILE_DICT, file_type=bad_ft)
        with pytest.raises(ValidationError):
            FileRecord.from_dict(bad_data)

    def test_file_record_validates_timestamp_formats(self) -> None:
        """FileRecord validates ISO 8601 timestamps and rejects malformed values."""
        bad_ts = dict(SAMPLE_FILE_DICT, first_seen_at="invalid-date")
        with pytest.raises(
            ValidationError, match="Field 'first_seen_at' must be a valid ISO 8601"
        ):
            FileRecord.from_dict(bad_ts)

        empty_ts = dict(SAMPLE_FILE_DICT, created_at="   ")
        with pytest.raises(
            ValidationError, match="Field 'created_at' must be a non-empty ISO 8601"
        ):
            FileRecord.from_dict(empty_ts)

        bad_last = dict(SAMPLE_FILE_DICT, last_seen_at="bad-time")
        with pytest.raises(
            ValidationError, match="Field 'last_seen_at' must be a valid ISO 8601"
        ):
            FileRecord.from_dict(bad_last)

        empty_last = dict(SAMPLE_FILE_DICT, last_seen_at="  ")
        with pytest.raises(
            ValidationError, match="Field 'last_seen_at' must be an ISO 8601 string"
        ):
            FileRecord.from_dict(empty_last)

    def test_file_alias_points_to_file_record(self) -> None:
        """File is an identical alias for FileRecord."""
        assert File is FileRecord
        rec = File.from_dict(SAMPLE_FILE_DICT)
        assert isinstance(rec, FileRecord)


class TestFileCollectionModel:
    """Tests for FileCollection dataclass validation and pagination."""

    def test_collection_from_dict_success(self) -> None:
        """FileCollection parses valid collection envelope."""
        col = FileCollection.from_dict(SAMPLE_COLLECTION_DICT)
        assert col.total == 1
        assert len(col.items) == 1
        assert col.limit == 50
        assert col.offset == 0
        assert col.items[0].id == SAMPLE_FILE_ID
        assert col.items[0].path == "/etc/hosts"

    def test_collection_empty(self) -> None:
        """FileCollection handles empty items list with total=0."""
        empty_data = {"total": 0, "items": [], "limit": 50, "offset": 0}
        col = FileCollection.from_dict(empty_data)
        assert col.total == 0
        assert col.items == ()
        assert col.limit == 50
        assert col.offset == 0

    def test_collection_to_dict_roundtrip(self) -> None:
        """FileCollection.to_dict converts cleanly and round-trips."""
        col = FileCollection.from_dict(SAMPLE_COLLECTION_DICT)
        d = col.to_dict()
        assert isinstance(d, dict)
        assert d["total"] == 1
        assert len(d["items"]) == 1
        roundtripped = FileCollection.from_dict(d)
        assert roundtripped == col

    def test_collection_preserves_ordering(self) -> None:
        """FileCollection preserves exact ordering of records from backend."""
        f1 = dict(
            SAMPLE_FILE_DICT,
            id="11111111-1111-4111-8111-111111111111",
            path="/tmp",
            first_seen_at="2026-03-01T09:00:00Z",
        )
        f2 = dict(
            SAMPLE_FILE_DICT,
            id="22222222-2222-4222-8222-222222222222",
            path="/tmp/file.txt",
            first_seen_at="2026-03-01T09:01:00Z",
        )
        f3 = dict(
            SAMPLE_FILE_DICT,
            id="33333333-3333-4333-8333-333333333333",
            path="/tmp/sub/file.txt",
            first_seen_at="2026-03-01T09:02:00Z",
        )
        payload = {
            "total": 3,
            "items": [f1, f2, f3],
            "limit": 10,
            "offset": 0,
        }
        col = FileCollection.from_dict(payload)
        assert col.items[0].id == f1["id"]
        assert col.items[0].path == "/tmp"
        assert col.items[1].id == f2["id"]
        assert col.items[1].path == "/tmp/file.txt"
        assert col.items[2].id == f3["id"]
        assert col.items[2].path == "/tmp/sub/file.txt"

    def test_collection_rejects_non_dict(self) -> None:
        """FileCollection.from_dict rejects non-dictionary inputs."""
        with pytest.raises(ValidationError, match="Expected JSON object"):
            FileCollection.from_dict(["not", "a", "dict"])

    @pytest.mark.parametrize(
        "missing_field",
        ["total", "items", "limit", "offset"],
    )
    def test_collection_rejects_missing_fields(self, missing_field: str) -> None:
        """FileCollection rejects missing envelope fields."""
        bad_data = dict(SAMPLE_COLLECTION_DICT)
        del bad_data[missing_field]
        with pytest.raises(
            ValidationError, match=f"Missing required field.*'{missing_field}'"
        ):
            FileCollection.from_dict(bad_data)

    @pytest.mark.parametrize(
        "bad_col, err_match",
        [
            (
                {"total": -1, "items": [], "limit": 50, "offset": 0},
                "Field 'total' must be a non-negative integer",
            ),
            (
                {"total": True, "items": [], "limit": 50, "offset": 0},
                "Field 'total' must be a non-negative integer",
            ),
            (
                {"total": 0, "items": [], "limit": 0, "offset": 0},
                "Field 'limit' must be a positive integer",
            ),
            (
                {"total": 0, "items": [], "limit": -1, "offset": 0},
                "Field 'limit' must be a positive integer",
            ),
            (
                {"total": 0, "items": [], "limit": True, "offset": 0},
                "Field 'limit' must be a positive integer",
            ),
            (
                {"total": 0, "items": [], "limit": 50, "offset": -1},
                "Field 'offset' must be a non-negative integer",
            ),
            (
                {"total": 0, "items": [], "limit": 50, "offset": False},
                "Field 'offset' must be a non-negative integer",
            ),
            (
                {"total": 0, "items": "not a list", "limit": 50, "offset": 0},
                "Field 'items' must be a list",
            ),
        ],
    )
    def test_collection_validates_metadata(
        self, bad_col: dict[str, Any], err_match: str
    ) -> None:
        """FileCollection validates envelope bounds."""
        with pytest.raises(ValidationError, match=err_match):
            FileCollection.from_dict(bad_col)

    def test_collection_rejects_invalid_item_in_list(self) -> None:
        """FileCollection rejects list containing invalid file item."""
        bad_data = {
            "total": 1,
            "items": [{"id": "not-a-valid-file"}],
            "limit": 50,
            "offset": 0,
        }
        with pytest.raises(ValidationError):
            FileCollection.from_dict(bad_data)

    def test_file_record_collection_alias(self) -> None:
        """FileRecordCollection is an alias for FileCollection."""
        assert FileRecordCollection is FileCollection


# ==============================================================================
# B. APIClient.get_files() Tests
# ==============================================================================


class TestGetFilesEndpoint:
    """Tests for APIClient.get_files()."""

    @respx.mock
    def test_get_files_success_default_pagination(self) -> None:
        """get_files() sends authenticated GET with default limit=50, offset=0."""
        route = respx.get("http://127.0.0.1:8001/api/files").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()
        files = client.get_files()

        assert route.called
        req = route.calls.last.request
        assert req.headers["Authorization"] == "Bearer test.secret.bearer.token"
        assert req.url.query.decode() == "limit=50&offset=0"
        assert files.total == 1
        assert len(files.items) == 1
        assert files.items[0].id == SAMPLE_FILE_ID
        assert files.items[0].path == "/etc/hosts"
        client.close()

    @respx.mock
    def test_get_files_custom_pagination(self) -> None:
        """get_files() forwards custom limit and offset query parameters."""
        route = respx.get("http://127.0.0.1:8001/api/files").respond(
            status_code=200,
            json={"total": 100, "items": [], "limit": 25, "offset": 75},
        )

        client = _authenticated_client()
        files = client.get_files(limit=25, offset=75)

        assert route.called
        query = route.calls.last.request.url.query.decode()
        assert "limit=25" in query
        assert "offset=75" in query
        assert files.limit == 25
        assert files.offset == 75
        client.close()

    @respx.mock
    def test_get_files_boundary_limits(self) -> None:
        """get_files() accepts limit boundaries 1 and 100."""
        route = respx.get("http://127.0.0.1:8001/api/files").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()
        client.get_files(limit=1, offset=0)
        assert "limit=1&offset=0" in route.calls.last.request.url.query.decode()

        client.get_files(limit=100, offset=200)
        assert "limit=100&offset=200" in route.calls.last.request.url.query.decode()
        client.close()

    @respx.mock
    def test_get_files_omits_unset_optional_filters(self) -> None:
        """get_files() omits optional filters when unset (None)."""
        route = respx.get("http://127.0.0.1:8001/api/files").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()
        client.get_files()

        assert route.called
        query = route.calls.last.request.url.query.decode()
        assert "host_id" not in query
        assert "path" not in query
        assert "file_type" not in query
        assert query == "limit=50&offset=0"
        client.close()

    @respx.mock
    def test_get_files_filter_host_id_str_and_uuid(self) -> None:
        """get_files() formats host_id parameter from str or UUID."""
        route = respx.get("http://127.0.0.1:8001/api/files").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()

        # String UUID
        client.get_files(host_id=SAMPLE_HOST_ID)
        query = route.calls.last.request.url.query.decode()
        assert f"host_id={SAMPLE_HOST_ID}" in query

        # UUID object
        client.get_files(host_id=uuid.UUID(SAMPLE_HOST_ID))
        query2 = route.calls.last.request.url.query.decode()
        assert f"host_id={SAMPLE_HOST_ID}" in query2

        client.close()

    @respx.mock
    def test_get_files_filter_path_prefix(self) -> None:
        """get_files() forwards path prefix filter including trailing slash."""
        route = respx.get("http://127.0.0.1:8001/api/files").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()

        # Normal path
        client.get_files(path="/tmp")
        query1 = route.calls.last.request.url.query.decode()
        assert "path=%2Ftmp" in query1 or "path=/tmp" in query1

        # Trailing slash path
        client.get_files(path="/tmp/")
        query2 = route.calls.last.request.url.query.decode()
        assert "path=%2Ftmp%2F" in query2 or "path=/tmp/" in query2

        client.close()

    @respx.mock
    def test_get_files_filter_file_type(self) -> None:
        """get_files() forwards normalized file_type filter."""
        route = respx.get("http://127.0.0.1:8001/api/files").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()

        client.get_files(file_type="file")
        assert "file_type=file" in route.calls.last.request.url.query.decode()

        client.get_files(file_type="directory")
        assert "file_type=directory" in route.calls.last.request.url.query.decode()

        # Case-insensitive normalization
        client.get_files(file_type="FILE")
        assert "file_type=file" in route.calls.last.request.url.query.decode()

        client.close()

    @respx.mock
    def test_get_files_combined_filters(self) -> None:
        """get_files() sends all combined query parameters accurately."""
        route = respx.get("http://127.0.0.1:8001/api/files").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()
        client.get_files(
            host_id=SAMPLE_HOST_ID,
            path="/tmp",
            file_type="file",
            limit=10,
            offset=20,
        )

        assert route.called
        query = route.calls.last.request.url.query.decode()
        assert f"host_id={SAMPLE_HOST_ID}" in query
        assert "path=" in query
        assert "file_type=file" in query
        assert "limit=10" in query
        assert "offset=20" in query
        client.close()

    @respx.mock
    @pytest.mark.parametrize(
        "kwargs, err_match",
        [
            ({"limit": 0}, "limit must be an integer between 1 and 100"),
            ({"limit": -1}, "limit must be an integer between 1 and 100"),
            ({"limit": 101}, "limit must be an integer between 1 and 100"),
            ({"limit": True}, "limit must be an integer between 1 and 100"),
            ({"limit": "50"}, "limit must be an integer between 1 and 100"),
            ({"offset": -1}, "offset must be a non-negative integer"),
            ({"offset": False}, "offset must be a non-negative integer"),
            ({"offset": "0"}, "offset must be a non-negative integer"),
            ({"host_id": "bad-uuid"}, "Invalid host_id UUID"),
            ({"host_id": True}, "Invalid host_id UUID"),
            ({"host_id": 12345}, "Invalid host_id UUID"),
            ({"path": ""}, "path must be a non-empty string"),
            ({"path": "   "}, "path must be a non-empty string"),
            ({"path": 12345}, "path must be a non-empty string"),
            ({"path": True}, "path must be a non-empty string"),
            ({"file_type": ""}, "file_type must be a non-empty string"),
            ({"file_type": "   "}, "file_type must be a non-empty string"),
            ({"file_type": "invalid"}, "Invalid file_type 'invalid'"),
            ({"file_type": "symlink"}, "Invalid file_type 'symlink'"),
            ({"file_type": 123}, "file_type must be a non-empty string"),
            ({"file_type": True}, "file_type must be a non-empty string"),
        ],
    )
    def test_get_files_invalid_args_prevent_dispatch(
        self, kwargs: dict[str, Any], err_match: str
    ) -> None:
        """Invalid arguments raise ValidationError locally without HTTP dispatch."""
        route = respx.get("http://127.0.0.1:8001/api/files").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()
        with pytest.raises(ValidationError, match=err_match):
            client.get_files(**kwargs)

        assert not route.called
        client.close()

    def test_get_files_requires_authentication(self) -> None:
        """get_files() raises AuthenticationError if client is unauthenticated."""
        client = APIClient(base_url="http://127.0.0.1:8001")
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.get_files()
        client.close()

    def test_get_files_closed_client_rejected(self) -> None:
        """get_files() raises OSIRISClientError if client session is closed."""
        client = _authenticated_client()
        client.close()
        with pytest.raises(OSIRISClientError, match="APIClient is closed"):
            client.get_files()

    @respx.mock
    def test_get_files_401_clears_token(self) -> None:
        """HTTP 401 clears stored token and raises AuthenticationError."""
        respx.get("http://127.0.0.1:8001/api/files").respond(
            status_code=401,
            json={"detail": "Token expired"},
        )

        client = _authenticated_client()
        assert client.is_authenticated is True

        with pytest.raises(AuthenticationError, match="Token expired"):
            client.get_files()

        assert client.is_authenticated is False
        client.close()

    @respx.mock
    def test_get_files_403_preserves_token(self) -> None:
        """HTTP 403 raises AuthorizationError without clearing held token."""
        respx.get("http://127.0.0.1:8001/api/files").respond(
            status_code=403,
            json={"detail": "Insufficient permissions"},
        )

        client = _authenticated_client()
        with pytest.raises(AuthorizationError, match="Insufficient permissions"):
            client.get_files()

        assert client.is_authenticated is True
        client.close()

    @respx.mock
    def test_get_files_404_maps_to_http_response_error(self) -> None:
        """HTTP 404 from server maps to HTTPResponseError with status_code=404."""
        respx.get("http://127.0.0.1:8001/api/files").respond(
            status_code=404,
            json={"detail": "Not found"},
        )

        client = _authenticated_client()
        with pytest.raises(HTTPResponseError) as exc_info:
            client.get_files()

        assert exc_info.value.status_code == 404
        client.close()

    @respx.mock
    def test_get_files_500_maps_to_http_response_error(self) -> None:
        """HTTP 500 maps to HTTPResponseError with status_code=500."""
        respx.get("http://127.0.0.1:8001/api/files").respond(
            status_code=500,
            json={"detail": "Internal server error"},
        )

        client = _authenticated_client()
        with pytest.raises(HTTPResponseError) as exc_info:
            client.get_files()

        assert exc_info.value.status_code == 500
        client.close()

    @respx.mock
    def test_get_files_timeout_maps_to_connection_timeout_error(self) -> None:
        """Timeout during request maps to ConnectionTimeoutError."""
        respx.get("http://127.0.0.1:8001/api/files").mock(
            side_effect=httpx.TimeoutException("Read timed out")
        )

        client = _authenticated_client()
        with pytest.raises(ConnectionTimeoutError, match="Connection timed out"):
            client.get_files()
        client.close()

    @respx.mock
    def test_get_files_network_error_maps_to_client_connection_error(
        self,
    ) -> None:
        """Network error maps to ClientConnectionError."""
        respx.get("http://127.0.0.1:8001/api/files").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        client = _authenticated_client()
        with pytest.raises(ClientConnectionError, match="Network connection failure"):
            client.get_files()
        client.close()

    @respx.mock
    def test_get_files_malformed_json_response(self) -> None:
        """Malformed non-JSON response raises ValidationError."""
        respx.get("http://127.0.0.1:8001/api/files").respond(
            status_code=200,
            text="<!DOCTYPE html><html>Not JSON</html>",
            headers={"Content-Type": "text/html"},
        )

        client = _authenticated_client()
        with pytest.raises(ValidationError, match="Server response is not valid JSON"):
            client.get_files()
        client.close()

    @respx.mock
    def test_get_files_malformed_response_schema(self) -> None:
        """Response missing required collection schema fields raises ValidationError."""
        respx.get("http://127.0.0.1:8001/api/files").respond(
            status_code=200,
            json={"unexpected": "structure"},
        )

        client = _authenticated_client()
        with pytest.raises(ValidationError, match="Missing required field"):
            client.get_files()
        client.close()


# ==============================================================================
# C. Public Exports & Contract Boundary Tests
# ==============================================================================


class TestFilesClientRegressions:
    """Verifies public exports, boundaries, and that existing models are unaffected."""

    def test_public_client_imports(self) -> None:
        """File, FileRecord, and FileCollection are exposed via desktop.client."""
        import desktop.client as dc

        assert hasattr(dc, "File")
        assert hasattr(dc, "FileRecord")
        assert hasattr(dc, "FileCollection")
        assert hasattr(dc, "FileRecordCollection")
        assert hasattr(dc, "VALID_FILE_TYPES")
        assert hasattr(dc, "APIClient")
        assert dc.File is FileRecord
        assert dc.FileRecord is FileRecord
        assert dc.FileCollection is FileCollection
        assert dc.FileRecordCollection is FileCollection
        assert dc.VALID_FILE_TYPES == ("file", "directory")
        assert VALID_FILE_TYPES == ("file", "directory")

    def test_api_client_has_get_files_method(self) -> None:
        """APIClient exposes get_files but avoids speculating absent get_file."""
        client = APIClient(base_url="http://127.0.0.1:8001")
        assert callable(getattr(client, "get_files", None))
        # Backend does not expose GET /api/files/{id}; no speculative single getter
        assert not hasattr(client, "get_file")
        client.close()

    def test_existing_models_unaffected(self) -> None:
        """Events, Processes, and Resources models remain functional and unaltered."""
        # Event
        event_dict = {
            "id": SAMPLE_FILE_ID,
            "host_id": SAMPLE_HOST_ID,
            "timestamp": SAMPLE_FIRST_SEEN,
            "ingested_at": SAMPLE_FIRST_SEEN,
            "source": "fs",
            "event_type": "file.create",
            "action": "create",
            "severity": "info",
            "created_at": SAMPLE_CREATED_AT,
        }
        event = Event.from_dict(event_dict)
        assert event.id == SAMPLE_FILE_ID

        # Process
        proc_dict = {
            "id": SAMPLE_FILE_ID,
            "host_id": SAMPLE_HOST_ID,
            "pid": 100,
            "command": "/bin/cat",
            "started_at": SAMPLE_FIRST_SEEN,
            "created_at": SAMPLE_CREATED_AT,
        }
        proc = Process.from_dict(proc_dict)
        assert proc.pid == 100

        # ResourceSnapshot
        snap_dict = {
            "id": SAMPLE_FILE_ID,
            "host_id": SAMPLE_HOST_ID,
            "timestamp": SAMPLE_FIRST_SEEN,
            "created_at": SAMPLE_CREATED_AT,
        }
        snap = ResourceSnapshot.from_dict(snap_dict)
        assert snap.id == SAMPLE_FILE_ID
