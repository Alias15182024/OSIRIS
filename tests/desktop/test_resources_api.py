"""Tests for OSIRIS Desktop authenticated resources REST API client.

Covers:
A. ResourceSnapshot and ResourceSnapshotCollection model validation and error handling.
B. APIClient.get_resources() listing, filtering, and pagination.
C. Security, authentication lifecycle, and transport exception regressions.
"""

from __future__ import annotations

import dataclasses
import uuid
from datetime import datetime, timezone
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
    HTTPResponseError,
    OSIRISClientError,
    ResourceSnapshot,
    ResourceSnapshotCollection,
    ValidationError,
)

SAMPLE_SNAPSHOT_ID = "11111111-1111-4111-8111-111111111111"
SAMPLE_HOST_ID = "22222222-2222-4222-8222-222222222222"
SAMPLE_TIMESTAMP = "2026-03-01T08:00:00Z"
SAMPLE_CREATED_AT = "2026-03-01T08:00:00Z"

SAMPLE_SNAPSHOT_DICT: dict[str, Any] = {
    "id": SAMPLE_SNAPSHOT_ID,
    "host_id": SAMPLE_HOST_ID,
    "timestamp": SAMPLE_TIMESTAMP,
    "cpu_percent": 15.2,
    "memory_total": 16_000_000_000,
    "memory_used": 4_000_000_000,
    "memory_percent": 25.0,
    "disk_read_bytes": 1048576,
    "disk_write_bytes": 2097152,
    "disk_usage_percent": 45.5,
    "created_at": SAMPLE_CREATED_AT,
}

SAMPLE_MINIMAL_SNAPSHOT_DICT: dict[str, Any] = {
    "id": SAMPLE_SNAPSHOT_ID,
    "host_id": SAMPLE_HOST_ID,
    "timestamp": SAMPLE_TIMESTAMP,
    "created_at": SAMPLE_CREATED_AT,
}

SAMPLE_COLLECTION_DICT: dict[str, Any] = {
    "total": 1,
    "items": [SAMPLE_SNAPSHOT_DICT],
    "limit": 50,
    "offset": 0,
}


def _authenticated_client() -> APIClient:
    """Return an APIClient initialized with an in-memory session token."""
    client = APIClient(base_url="http://127.0.0.1:8001")
    client._token = "test.secret.bearer.token"
    return client


# ==============================================================================
# A. ResourceSnapshot & ResourceSnapshotCollection Model Tests
# ==============================================================================


class TestResourceSnapshotModel:
    """Tests for ResourceSnapshot dataclass."""

    def test_snapshot_from_dict_full(self) -> None:
        """ResourceSnapshot correctly parses all fields matching backend schema."""
        snap = ResourceSnapshot.from_dict(SAMPLE_SNAPSHOT_DICT)
        assert snap.id == SAMPLE_SNAPSHOT_ID
        assert snap.host_id == SAMPLE_HOST_ID
        assert snap.timestamp == SAMPLE_TIMESTAMP
        assert snap.cpu_percent == 15.2
        assert snap.memory_total == 16_000_000_000
        assert snap.memory_used == 4_000_000_000
        assert snap.memory_percent == 25.0
        assert snap.disk_read_bytes == 1048576
        assert snap.disk_write_bytes == 2097152
        assert snap.disk_usage_percent == 45.5
        assert snap.created_at == SAMPLE_CREATED_AT

    def test_snapshot_from_dict_minimal(self) -> None:
        """ResourceSnapshot defaults nullable telemetry metrics to None."""
        snap = ResourceSnapshot.from_dict(SAMPLE_MINIMAL_SNAPSHOT_DICT)
        assert snap.id == SAMPLE_SNAPSHOT_ID
        assert snap.host_id == SAMPLE_HOST_ID
        assert snap.timestamp == SAMPLE_TIMESTAMP
        assert snap.created_at == SAMPLE_CREATED_AT
        assert snap.cpu_percent is None
        assert snap.memory_total is None
        assert snap.memory_used is None
        assert snap.memory_percent is None
        assert snap.disk_read_bytes is None
        assert snap.disk_write_bytes is None
        assert snap.disk_usage_percent is None

    def test_snapshot_preserves_numeric_zeros(self) -> None:
        """ResourceSnapshot preserves valid 0 and 0.0 values across all metrics."""
        data = {
            "id": SAMPLE_SNAPSHOT_ID,
            "host_id": SAMPLE_HOST_ID,
            "timestamp": SAMPLE_TIMESTAMP,
            "cpu_percent": 0.0,
            "memory_total": 0,
            "memory_used": 0,
            "memory_percent": 0.0,
            "disk_read_bytes": 0,
            "disk_write_bytes": 0,
            "disk_usage_percent": 0.0,
            "created_at": SAMPLE_CREATED_AT,
        }
        snap = ResourceSnapshot.from_dict(data)
        assert snap.cpu_percent == 0.0
        assert snap.memory_total == 0
        assert snap.memory_used == 0
        assert snap.memory_percent == 0.0
        assert snap.disk_read_bytes == 0
        assert snap.disk_write_bytes == 0
        assert snap.disk_usage_percent == 0.0

    def test_snapshot_to_dict_roundtrip(self) -> None:
        """ResourceSnapshot.to_dict produces dictionary that round-trips cleanly."""
        snap = ResourceSnapshot.from_dict(SAMPLE_SNAPSHOT_DICT)
        d = snap.to_dict()
        assert isinstance(d, dict)
        assert d["id"] == SAMPLE_SNAPSHOT_ID
        assert d["cpu_percent"] == 15.2
        roundtripped = ResourceSnapshot.from_dict(d)
        assert roundtripped == snap

    def test_snapshot_frozen_immutability(self) -> None:
        """ResourceSnapshot is a frozen dataclass and prevents field mutations."""
        snap = ResourceSnapshot.from_dict(SAMPLE_SNAPSHOT_DICT)
        with pytest.raises(dataclasses.FrozenInstanceError):
            snap.cpu_percent = 99.9  # type: ignore[misc]

    def test_snapshot_rejects_non_dict(self) -> None:
        """ResourceSnapshot.from_dict rejects non-dictionary inputs."""
        with pytest.raises(ValidationError, match="Expected JSON object"):
            ResourceSnapshot.from_dict("not-a-dict")
        with pytest.raises(ValidationError, match="Expected JSON object"):
            ResourceSnapshot.from_dict([SAMPLE_SNAPSHOT_DICT])

    @pytest.mark.parametrize(
        "missing_field",
        ["id", "host_id", "timestamp", "created_at"],
    )
    def test_snapshot_rejects_missing_required_fields(
        self, missing_field: str
    ) -> None:
        """ResourceSnapshot rejects payloads missing any required field."""
        bad_data = dict(SAMPLE_SNAPSHOT_DICT)
        del bad_data[missing_field]
        with pytest.raises(
            ValidationError, match=f"Missing required field.*'{missing_field}'"
        ):
            ResourceSnapshot.from_dict(bad_data)

    def test_snapshot_validates_uuid_fields(self) -> None:
        """ResourceSnapshot validates id and host_id UUID representations."""
        bad_id = dict(SAMPLE_SNAPSHOT_DICT, id="invalid-uuid")
        with pytest.raises(ValidationError, match="Field 'id' must be a valid UUID"):
            ResourceSnapshot.from_dict(bad_id)

        bad_id_bool = dict(SAMPLE_SNAPSHOT_DICT, id=True)
        with pytest.raises(ValidationError, match="Field 'id' must be a valid UUID"):
            ResourceSnapshot.from_dict(bad_id_bool)

        bad_host = dict(SAMPLE_SNAPSHOT_DICT, host_id="not-a-uuid")
        with pytest.raises(
            ValidationError, match="Field 'host_id' must be a valid UUID"
        ):
            ResourceSnapshot.from_dict(bad_host)

        bad_host_bool = dict(SAMPLE_SNAPSHOT_DICT, host_id=False)
        with pytest.raises(
            ValidationError, match="Field 'host_id' must be a valid UUID"
        ):
            ResourceSnapshot.from_dict(bad_host_bool)

    def test_snapshot_accepts_uuid_objects(self) -> None:
        """ResourceSnapshot parses UUID instances for id and host_id."""
        data = dict(SAMPLE_SNAPSHOT_DICT)
        data["id"] = uuid.UUID(SAMPLE_SNAPSHOT_ID)
        data["host_id"] = uuid.UUID(SAMPLE_HOST_ID)
        snap = ResourceSnapshot.from_dict(data)
        assert snap.id == SAMPLE_SNAPSHOT_ID
        assert snap.host_id == SAMPLE_HOST_ID

    def test_snapshot_validates_timestamp_formats(self) -> None:
        """ResourceSnapshot validates ISO 8601 timestamps and preserves format."""
        bad_ts = dict(SAMPLE_SNAPSHOT_DICT, timestamp="invalid-timestamp")
        with pytest.raises(
            ValidationError, match="Field 'timestamp' must be a valid ISO 8601"
        ):
            ResourceSnapshot.from_dict(bad_ts)

        bad_created = dict(SAMPLE_SNAPSHOT_DICT, created_at="bad-date")
        with pytest.raises(
            ValidationError, match="Field 'created_at' must be a valid ISO 8601"
        ):
            ResourceSnapshot.from_dict(bad_created)

        empty_ts = dict(SAMPLE_SNAPSHOT_DICT, timestamp="   ")
        with pytest.raises(
            ValidationError, match="Field 'timestamp' must be a non-empty ISO 8601"
        ):
            ResourceSnapshot.from_dict(empty_ts)

    @pytest.mark.parametrize(
        "val, expected",
        [
            (0.0, 0.0),
            (100.0, 100.0),
            (0, 0.0),
            (100, 100.0),
            (50.5, 50.5),
        ],
    )
    def test_snapshot_percentage_valid_boundaries(
        self, val: float | int, expected: float
    ) -> None:
        """ResourceSnapshot accepts percentage boundaries 0.0 to 100.0."""
        data = dict(SAMPLE_SNAPSHOT_DICT)
        data["cpu_percent"] = val
        data["memory_percent"] = val
        data["disk_usage_percent"] = val
        snap = ResourceSnapshot.from_dict(data)
        assert snap.cpu_percent == expected
        assert snap.memory_percent == expected
        assert snap.disk_usage_percent == expected

    @pytest.mark.parametrize(
        "bad_pct",
        [-0.01, -1.0, 100.01, 150.0, float("nan"), float("inf"), float("-inf")],
    )
    def test_snapshot_percentage_invalid_values(self, bad_pct: float) -> None:
        """ResourceSnapshot rejects percentages outside 0.0 to 100.0."""
        for field in ("cpu_percent", "memory_percent", "disk_usage_percent"):
            bad_data = dict(SAMPLE_SNAPSHOT_DICT, **{field: bad_pct})
            with pytest.raises(
                ValidationError, match=f"Field '{field}' must be between 0.0 and 100.0"
            ):
                ResourceSnapshot.from_dict(bad_data)

    def test_snapshot_rejects_booleans_for_percentages(self) -> None:
        """ResourceSnapshot strictly rejects bool values for percentage fields."""
        for field in ("cpu_percent", "memory_percent", "disk_usage_percent"):
            for bool_val in (True, False):
                bad_data = dict(SAMPLE_SNAPSHOT_DICT, **{field: bool_val})
                with pytest.raises(
                    ValidationError,
                    match=f"Field '{field}' must be a float between 0.0 and 100.0",
                ):
                    ResourceSnapshot.from_dict(bad_data)

    def test_snapshot_byte_counters_valid(self) -> None:
        """ResourceSnapshot accepts valid non-negative integer byte counters."""
        data = dict(SAMPLE_SNAPSHOT_DICT)
        data["memory_total"] = 32_000_000_000
        data["memory_used"] = 0
        data["disk_read_bytes"] = 0
        data["disk_write_bytes"] = 5_000_000
        snap = ResourceSnapshot.from_dict(data)
        assert snap.memory_total == 32_000_000_000
        assert snap.memory_used == 0
        assert snap.disk_read_bytes == 0
        assert snap.disk_write_bytes == 5_000_000

    @pytest.mark.parametrize("bad_val", [-1, -100, 1048576.5, "1048576"])
    def test_snapshot_byte_counters_invalid(self, bad_val: object) -> None:
        """ResourceSnapshot rejects negative, float, or string values for bytes."""
        for field in (
            "memory_total",
            "memory_used",
            "disk_read_bytes",
            "disk_write_bytes",
        ):
            bad_data = dict(SAMPLE_SNAPSHOT_DICT, **{field: bad_val})
            with pytest.raises(
                ValidationError,
                match=f"Field '{field}' must be a non-negative integer or None",
            ):
                ResourceSnapshot.from_dict(bad_data)

    def test_snapshot_rejects_booleans_for_byte_counters(self) -> None:
        """ResourceSnapshot strictly rejects booleans for byte counters."""
        for field in (
            "memory_total",
            "memory_used",
            "disk_read_bytes",
            "disk_write_bytes",
        ):
            for bool_val in (True, False):
                bad_data = dict(SAMPLE_SNAPSHOT_DICT, **{field: bool_val})
                with pytest.raises(
                    ValidationError,
                    match=f"Field '{field}' must be a non-negative integer or None",
                ):
                    ResourceSnapshot.from_dict(bad_data)


class TestResourceSnapshotCollectionModel:
    """Tests for ResourceSnapshotCollection dataclass."""

    def test_collection_from_dict_success(self) -> None:
        """ResourceSnapshotCollection parses valid collection envelope."""
        col = ResourceSnapshotCollection.from_dict(SAMPLE_COLLECTION_DICT)
        assert col.total == 1
        assert len(col.items) == 1
        assert col.limit == 50
        assert col.offset == 0
        assert col.items[0].id == SAMPLE_SNAPSHOT_ID

    def test_collection_empty(self) -> None:
        """ResourceSnapshotCollection handles empty list response with total 0."""
        empty_data = {"total": 0, "items": [], "limit": 50, "offset": 0}
        col = ResourceSnapshotCollection.from_dict(empty_data)
        assert col.total == 0
        assert col.items == ()
        assert col.limit == 50
        assert col.offset == 0

    def test_collection_to_dict_roundtrip(self) -> None:
        """ResourceSnapshotCollection.to_dict converts cleanly and round-trips."""
        col = ResourceSnapshotCollection.from_dict(SAMPLE_COLLECTION_DICT)
        d = col.to_dict()
        assert isinstance(d, dict)
        assert d["total"] == 1
        assert len(d["items"]) == 1
        roundtripped = ResourceSnapshotCollection.from_dict(d)
        assert roundtripped == col

    def test_collection_preserves_ordering(self) -> None:
        """ResourceSnapshotCollection preserves order of records from API."""
        s1 = dict(SAMPLE_SNAPSHOT_DICT, id="11111111-1111-4111-8111-111111111111")
        s2 = dict(SAMPLE_SNAPSHOT_DICT, id="22222222-2222-4222-8222-222222222222")
        s3 = dict(SAMPLE_SNAPSHOT_DICT, id="33333333-3333-4333-8333-333333333333")
        payload = {
            "total": 3,
            "items": [s1, s2, s3],
            "limit": 10,
            "offset": 0,
        }
        col = ResourceSnapshotCollection.from_dict(payload)
        assert col.items[0].id == s1["id"]
        assert col.items[1].id == s2["id"]
        assert col.items[2].id == s3["id"]

    def test_collection_rejects_non_dict(self) -> None:
        """ResourceSnapshotCollection.from_dict rejects non-dictionary inputs."""
        with pytest.raises(ValidationError, match="Expected JSON object"):
            ResourceSnapshotCollection.from_dict(["not", "a", "dict"])

    @pytest.mark.parametrize(
        "missing_field",
        ["total", "items", "limit", "offset"],
    )
    def test_collection_rejects_missing_fields(self, missing_field: str) -> None:
        """ResourceSnapshotCollection rejects missing envelope fields."""
        bad_data = dict(SAMPLE_COLLECTION_DICT)
        del bad_data[missing_field]
        with pytest.raises(
            ValidationError, match=f"Missing required field.*'{missing_field}'"
        ):
            ResourceSnapshotCollection.from_dict(bad_data)

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
        """ResourceSnapshotCollection validates envelope metadata bounds."""
        with pytest.raises(ValidationError, match=err_match):
            ResourceSnapshotCollection.from_dict(bad_col)

    def test_collection_rejects_invalid_item_in_list(self) -> None:
        """ResourceSnapshotCollection rejects items with invalid snapshot data."""
        bad_data = {
            "total": 1,
            "items": [{"id": "not-a-valid-snapshot"}],
            "limit": 50,
            "offset": 0,
        }
        with pytest.raises(ValidationError):
            ResourceSnapshotCollection.from_dict(bad_data)


# ==============================================================================
# B. APIClient.get_resources() Tests
# ==============================================================================


class TestGetResourcesEndpoint:
    """Tests for APIClient.get_resources()."""

    @respx.mock
    def test_get_resources_success_default_pagination(self) -> None:
        """get_resources() sends authenticated GET with default limit=50, offset=0."""
        route = respx.get("http://127.0.0.1:8001/api/resources").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()
        snapshots = client.get_resources()

        assert route.called
        req = route.calls.last.request
        assert req.headers["Authorization"] == "Bearer test.secret.bearer.token"
        assert req.url.query.decode() == "limit=50&offset=0"
        assert snapshots.total == 1
        assert len(snapshots.items) == 1
        assert snapshots.items[0].id == SAMPLE_SNAPSHOT_ID
        assert snapshots.items[0].cpu_percent == 15.2
        client.close()

    @respx.mock
    def test_get_resources_custom_pagination(self) -> None:
        """get_resources() forwards custom limit and offset query parameters."""
        route = respx.get("http://127.0.0.1:8001/api/resources").respond(
            status_code=200,
            json={"total": 200, "items": [], "limit": 25, "offset": 50},
        )

        client = _authenticated_client()
        snapshots = client.get_resources(limit=25, offset=50)

        assert route.called
        query = route.calls.last.request.url.query.decode()
        assert "limit=25" in query
        assert "offset=50" in query
        assert snapshots.limit == 25
        assert snapshots.offset == 50
        client.close()

    @respx.mock
    def test_get_resources_boundary_limits(self) -> None:
        """get_resources() accepts limit boundaries 1 and 100."""
        route = respx.get("http://127.0.0.1:8001/api/resources").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()
        client.get_resources(limit=1, offset=0)
        assert "limit=1&offset=0" in route.calls.last.request.url.query.decode()

        client.get_resources(limit=100, offset=500)
        assert "limit=100&offset=500" in route.calls.last.request.url.query.decode()
        client.close()

    @respx.mock
    def test_get_resources_omits_unset_optional_filters(self) -> None:
        """get_resources() omits optional filters when unset (None)."""
        route = respx.get("http://127.0.0.1:8001/api/resources").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()
        client.get_resources()

        assert route.called
        query = route.calls.last.request.url.query.decode()
        assert "host_id" not in query
        assert "start_time" not in query
        assert "end_time" not in query
        assert query == "limit=50&offset=0"
        client.close()

    @respx.mock
    def test_get_resources_filter_host_id_str_and_uuid(self) -> None:
        """get_resources() formats host_id query parameter from str or UUID."""
        route = respx.get("http://127.0.0.1:8001/api/resources").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()

        # String UUID
        client.get_resources(host_id=SAMPLE_HOST_ID)
        query = route.calls.last.request.url.query.decode()
        assert f"host_id={SAMPLE_HOST_ID}" in query

        # UUID object
        client.get_resources(host_id=uuid.UUID(SAMPLE_HOST_ID))
        query2 = route.calls.last.request.url.query.decode()
        assert f"host_id={SAMPLE_HOST_ID}" in query2

        client.close()

    @respx.mock
    def test_get_resources_filter_time_boundaries(self) -> None:
        """get_resources() accepts start_time only, end_time only, and both."""
        route = respx.get("http://127.0.0.1:8001/api/resources").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()

        # start_time only (str)
        t_start = "2026-03-01T08:00:00Z"
        client.get_resources(start_time=t_start)
        query1 = route.calls.last.request.url.query.decode()
        assert "start_time=" in query1
        assert "end_time=" not in query1

        # end_time only (datetime)
        dt_end = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        client.get_resources(end_time=dt_end)
        query2 = route.calls.last.request.url.query.decode()
        assert "start_time=" not in query2
        assert "end_time=" in query2

        # Combined range (datetime and str)
        dt_start = datetime(2026, 3, 1, 8, 0, 0, tzinfo=timezone.utc)
        t_end = "2026-03-01T12:00:00Z"
        client.get_resources(start_time=dt_start, end_time=t_end)
        query3 = route.calls.last.request.url.query.decode()
        assert "start_time=" in query3
        assert "end_time=" in query3

        client.close()

    @respx.mock
    def test_get_resources_reversed_time_range_rejected_before_dispatch(
        self,
    ) -> None:
        """Reversed start_time > end_time raises ValidationError with no request."""
        route = respx.get("http://127.0.0.1:8001/api/resources").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()

        # String reversed range
        with pytest.raises(
            ValidationError,
            match="start_time must be less than or equal to end_time",
        ):
            client.get_resources(
                start_time="2026-03-01T12:00:00Z",
                end_time="2026-03-01T08:00:00Z",
            )
        assert not route.called

        # Datetime reversed range
        dt_later = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        dt_earlier = datetime(2026, 3, 1, 8, 0, 0, tzinfo=timezone.utc)
        with pytest.raises(
            ValidationError,
            match="start_time must be less than or equal to end_time",
        ):
            client.get_resources(start_time=dt_later, end_time=dt_earlier)
        assert not route.called

        client.close()

    @respx.mock
    def test_get_resources_equal_time_range_allowed(self) -> None:
        """Equal start_time and end_time (point-in-time) is permitted."""
        route = respx.get("http://127.0.0.1:8001/api/resources").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()
        t = "2026-03-01T08:00:00Z"
        client.get_resources(start_time=t, end_time=t)
        assert route.called
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
            ({"start_time": "bad-date"}, "Invalid ISO 8601 timestamp format"),
            ({"start_time": True}, "must be an ISO 8601 string or datetime"),
            ({"end_time": "   "}, "must be a non-empty string or datetime"),
            ({"end_time": 99999}, "must be an ISO 8601 string or datetime"),
        ],
    )
    def test_get_resources_invalid_local_args_prevent_dispatch(
        self, kwargs: dict[str, Any], err_match: str
    ) -> None:
        """Invalid arguments raise ValidationError locally without HTTP dispatch."""
        route = respx.get("http://127.0.0.1:8001/api/resources").respond(
            status_code=200,
            json=SAMPLE_COLLECTION_DICT,
        )

        client = _authenticated_client()
        with pytest.raises(ValidationError, match=err_match):
            client.get_resources(**kwargs)

        assert not route.called
        client.close()

    def test_get_resources_requires_authentication(self) -> None:
        """get_resources() raises AuthenticationError if client is unauthenticated."""
        client = APIClient(base_url="http://127.0.0.1:8001")
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.get_resources()
        client.close()

    def test_get_resources_closed_client_rejected(self) -> None:
        """get_resources() raises OSIRISClientError if client session is closed."""
        client = _authenticated_client()
        client.close()
        with pytest.raises(OSIRISClientError, match="APIClient is closed"):
            client.get_resources()

    @respx.mock
    def test_get_resources_401_clears_token(self) -> None:
        """HTTP 401 clears stored token and raises AuthenticationError."""
        respx.get("http://127.0.0.1:8001/api/resources").respond(
            status_code=401,
            json={"detail": "Token expired"},
        )

        client = _authenticated_client()
        assert client.is_authenticated is True

        with pytest.raises(AuthenticationError, match="Token expired"):
            client.get_resources()

        assert client.is_authenticated is False
        client.close()

    @respx.mock
    def test_get_resources_403_preserves_token(self) -> None:
        """HTTP 403 raises AuthorizationError without clearing held token."""
        respx.get("http://127.0.0.1:8001/api/resources").respond(
            status_code=403,
            json={"detail": "Insufficient permissions"},
        )

        client = _authenticated_client()
        with pytest.raises(AuthorizationError, match="Insufficient permissions"):
            client.get_resources()

        assert client.is_authenticated is True
        client.close()

    @respx.mock
    def test_get_resources_400_maps_to_http_response_error(self) -> None:
        """HTTP 400 from server maps to HTTPResponseError with status_code=400."""
        respx.get("http://127.0.0.1:8001/api/resources").respond(
            status_code=400,
            json={"detail": "start_time must be less than or equal to end_time"},
        )

        client = _authenticated_client()
        with pytest.raises(HTTPResponseError) as exc_info:
            client.get_resources()

        assert exc_info.value.status_code == 400
        assert "start_time must be less than or equal to end_time" in str(
            exc_info.value
        )
        client.close()

    @respx.mock
    def test_get_resources_500_maps_to_http_response_error(self) -> None:
        """HTTP 500 maps to HTTPResponseError with status_code=500."""
        respx.get("http://127.0.0.1:8001/api/resources").respond(
            status_code=500,
            json={"detail": "Internal server error"},
        )

        client = _authenticated_client()
        with pytest.raises(HTTPResponseError) as exc_info:
            client.get_resources()

        assert exc_info.value.status_code == 500
        client.close()

    @respx.mock
    def test_get_resources_timeout_maps_to_connection_timeout_error(self) -> None:
        """Timeout during request maps to ConnectionTimeoutError."""
        respx.get("http://127.0.0.1:8001/api/resources").mock(
            side_effect=httpx.TimeoutException("Read timed out")
        )

        client = _authenticated_client()
        with pytest.raises(ConnectionTimeoutError, match="Connection timed out"):
            client.get_resources()
        client.close()

    @respx.mock
    def test_get_resources_network_error_maps_to_client_connection_error(
        self,
    ) -> None:
        """Network error maps to ClientConnectionError."""
        respx.get("http://127.0.0.1:8001/api/resources").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        client = _authenticated_client()
        with pytest.raises(ClientConnectionError, match="Network connection failure"):
            client.get_resources()
        client.close()

    @respx.mock
    def test_get_resources_malformed_json_response(self) -> None:
        """Malformed non-JSON response raises ValidationError."""
        respx.get("http://127.0.0.1:8001/api/resources").respond(
            status_code=200,
            text="<!DOCTYPE html><html>Not JSON</html>",
            headers={"Content-Type": "text/html"},
        )

        client = _authenticated_client()
        with pytest.raises(ValidationError, match="Server response is not valid JSON"):
            client.get_resources()
        client.close()

    @respx.mock
    def test_get_resources_malformed_response_schema(self) -> None:
        """Response missing required collection schema fields raises ValidationError."""
        respx.get("http://127.0.0.1:8001/api/resources").respond(
            status_code=200,
            json={"unexpected": "structure"},
        )

        client = _authenticated_client()
        with pytest.raises(ValidationError, match="Missing required field"):
            client.get_resources()
        client.close()
