"""OSIRIS Desktop API response data models.

Provides pure-Python standard-library dataclasses representing backend API
responses for authentication, user profiles, system status, and health.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from desktop.client.exceptions import ValidationError


@dataclass(frozen=True)
class User:
    """Authenticated application user profile.

    Corresponds to backend UserResponse schema.
    """

    id: str
    username: str
    role: str
    is_active: bool
    created_at: str
    display_name: str | None = None

    @classmethod
    def from_dict(cls, data: Any) -> User:
        """Construct and validate a User instance from a response dictionary.

        Raises:
            ValidationError: If data is not a dict or required fields are missing.
        """
        if not isinstance(data, dict):
            raise ValidationError(
                f"Expected JSON object for user profile, got {type(data).__name__}"
            )

        required_fields = ("id", "username", "role", "is_active", "created_at")
        for field in required_fields:
            if field not in data:
                raise ValidationError(
                    f"Missing required field in user profile: '{field}'"
                )

        user_id = data["id"]
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValidationError("Field 'id' must be a non-empty string")

        username = data["username"]
        if not isinstance(username, str) or not username.strip():
            raise ValidationError("Field 'username' must be a non-empty string")

        role = data["role"]
        if not isinstance(role, str) or not role.strip():
            raise ValidationError("Field 'role' must be a non-empty string")

        is_active = data["is_active"]
        if not isinstance(is_active, bool):
            raise ValidationError("Field 'is_active' must be a boolean")

        created_at = data["created_at"]
        if not isinstance(created_at, str) or not created_at.strip():
            raise ValidationError("Field 'created_at' must be a non-empty string")

        display_name = data.get("display_name")
        if display_name is not None and not isinstance(display_name, str):
            raise ValidationError("Field 'display_name' must be a string or None")

        return cls(
            id=str(user_id),
            username=str(username),
            role=str(role),
            is_active=bool(is_active),
            created_at=str(created_at),
            display_name=display_name,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert model to standard dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class TokenInfo:
    """Access token payload returned upon successful authentication.

    Corresponds to backend TokenResponse schema.
    """

    access_token: str
    token_type: str
    user: User

    @classmethod
    def from_dict(cls, data: Any) -> TokenInfo:
        """Construct and validate a TokenInfo instance from a response dictionary.

        Raises:
            ValidationError: If data is invalid or missing required token fields.
        """
        if not isinstance(data, dict):
            raise ValidationError(
                f"Expected JSON object for token response, got {type(data).__name__}"
            )

        if "access_token" not in data:
            raise ValidationError(
                "Missing required field in token response: 'access_token'"
            )
        access_token = data["access_token"]
        if not isinstance(access_token, str) or not access_token.strip():
            raise ValidationError("Field 'access_token' must be a non-empty string")

        if "token_type" not in data:
            raise ValidationError(
                "Missing required field in token response: 'token_type'"
            )
        token_type = data["token_type"]
        if not isinstance(token_type, str) or not token_type.strip():
            raise ValidationError("Field 'token_type' must be a non-empty string")
        if token_type.strip().lower() != "bearer":
            raise ValidationError(
                f"Unsupported token_type '{token_type}'. Expected 'bearer'"
            )

        if "user" not in data:
            raise ValidationError("Missing required field in token response: 'user'")
        user = User.from_dict(data["user"])

        return cls(
            access_token=str(access_token),
            token_type=str(token_type).lower(),
            user=user,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert model to standard dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class SystemStatus:
    """System health and database connectivity status.

    Corresponds to backend StatusResponse schema from GET /api/status.
    Does not include collector status (which is queried independently).
    """

    status: str
    system: str
    database: str
    host_id: str

    @classmethod
    def from_dict(cls, data: Any) -> SystemStatus:
        """Construct and validate a SystemStatus instance from a response dictionary.

        Raises:
            ValidationError: If data is invalid or missing required status fields.
        """
        if not isinstance(data, dict):
            raise ValidationError(
                f"Expected JSON object for status response, got {type(data).__name__}"
            )

        required_fields = ("status", "system", "database", "host_id")
        for field in required_fields:
            if field not in data:
                raise ValidationError(
                    f"Missing required field in status response: '{field}'"
                )
            val = data[field]
            if not isinstance(val, str) or not val.strip():
                raise ValidationError(f"Field '{field}' must be a non-empty string")

        return cls(
            status=str(data["status"]),
            system=str(data["system"]),
            database=str(data["database"]),
            host_id=str(data["host_id"]),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert model to standard dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class HealthStatus:
    """Basic service liveness status.

    Corresponds to response from GET /health.
    """

    status: str
    system: str

    @classmethod
    def from_dict(cls, data: Any) -> HealthStatus:
        """Construct and validate a HealthStatus instance from a response dictionary.

        Raises:
            ValidationError: If data is invalid or missing required liveness fields.
        """
        if not isinstance(data, dict):
            raise ValidationError(
                f"Expected JSON object for health response, got {type(data).__name__}"
            )

        required_fields = ("status", "system")
        for field in required_fields:
            if field not in data:
                raise ValidationError(
                    f"Missing required field in health response: '{field}'"
                )
            val = data[field]
            if not isinstance(val, str) or not val.strip():
                raise ValidationError(f"Field '{field}' must be a non-empty string")

        return cls(
            status=str(data["status"]),
            system=str(data["system"]),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert model to standard dictionary."""
        return asdict(self)


VALID_SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Event:
    """Single normalized security event.

    Corresponds to backend EventResponse schema from GET /api/events.
    """

    id: str
    host_id: str
    timestamp: str
    ingested_at: str
    source: str
    event_type: str
    action: str
    severity: str
    created_at: str
    process_id: str | None = None
    uid: int | None = None
    username: str | None = None
    pid: int | None = None
    ppid: int | None = None
    command: str | None = None
    object_type: str | None = None
    object_path: str | None = None
    success: bool | None = None
    result: str | None = None
    payload: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: Any) -> Event:
        """Construct and validate an Event instance from a response dictionary.

        Raises:
            ValidationError: If data is not a dict or required fields
                are missing or invalid.
        """
        if not isinstance(data, dict):
            raise ValidationError(
                f"Expected JSON object for event, got {type(data).__name__}"
            )

        required_fields = (
            "id",
            "host_id",
            "timestamp",
            "ingested_at",
            "source",
            "event_type",
            "action",
            "severity",
            "created_at",
        )
        for field in required_fields:
            if field not in data:
                raise ValidationError(
                    f"Missing required field in event: '{field}'"
                )

        raw_id = data["id"]
        try:
            event_id = str(uuid.UUID(str(raw_id)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValidationError(f"Field 'id' must be a valid UUID: {exc}") from exc

        raw_host = data["host_id"]
        try:
            host_id = str(uuid.UUID(str(raw_host)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValidationError(
                f"Field 'host_id' must be a valid UUID: {exc}"
            ) from exc

        for ts_field in ("timestamp", "ingested_at", "created_at"):
            ts_val = data[ts_field]
            if not isinstance(ts_val, str) or not ts_val.strip():
                raise ValidationError(
                    f"Field '{ts_field}' must be a non-empty ISO 8601 string"
                )
            try:
                datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            except Exception as exc:
                raise ValidationError(
                    f"Field '{ts_field}' must be a valid ISO 8601 timestamp: {exc}"
                ) from exc

        for str_field in ("source", "event_type", "action"):
            val = data[str_field]
            if not isinstance(val, str) or not val.strip():
                raise ValidationError(
                    f"Field '{str_field}' must be a non-empty string"
                )

        raw_sev = data["severity"]
        if not isinstance(raw_sev, str) or not raw_sev.strip():
            raise ValidationError("Field 'severity' must be a non-empty string")
        sev_clean = raw_sev.strip().lower()
        if sev_clean not in VALID_SEVERITIES:
            valid_str = ", ".join(VALID_SEVERITIES)
            raise ValidationError(
                f"Invalid severity '{raw_sev}'. Must be one of: {valid_str}"
            )

        process_id = data.get("process_id")
        if process_id is not None:
            try:
                process_id = str(uuid.UUID(str(process_id)))
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValidationError(
                    f"Field 'process_id' must be a valid UUID: {exc}"
                ) from exc

        for int_field in ("uid", "pid", "ppid"):
            int_val = data.get(int_field)
            if int_val is not None:
                if (
                    not isinstance(int_val, int)
                    or isinstance(int_val, bool)
                    or int_val < 0
                ):
                    raise ValidationError(
                        f"Field '{int_field}' must be a non-negative integer or None"
                    )

        for opt_str in ("username", "command", "object_type", "object_path", "result"):
            val = data.get(opt_str)
            if val is not None and not isinstance(val, str):
                raise ValidationError(
                    f"Field '{opt_str}' must be a string or None"
                )

        success = data.get("success")
        if success is not None and not isinstance(success, bool):
            raise ValidationError("Field 'success' must be a boolean or None")

        payload = data.get("payload")
        if payload is not None and not isinstance(payload, dict):
            raise ValidationError("Field 'payload' must be a dict or None")

        return cls(
            id=event_id,
            host_id=host_id,
            timestamp=str(data["timestamp"]),
            ingested_at=str(data["ingested_at"]),
            source=str(data["source"]),
            event_type=str(data["event_type"]),
            action=str(data["action"]),
            severity=sev_clean,
            created_at=str(data["created_at"]),
            process_id=process_id,
            uid=data.get("uid"),
            username=data.get("username"),
            pid=data.get("pid"),
            ppid=data.get("ppid"),
            command=data.get("command"),
            object_type=data.get("object_type"),
            object_path=data.get("object_path"),
            success=success,
            result=data.get("result"),
            payload=payload,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert model to standard dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class EventCollection:
    """Paginated collection of security events.

    Corresponds to backend PaginatedEventResponse schema from GET /api/events.
    """

    total: int
    items: tuple[Event, ...]
    limit: int
    offset: int

    @classmethod
    def from_dict(cls, data: Any) -> EventCollection:
        """Construct and validate an EventCollection from a response dictionary.

        Raises:
            ValidationError: If data is invalid or missing required collection fields.
        """
        if not isinstance(data, dict):
            raise ValidationError(
                f"Expected JSON object for event collection, got {type(data).__name__}"
            )

        required_fields = ("total", "items", "limit", "offset")
        for field in required_fields:
            if field not in data:
                raise ValidationError(
                    f"Missing required field in event collection: '{field}'"
                )

        total = data["total"]
        if not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise ValidationError("Field 'total' must be a non-negative integer")

        limit = data["limit"]
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValidationError("Field 'limit' must be a positive integer (>= 1)")

        offset = data["offset"]
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValidationError("Field 'offset' must be a non-negative integer")

        raw_items = data["items"]
        if not isinstance(raw_items, list):
            raise ValidationError("Field 'items' must be a list of events")

        items = tuple(Event.from_dict(item) for item in raw_items)

        return cls(
            total=total,
            items=items,
            limit=limit,
            offset=offset,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert model to standard dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class Process:
    """Single observed process record.

    Corresponds to backend ProcessResponse schema from GET /api/processes.
    """

    id: str
    host_id: str
    pid: int
    command: str
    started_at: str
    created_at: str
    ppid: int | None = None
    executable: str | None = None
    linux_user_id: str | None = None
    ended_at: str | None = None

    @property
    def is_active(self) -> bool:
        """Return True if the process has not terminated (ended_at is None)."""
        return self.ended_at is None

    @classmethod
    def from_dict(cls, data: Any) -> Process:
        """Construct and validate a Process instance from a response dictionary.

        Raises:
            ValidationError: If data is not a dict or required fields
                are missing or invalid.
        """
        if not isinstance(data, dict):
            raise ValidationError(
                f"Expected JSON object for process, got {type(data).__name__}"
            )

        required_fields = (
            "id",
            "host_id",
            "pid",
            "command",
            "started_at",
            "created_at",
        )
        for field in required_fields:
            if field not in data:
                raise ValidationError(
                    f"Missing required field in process: '{field}'"
                )

        raw_id = data["id"]
        if isinstance(raw_id, bool):
            raise ValidationError("Field 'id' must be a valid UUID")
        try:
            process_id = str(uuid.UUID(str(raw_id)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValidationError(f"Field 'id' must be a valid UUID: {exc}") from exc

        raw_host = data["host_id"]
        if isinstance(raw_host, bool):
            raise ValidationError("Field 'host_id' must be a valid UUID")
        try:
            host_id = str(uuid.UUID(str(raw_host)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValidationError(
                f"Field 'host_id' must be a valid UUID: {exc}"
            ) from exc

        raw_pid = data["pid"]
        if (
            not isinstance(raw_pid, int)
            or isinstance(raw_pid, bool)
            or raw_pid < 0
        ):
            raise ValidationError("Field 'pid' must be a non-negative integer")

        ppid = data.get("ppid")
        if ppid is not None:
            if (
                not isinstance(ppid, int)
                or isinstance(ppid, bool)
                or ppid < 0
            ):
                raise ValidationError(
                    "Field 'ppid' must be a non-negative integer or None"
                )

        raw_cmd = data["command"]
        if not isinstance(raw_cmd, str) or not raw_cmd.strip():
            raise ValidationError("Field 'command' must be a non-empty string")

        executable = data.get("executable")
        if executable is not None and not isinstance(executable, str):
            raise ValidationError("Field 'executable' must be a string or None")

        linux_user_id = data.get("linux_user_id")
        if linux_user_id is not None:
            if isinstance(linux_user_id, bool):
                raise ValidationError(
                    "Field 'linux_user_id' must be a valid UUID or None"
                )
            try:
                linux_user_id = str(uuid.UUID(str(linux_user_id)))
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValidationError(
                    f"Field 'linux_user_id' must be a valid UUID or None: {exc}"
                ) from exc

        for ts_field in ("started_at", "created_at"):
            ts_val = data[ts_field]
            if not isinstance(ts_val, str) or not ts_val.strip():
                raise ValidationError(
                    f"Field '{ts_field}' must be a non-empty ISO 8601 string"
                )
            try:
                datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            except Exception as exc:
                raise ValidationError(
                    f"Field '{ts_field}' must be a valid ISO 8601 timestamp: {exc}"
                ) from exc

        ended_at = data.get("ended_at")
        if ended_at is not None:
            if not isinstance(ended_at, str) or not ended_at.strip():
                raise ValidationError(
                    "Field 'ended_at' must be an ISO 8601 string or None"
                )
            try:
                datetime.fromisoformat(ended_at.replace("Z", "+00:00"))
            except Exception as exc:
                raise ValidationError(
                    f"Field 'ended_at' must be a valid ISO 8601 timestamp: {exc}"
                ) from exc

        return cls(
            id=process_id,
            host_id=host_id,
            pid=raw_pid,
            command=str(raw_cmd),
            started_at=str(data["started_at"]),
            created_at=str(data["created_at"]),
            ppid=ppid,
            executable=executable,
            linux_user_id=linux_user_id,
            ended_at=ended_at,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert model to standard dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class ProcessCollection:
    """Paginated collection of process records.

    Corresponds to backend PaginatedProcessResponse schema from GET /api/processes.
    """

    total: int
    items: tuple[Process, ...]
    limit: int
    offset: int

    @classmethod
    def from_dict(cls, data: Any) -> ProcessCollection:
        """Construct and validate a ProcessCollection from a response dictionary.

        Raises:
            ValidationError: If data is invalid or missing required collection fields.
        """
        if not isinstance(data, dict):
            raise ValidationError(
                "Expected JSON object for process collection, "
                f"got {type(data).__name__}"
            )

        required_fields = ("total", "items", "limit", "offset")
        for field in required_fields:
            if field not in data:
                raise ValidationError(
                    f"Missing required field in process collection: '{field}'"
                )

        total = data["total"]
        if not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise ValidationError("Field 'total' must be a non-negative integer")

        limit = data["limit"]
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValidationError("Field 'limit' must be a positive integer (>= 1)")

        offset = data["offset"]
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValidationError("Field 'offset' must be a non-negative integer")

        raw_items = data["items"]
        if not isinstance(raw_items, list):
            raise ValidationError("Field 'items' must be a list of processes")

        items = tuple(Process.from_dict(item) for item in raw_items)

        return cls(
            total=total,
            items=items,
            limit=limit,
            offset=offset,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert model to standard dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class ResourceSnapshot:
    """Single point-in-time system resource snapshot.

    Corresponds to backend ResourceSnapshotResponse schema from GET /api/resources.
    """

    id: str
    host_id: str
    timestamp: str
    created_at: str
    cpu_percent: float | None = None
    memory_total: int | None = None
    memory_used: int | None = None
    memory_percent: float | None = None
    disk_read_bytes: int | None = None
    disk_write_bytes: int | None = None
    disk_usage_percent: float | None = None

    @classmethod
    def from_dict(cls, data: Any) -> ResourceSnapshot:
        """Construct and validate a ResourceSnapshot from a response dict.

        Raises:
            ValidationError: If data is not a dict or required fields
                are missing or invalid.
        """
        if not isinstance(data, dict):
            raise ValidationError(
                "Expected JSON object for resource snapshot, "
                f"got {type(data).__name__}"
            )

        required_fields = ("id", "host_id", "timestamp", "created_at")
        for field in required_fields:
            if field not in data:
                raise ValidationError(
                    f"Missing required field in resource snapshot: '{field}'"
                )

        raw_id = data["id"]
        if isinstance(raw_id, bool):
            raise ValidationError("Field 'id' must be a valid UUID")
        try:
            snapshot_id = str(uuid.UUID(str(raw_id)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValidationError(f"Field 'id' must be a valid UUID: {exc}") from exc

        raw_host = data["host_id"]
        if isinstance(raw_host, bool):
            raise ValidationError("Field 'host_id' must be a valid UUID")
        try:
            host_id = str(uuid.UUID(str(raw_host)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValidationError(
                f"Field 'host_id' must be a valid UUID: {exc}"
            ) from exc

        for ts_field in ("timestamp", "created_at"):
            ts_val = data[ts_field]
            if not isinstance(ts_val, str) or not ts_val.strip():
                raise ValidationError(
                    f"Field '{ts_field}' must be a non-empty ISO 8601 string"
                )
            try:
                datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            except Exception as exc:
                raise ValidationError(
                    f"Field '{ts_field}' must be a valid ISO 8601 timestamp: {exc}"
                ) from exc

        percentages: dict[str, float | None] = {}
        for pct_field in ("cpu_percent", "memory_percent", "disk_usage_percent"):
            val = data.get(pct_field)
            if val is not None:
                if isinstance(val, bool) or not isinstance(val, (int, float)):
                    raise ValidationError(
                        f"Field '{pct_field}' must be a float "
                        "between 0.0 and 100.0 or None"
                    )
                fval = float(val)
                if not (0.0 <= fval <= 100.0):
                    raise ValidationError(
                        f"Field '{pct_field}' must be between 0.0 and 100.0"
                    )
                percentages[pct_field] = fval
            else:
                percentages[pct_field] = None

        int_metrics: dict[str, int | None] = {}
        for int_field in (
            "memory_total",
            "memory_used",
            "disk_read_bytes",
            "disk_write_bytes",
        ):
            val = data.get(int_field)
            if val is not None:
                if isinstance(val, bool) or not isinstance(val, int):
                    raise ValidationError(
                        f"Field '{int_field}' must be a non-negative integer or None"
                    )
                if val < 0:
                    raise ValidationError(
                        f"Field '{int_field}' must be a non-negative integer or None"
                    )
                int_metrics[int_field] = val
            else:
                int_metrics[int_field] = None

        return cls(
            id=snapshot_id,
            host_id=host_id,
            timestamp=str(data["timestamp"]),
            created_at=str(data["created_at"]),
            cpu_percent=percentages["cpu_percent"],
            memory_total=int_metrics["memory_total"],
            memory_used=int_metrics["memory_used"],
            memory_percent=percentages["memory_percent"],
            disk_read_bytes=int_metrics["disk_read_bytes"],
            disk_write_bytes=int_metrics["disk_write_bytes"],
            disk_usage_percent=percentages["disk_usage_percent"],
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert model to standard dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class ResourceSnapshotCollection:
    """Paginated collection of resource snapshots.

    Corresponds to backend PaginatedResourceSnapshotResponse schema
    from GET /api/resources.
    """

    total: int
    items: tuple[ResourceSnapshot, ...]
    limit: int
    offset: int

    @classmethod
    def from_dict(cls, data: Any) -> ResourceSnapshotCollection:
        """Construct and validate a ResourceSnapshotCollection from a response dict.

        Raises:
            ValidationError: If data is invalid or missing required collection fields.
        """
        if not isinstance(data, dict):
            raise ValidationError(
                "Expected JSON object for resource snapshot collection, "
                f"got {type(data).__name__}"
            )

        required_fields = ("total", "items", "limit", "offset")
        for field in required_fields:
            if field not in data:
                raise ValidationError(
                    f"Missing required field in resource snapshot collection: '{field}'"
                )

        total = data["total"]
        if not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise ValidationError("Field 'total' must be a non-negative integer")

        limit = data["limit"]
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValidationError("Field 'limit' must be a positive integer (>= 1)")

        offset = data["offset"]
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValidationError("Field 'offset' must be a non-negative integer")

        raw_items = data["items"]
        if not isinstance(raw_items, list):
            raise ValidationError(
                "Field 'items' must be a list of resource snapshots"
            )

        items = tuple(ResourceSnapshot.from_dict(item) for item in raw_items)

        return cls(
            total=total,
            items=items,
            limit=limit,
            offset=offset,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert model to standard dictionary."""
        res = asdict(self)
        res["items"] = list(res["items"])
        return res


VALID_FILE_TYPES: tuple[str, ...] = ("file", "directory")


@dataclass(frozen=True)
class FileRecord:
    """Single observed file record.

    Corresponds to backend FileResponse schema from GET /api/files.
    """

    id: str
    host_id: str
    path: str
    first_seen_at: str
    created_at: str
    inode: int | None = None
    file_type: str | None = None
    last_seen_at: str | None = None

    @classmethod
    def from_dict(cls, data: Any) -> FileRecord:
        """Construct and validate a FileRecord instance from a response dictionary.

        Raises:
            ValidationError: If data is not a dict or required fields
                are missing or invalid.
        """
        if not isinstance(data, dict):
            raise ValidationError(
                f"Expected JSON object for file record, got {type(data).__name__}"
            )

        required_fields = (
            "id",
            "host_id",
            "path",
            "first_seen_at",
            "created_at",
        )
        for field in required_fields:
            if field not in data:
                raise ValidationError(
                    f"Missing required field in file record: '{field}'"
                )

        raw_id = data["id"]
        if isinstance(raw_id, bool):
            raise ValidationError("Field 'id' must be a valid UUID")
        try:
            file_id = str(uuid.UUID(str(raw_id)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValidationError(f"Field 'id' must be a valid UUID: {exc}") from exc

        raw_host = data["host_id"]
        if isinstance(raw_host, bool):
            raise ValidationError("Field 'host_id' must be a valid UUID")
        try:
            host_id = str(uuid.UUID(str(raw_host)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValidationError(
                f"Field 'host_id' must be a valid UUID: {exc}"
            ) from exc

        raw_path = data["path"]
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise ValidationError("Field 'path' must be a non-empty string")

        inode = data.get("inode")
        if inode is not None:
            if (
                not isinstance(inode, int)
                or isinstance(inode, bool)
                or inode < 0
            ):
                raise ValidationError(
                    "Field 'inode' must be a non-negative integer or None"
                )

        file_type = data.get("file_type")
        if file_type is not None:
            if not isinstance(file_type, str):
                raise ValidationError("Field 'file_type' must be a string or None")
            file_type = file_type.strip()
            if not file_type:
                raise ValidationError(
                    "Field 'file_type' must be a non-empty string or None"
                )

        for ts_field in ("first_seen_at", "created_at"):
            ts_val = data[ts_field]
            if not isinstance(ts_val, str) or not ts_val.strip():
                raise ValidationError(
                    f"Field '{ts_field}' must be a non-empty ISO 8601 string"
                )
            try:
                datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            except Exception as exc:
                raise ValidationError(
                    f"Field '{ts_field}' must be a valid ISO 8601 timestamp: {exc}"
                ) from exc

        last_seen_at = data.get("last_seen_at")
        if last_seen_at is not None:
            if not isinstance(last_seen_at, str) or not last_seen_at.strip():
                raise ValidationError(
                    "Field 'last_seen_at' must be an ISO 8601 string or None"
                )
            try:
                datetime.fromisoformat(last_seen_at.replace("Z", "+00:00"))
            except Exception as exc:
                raise ValidationError(
                    f"Field 'last_seen_at' must be a valid ISO 8601 timestamp: {exc}"
                ) from exc

        return cls(
            id=file_id,
            host_id=host_id,
            path=str(raw_path),
            first_seen_at=str(data["first_seen_at"]),
            created_at=str(data["created_at"]),
            inode=inode,
            file_type=file_type,
            last_seen_at=last_seen_at,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert model to standard dictionary."""
        return asdict(self)


File = FileRecord


@dataclass(frozen=True)
class FileCollection:
    """Paginated collection of file records.

    Corresponds to backend PaginatedFileResponse schema from GET /api/files.
    """

    total: int
    items: tuple[FileRecord, ...]
    limit: int
    offset: int

    @classmethod
    def from_dict(cls, data: Any) -> FileCollection:
        """Construct and validate a FileCollection from a response dictionary.

        Raises:
            ValidationError: If data is invalid or missing required collection fields.
        """
        if not isinstance(data, dict):
            raise ValidationError(
                "Expected JSON object for file collection, "
                f"got {type(data).__name__}"
            )

        required_fields = ("total", "items", "limit", "offset")
        for field in required_fields:
            if field not in data:
                raise ValidationError(
                    f"Missing required field in file collection: '{field}'"
                )

        total = data["total"]
        if not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise ValidationError("Field 'total' must be a non-negative integer")

        limit = data["limit"]
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValidationError("Field 'limit' must be a positive integer (>= 1)")

        offset = data["offset"]
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValidationError("Field 'offset' must be a non-negative integer")

        raw_items = data["items"]
        if not isinstance(raw_items, list):
            raise ValidationError("Field 'items' must be a list of file records")

        items = tuple(FileRecord.from_dict(item) for item in raw_items)

        return cls(
            total=total,
            items=items,
            limit=limit,
            offset=offset,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert model to standard dictionary."""
        res = asdict(self)
        res["items"] = list(res["items"])
        return res


FileRecordCollection = FileCollection


__all__ = [
    "Event",
    "EventCollection",
    "File",
    "FileCollection",
    "FileRecord",
    "FileRecordCollection",
    "HealthStatus",
    "Process",
    "ProcessCollection",
    "ResourceSnapshot",
    "ResourceSnapshotCollection",
    "SystemStatus",
    "TokenInfo",
    "User",
    "VALID_FILE_TYPES",
    "VALID_SEVERITIES",
]
