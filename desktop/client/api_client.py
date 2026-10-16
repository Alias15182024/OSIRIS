"""OSIRIS Desktop REST API Client.

Provides APIClient, a production-minded synchronous HTTP client managing
secure base URL validation, token authentication lifecycles, service liveness,
and sanitized error translation.
"""

from __future__ import annotations

import ipaddress
import urllib.parse
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

from desktop.client.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ClientConnectionError,
    ConnectionTimeoutError,
    HTTPResponseError,
    NotFoundError,
    OSIRISClientError,
    ServerError,
    ValidationError,
)
from desktop.client.models import (
    VALID_FILE_TYPES,
    VALID_SEVERITIES,
    Event,
    EventCollection,
    FileCollection,
    HealthStatus,
    Process,
    ProcessCollection,
    ResourceSnapshotCollection,
    SystemStatus,
    TokenInfo,
    User,
)

DEFAULT_BASE_URL: str = "http://127.0.0.1:8001"
DEFAULT_TIMEOUT: float = 10.0


def _is_loopback_host(hostname: str) -> bool:
    """Check if hostname is a recognized loopback address without DNS resolution."""
    clean = hostname.strip().rstrip(".").lower()
    if clean == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(clean)
        return ip.is_loopback
    except ValueError:
        return False


def validate_base_url(url: str, allow_remote: bool = False) -> str:
    """Validate and normalize an API base URL according to strict security rules.

    Rules:
    - Must be a non-empty string.
    - Protocol must be HTTP or HTTPS.
    - Loopback hosts (localhost, 127.0.0.0/8, ::1) are permitted by default.
    - Remote hosts are REJECTED by default unless allow_remote=True.
    - Plain HTTP is permitted ONLY for loopback hosts.
    - Remote hosts REQUIRE HTTPS even when allow_remote=True.
    - Embedded credentials (user:pass@host) are rejected.
    - Query strings and fragments are rejected.
    - Port numbers must be in the range 1-65535.
    - Trailing slashes are stripped for deterministic path construction.

    Raises:
        ValidationError: If the base URL violates any security constraint.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValidationError("Base URL must be a non-empty string")

    raw_url = url.strip()
    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except Exception as exc:
        raise ValidationError(f"Invalid base URL syntax: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValidationError(
            f"Invalid base URL scheme '{scheme}'. Only HTTP and HTTPS are permitted."
        )

    # Reject embedded username / password
    if (
        parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
    ):
        raise ValidationError("Base URL must not contain embedded user credentials")

    # Reject query parameters and fragments
    if parsed.query:
        raise ValidationError("Base URL must not contain query parameters")
    if parsed.fragment:
        raise ValidationError("Base URL must not contain URL fragments")

    # Hostname validation
    hostname = parsed.hostname
    if not hostname:
        raise ValidationError("Base URL must specify a valid host")

    # Port range validation
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValidationError("Base URL specifies an invalid port number") from exc

    if port is not None and not (1 <= port <= 65535):
        raise ValidationError("Port number must be between 1 and 65535")

    # Strict loopback vs remote host rules
    is_loopback = _is_loopback_host(hostname)
    if not is_loopback and not allow_remote:
        raise ValidationError(
            f"Remote API base URL '{raw_url}' is not permitted without explicit "
            "authorization (loopback only: localhost, 127.0.0.1, ::1)"
        )

    # Insecure plain HTTP is only permitted for loopback hosts
    if scheme == "http" and not is_loopback:
        raise ValidationError(
            "Insecure plain HTTP is only permitted for loopback hosts "
            "(localhost, 127.0.0.1, ::1); HTTPS is required for remote hosts."
        )

    norm_path = parsed.path.rstrip("/")
    return f"{scheme}://{parsed.netloc}{norm_path}"


def _normalize_iso_timestamp(
    ts: str | datetime, field_name: str
) -> tuple[str, datetime]:
    """Validate and normalize an ISO 8601 timestamp string or datetime object.

    Returns:
        A tuple of (iso_string, datetime_object).

    Raises:
        ValidationError: If the timestamp is empty or cannot be parsed.
    """
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            dt = ts.replace(tzinfo=timezone.utc)
        else:
            dt = ts
        return dt.isoformat(), dt

    if isinstance(ts, str):
        cleaned = ts.strip()
        if not cleaned:
            raise ValidationError(
                f"{field_name} must be a non-empty string or datetime"
            )
        try:
            dt = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        except Exception as exc:
            raise ValidationError(
                f"Invalid ISO 8601 timestamp format for '{field_name}': {exc}"
            ) from exc
        return cleaned, dt

    raise ValidationError(
        f"'{field_name}' must be an ISO 8601 string or datetime object, "
        f"got {type(ts).__name__}"
    )


class APIClient:
    """Synchronous REST API client for the OSIRIS Desktop application.

    Manages connection lifecycle, token authentication, and endpoint requests
    against the OSIRIS backend API.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        allow_remote: bool = False,
    ) -> None:
        """Initialize the API client without issuing network requests.

        Args:
            base_url: Validated base URL for the backend API.
            timeout: Request timeout in seconds.
            allow_remote: Whether non-loopback remote base URLs are permitted.
        """
        self._allow_remote = bool(allow_remote)
        self._base_url = validate_base_url(base_url, allow_remote=self._allow_remote)
        self._timeout = float(timeout)
        self._token: str | None = None
        self._closed: bool = False
        self._client: httpx.Client | None = httpx.Client(
            base_url=self._base_url,
            timeout=self._timeout,
        )

    # -----------------------------------------------------------------------
    # Lifecycle & Context Management
    # -----------------------------------------------------------------------

    @property
    def base_url(self) -> str:
        """Return the validated normalized base URL."""
        return self._base_url

    @property
    def allow_remote(self) -> bool:
        """Return True if remote base URLs are explicitly authorized."""
        return self._allow_remote

    @property
    def is_authenticated(self) -> bool:
        """Return True if an in-memory access token is currently held."""
        return self._token is not None and not self._closed

    @property
    def is_closed(self) -> bool:
        """Return True if the underlying client session has been closed."""
        return self._closed

    def close(self) -> None:
        """Close the underlying HTTP client and clear in-memory auth state."""
        if not self._closed:
            self._closed = True
            self._token = None
            if self._client is not None:
                self._client.headers.pop("Authorization", None)
                self._client.close()
                self._client = None

    def __enter__(self) -> APIClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _ensure_open(self) -> None:
        """Raise an error if the client has already been closed."""
        if self._closed or self._client is None:
            raise OSIRISClientError("APIClient is closed and cannot perform requests")

    # -----------------------------------------------------------------------
    # Authentication Methods
    # -----------------------------------------------------------------------

    def login(self, username: str, password: str) -> TokenInfo:
        """Authenticate via POST /api/auth/login and store bearer token in memory.

        Clears any prior authentication token before making the attempt.
        Never persists or logs passwords or tokens.

        Args:
            username: User account login name.
            password: User account password.

        Returns:
            Validated TokenInfo payload.

        Raises:
            ValidationError: If input is invalid or response is malformed.
            AuthenticationError: On HTTP 401 invalid credentials.
            AuthorizationError: On HTTP 403 inactive account.
            OSIRISClientError: On transport or server failure.
        """
        self._ensure_open()
        # Always clear existing token before attempting new login
        self._token = None

        if not isinstance(username, str) or not username.strip():
            raise ValidationError("Username must be a non-empty string")
        if not isinstance(password, str) or not password:
            raise ValidationError("Password must be a non-empty string")

        payload = {"username": username.strip(), "password": password}
        resp = self._request(
            "POST",
            "/api/auth/login",
            json=payload,
            is_authenticated_request=False,
        )
        data = self._parse_json(resp)
        token_info = TokenInfo.from_dict(data)

        # Store token only after successful validation
        self._token = token_info.access_token
        return token_info

    def get_current_user(self) -> User:
        """Retrieve profile of currently authenticated user from GET /api/auth/me.

        Returns:
            Validated User profile.

        Raises:
            AuthenticationError: If unauthenticated or token expired/invalid.
            AuthorizationError: If user account is deactivated (HTTP 403).
            OSIRISClientError: On transport or server failure.
        """
        self._ensure_open()
        if self._token is None:
            raise AuthenticationError("Not authenticated; login required")

        headers = {"Authorization": f"Bearer {self._token}"}
        resp = self._request(
            "GET",
            "/api/auth/me",
            headers=headers,
            is_authenticated_request=True,
        )
        data = self._parse_json(resp)
        return User.from_dict(data)

    def logout(self) -> None:
        """Clear all in-memory authentication state without issuing network requests."""
        self._token = None
        if self._client is not None:
            self._client.headers.pop("Authorization", None)

    # -----------------------------------------------------------------------
    # System Status & Health Methods
    # -----------------------------------------------------------------------

    def get_status(self) -> SystemStatus:
        """Retrieve overall system health and database status from GET /api/status.

        Returns:
            Validated SystemStatus response.
        """
        self._ensure_open()
        resp = self._request("GET", "/api/status", is_authenticated_request=False)
        data = self._parse_json(resp)
        return SystemStatus.from_dict(data)

    def health_check(self) -> HealthStatus:
        """Perform basic service liveness check against GET /health.

        Returns:
            Validated HealthStatus response.
        """
        self._ensure_open()
        resp = self._request("GET", "/health", is_authenticated_request=False)
        data = self._parse_json(resp)
        return HealthStatus.from_dict(data)

    def get_health(self) -> HealthStatus:
        """Retrieve service liveness from GET /health.

        Alias for health_check().

        Returns:
            Validated HealthStatus response.
        """
        return self.health_check()

    # -----------------------------------------------------------------------
    # Security Events Methods
    # -----------------------------------------------------------------------

    def get_events(
        self,
        *,
        host_id: str | uuid.UUID | None = None,
        start_time: str | datetime | None = None,
        end_time: str | datetime | None = None,
        source: str | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        process_id: str | uuid.UUID | None = None,
        pid: int | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> EventCollection:
        """Retrieve paginated security events from GET /api/events.

        Args:
            host_id: Filter by monitored host UUID.
            start_time: Earliest timestamp (inclusive), ISO string or datetime.
            end_time: Latest timestamp (inclusive), ISO string or datetime.
            source: Filter by collector source (e.g. 'proc', 'fs', 'resource').
            event_type: Filter by event type identifier (e.g. 'process.start').
            severity: Filter by canonical severity level.
            process_id: Filter by internal process UUID.
            pid: Filter by Linux process ID (supports pid=0).
            limit: Maximum items per page (1 to 100, default 50).
            offset: Page offset (>= 0, default 0).

        Returns:
            Validated EventCollection with items and pagination metadata.

        Raises:
            AuthenticationError: If client is not authenticated (HTTP 401).
            AuthorizationError: If account lacks permissions (HTTP 403).
            ValidationError: If input parameters or response data are invalid.
            OSIRISClientError: On transport or server failure.
        """
        self._ensure_open()
        if self._token is None:
            raise AuthenticationError("Not authenticated; login required")

        # Validate pagination constraints
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not (1 <= limit <= 100)
        ):
            raise ValidationError("limit must be an integer between 1 and 100")
        if (
            not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset < 0
        ):
            raise ValidationError("offset must be a non-negative integer")

        params: dict[str, Any] = {"limit": limit, "offset": offset}

        if host_id is not None:
            try:
                params["host_id"] = str(uuid.UUID(str(host_id)))
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValidationError(f"Invalid host_id UUID: {exc}") from exc

        if process_id is not None:
            try:
                params["process_id"] = str(uuid.UUID(str(process_id)))
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValidationError(f"Invalid process_id UUID: {exc}") from exc

        if source is not None:
            if not isinstance(source, str) or not source.strip():
                raise ValidationError("source must be a non-empty string")
            params["source"] = source.strip()

        if event_type is not None:
            if not isinstance(event_type, str) or not event_type.strip():
                raise ValidationError("event_type must be a non-empty string")
            params["event_type"] = event_type.strip()

        if severity is not None:
            if not isinstance(severity, str) or not severity.strip():
                raise ValidationError("severity must be a non-empty string")
            sev_clean = severity.strip().lower()
            if sev_clean not in VALID_SEVERITIES:
                valid_str = ", ".join(VALID_SEVERITIES)
                raise ValidationError(
                    f"Invalid severity '{severity}'. Must be one of: {valid_str}"
                )
            params["severity"] = sev_clean

        if pid is not None:
            if not isinstance(pid, int) or isinstance(pid, bool) or pid < 0:
                raise ValidationError("pid must be a non-negative integer")
            params["pid"] = pid

        start_dt = None
        if start_time is not None:
            start_str, start_dt = _normalize_iso_timestamp(start_time, "start_time")
            params["start_time"] = start_str

        end_dt = None
        if end_time is not None:
            end_str, end_dt = _normalize_iso_timestamp(end_time, "end_time")
            params["end_time"] = end_str

        if start_dt is not None and end_dt is not None:
            c_start = (
                start_dt
                if start_dt.tzinfo is not None
                else start_dt.replace(tzinfo=timezone.utc)
            )
            c_end = (
                end_dt
                if end_dt.tzinfo is not None
                else end_dt.replace(tzinfo=timezone.utc)
            )
            if c_start > c_end:
                raise ValidationError(
                    "start_time must be less than or equal to end_time"
                )

        headers = {"Authorization": f"Bearer {self._token}"}
        resp = self._request(
            "GET",
            "/api/events",
            headers=headers,
            params=params,
            is_authenticated_request=True,
        )
        data = self._parse_json(resp)
        return EventCollection.from_dict(data)

    def get_event(self, event_id: str | uuid.UUID) -> Event:
        """Retrieve a single normalized security event from GET /api/events/{event_id}.

        Args:
            event_id: UUID of the event to retrieve.

        Returns:
            Validated Event response.

        Raises:
            AuthenticationError: If client is not authenticated (HTTP 401).
            AuthorizationError: If account lacks permissions (HTTP 403).
            HTTPResponseError: If event does not exist (HTTP 404).
            ValidationError: If event_id is invalid UUID or response is malformed.
            OSIRISClientError: On transport or server failure.
        """
        self._ensure_open()
        if self._token is None:
            raise AuthenticationError("Not authenticated; login required")

        if event_id is None or (isinstance(event_id, str) and not event_id.strip()):
            raise ValidationError("event_id must be a non-empty string or UUID")

        try:
            clean_id = str(uuid.UUID(str(event_id)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValidationError(f"Invalid event_id UUID: {exc}") from exc

        headers = {"Authorization": f"Bearer {self._token}"}
        resp = self._request(
            "GET",
            f"/api/events/{clean_id}",
            headers=headers,
            is_authenticated_request=True,
        )
        data = self._parse_json(resp)
        return Event.from_dict(data)

    # -----------------------------------------------------------------------
    # Process Methods
    # -----------------------------------------------------------------------

    def get_processes(
        self,
        *,
        host_id: str | uuid.UUID | None = None,
        pid: int | None = None,
        is_active: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> ProcessCollection:
        """Retrieve paginated observed processes from GET /api/processes.

        Args:
            host_id: Filter by monitored host UUID.
            pid: Filter by Linux process ID (supports pid=0).
            is_active: Filter by active lifecycle status (True for running,
                False for terminated).
            limit: Maximum items per page (1 to 100, default 50).
            offset: Page offset (>= 0, default 0).

        Returns:
            Validated ProcessCollection with items and pagination metadata.

        Raises:
            AuthenticationError: If client is not authenticated (HTTP 401).
            AuthorizationError: If account lacks permissions (HTTP 403).
            ValidationError: If input parameters or response data are invalid.
            OSIRISClientError: On transport or server failure.
        """
        self._ensure_open()
        if self._token is None:
            raise AuthenticationError("Not authenticated; login required")

        # Validate pagination constraints
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not (1 <= limit <= 100)
        ):
            raise ValidationError("limit must be an integer between 1 and 100")
        if (
            not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset < 0
        ):
            raise ValidationError("offset must be a non-negative integer")

        params: dict[str, Any] = {"limit": limit, "offset": offset}

        if host_id is not None:
            if isinstance(host_id, bool):
                raise ValidationError("Invalid host_id UUID")
            try:
                params["host_id"] = str(uuid.UUID(str(host_id)))
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValidationError(f"Invalid host_id UUID: {exc}") from exc

        if pid is not None:
            if not isinstance(pid, int) or isinstance(pid, bool) or pid < 0:
                raise ValidationError("pid must be a non-negative integer")
            params["pid"] = pid

        if is_active is not None:
            if not isinstance(is_active, bool):
                raise ValidationError("is_active must be a boolean or None")
            params["is_active"] = is_active

        headers = {"Authorization": f"Bearer {self._token}"}
        resp = self._request(
            "GET",
            "/api/processes",
            headers=headers,
            params=params,
            is_authenticated_request=True,
        )
        data = self._parse_json(resp)
        return ProcessCollection.from_dict(data)

    def get_process(self, process_id: str | uuid.UUID) -> Process:
        """Retrieve a single observed process from GET /api/processes/{process_id}.

        Args:
            process_id: OSIRIS UUID identity of the process to retrieve.

        Returns:
            Validated Process response.

        Raises:
            AuthenticationError: If client is not authenticated (HTTP 401).
            AuthorizationError: If account lacks permissions (HTTP 403).
            HTTPResponseError: If process does not exist (HTTP 404).
            ValidationError: If process_id is invalid UUID or response is malformed.
            OSIRISClientError: On transport or server failure.
        """
        self._ensure_open()
        if self._token is None:
            raise AuthenticationError("Not authenticated; login required")

        if process_id is None or (
            isinstance(process_id, str) and not process_id.strip()
        ):
            raise ValidationError("process_id must be a non-empty string or UUID")

        if isinstance(process_id, bool):
            raise ValidationError("process_id must be a non-empty string or UUID")

        try:
            clean_id = str(uuid.UUID(str(process_id)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValidationError(f"Invalid process_id UUID: {exc}") from exc

        headers = {"Authorization": f"Bearer {self._token}"}
        resp = self._request(
            "GET",
            f"/api/processes/{clean_id}",
            headers=headers,
            is_authenticated_request=True,
        )
        data = self._parse_json(resp)
        return Process.from_dict(data)

    # -----------------------------------------------------------------------
    # Resource Snapshot Methods
    # -----------------------------------------------------------------------

    def get_resources(
        self,
        *,
        host_id: str | uuid.UUID | None = None,
        start_time: str | datetime | None = None,
        end_time: str | datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> ResourceSnapshotCollection:
        """Retrieve paginated resource snapshots from GET /api/resources.

        Args:
            host_id: Filter by monitored host UUID.
            start_time: Earliest timestamp (inclusive), ISO string or datetime.
            end_time: Latest timestamp (inclusive), ISO string or datetime.
            limit: Maximum items per page (1 to 100, default 50).
            offset: Page offset (>= 0, default 0).

        Returns:
            Validated ResourceSnapshotCollection with items and pagination metadata.

        Raises:
            AuthenticationError: If client is not authenticated (HTTP 401).
            AuthorizationError: If account lacks permissions (HTTP 403).
            ValidationError: If input parameters or response data are invalid.
            OSIRISClientError: On transport or server failure.
        """
        self._ensure_open()
        if self._token is None:
            raise AuthenticationError("Not authenticated; login required")

        # Validate pagination constraints
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not (1 <= limit <= 100)
        ):
            raise ValidationError("limit must be an integer between 1 and 100")
        if (
            not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset < 0
        ):
            raise ValidationError("offset must be a non-negative integer")

        params: dict[str, Any] = {"limit": limit, "offset": offset}

        if host_id is not None:
            if isinstance(host_id, bool):
                raise ValidationError("Invalid host_id UUID")
            try:
                params["host_id"] = str(uuid.UUID(str(host_id)))
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValidationError(f"Invalid host_id UUID: {exc}") from exc

        start_dt = None
        if start_time is not None:
            start_str, start_dt = _normalize_iso_timestamp(start_time, "start_time")
            params["start_time"] = start_str

        end_dt = None
        if end_time is not None:
            end_str, end_dt = _normalize_iso_timestamp(end_time, "end_time")
            params["end_time"] = end_str

        if start_dt is not None and end_dt is not None:
            c_start = (
                start_dt
                if start_dt.tzinfo is not None
                else start_dt.replace(tzinfo=timezone.utc)
            )
            c_end = (
                end_dt
                if end_dt.tzinfo is not None
                else end_dt.replace(tzinfo=timezone.utc)
            )
            if c_start > c_end:
                raise ValidationError(
                    "start_time must be less than or equal to end_time"
                )

        headers = {"Authorization": f"Bearer {self._token}"}
        resp = self._request(
            "GET",
            "/api/resources",
            headers=headers,
            params=params,
            is_authenticated_request=True,
        )
        data = self._parse_json(resp)
        return ResourceSnapshotCollection.from_dict(data)

    # -----------------------------------------------------------------------
    # Files Methods
    # -----------------------------------------------------------------------

    def get_files(
        self,
        *,
        host_id: str | uuid.UUID | None = None,
        path: str | None = None,
        file_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> FileCollection:
        """Retrieve paginated observed files from GET /api/files.

        Args:
            host_id: Filter by monitored host UUID.
            path: Filter by path prefix.
            file_type: Filter by exact file type ('file' or 'directory').
            limit: Maximum items per page (1 to 100, default 50).
            offset: Page offset (>= 0, default 0).

        Returns:
            Validated FileCollection with items and pagination metadata.

        Raises:
            AuthenticationError: If client is not authenticated (HTTP 401).
            AuthorizationError: If account lacks permissions (HTTP 403).
            ValidationError: If input parameters or response data are invalid.
            OSIRISClientError: On transport or server failure.
        """
        self._ensure_open()
        if self._token is None:
            raise AuthenticationError("Not authenticated; login required")

        # Validate pagination constraints
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not (1 <= limit <= 100)
        ):
            raise ValidationError("limit must be an integer between 1 and 100")
        if (
            not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset < 0
        ):
            raise ValidationError("offset must be a non-negative integer")

        params: dict[str, Any] = {"limit": limit, "offset": offset}

        if host_id is not None:
            if isinstance(host_id, bool):
                raise ValidationError("Invalid host_id UUID")
            try:
                params["host_id"] = str(uuid.UUID(str(host_id)))
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValidationError(f"Invalid host_id UUID: {exc}") from exc

        if path is not None:
            if not isinstance(path, str) or not path.strip():
                raise ValidationError("path must be a non-empty string")
            params["path"] = path.strip()

        if file_type is not None:
            if not isinstance(file_type, str) or not file_type.strip():
                raise ValidationError("file_type must be a non-empty string")
            clean_type = file_type.strip().lower()
            if clean_type not in VALID_FILE_TYPES:
                valid_str = ", ".join(VALID_FILE_TYPES)
                raise ValidationError(
                    f"Invalid file_type '{file_type}'. Must be one of: {valid_str}"
                )
            params["file_type"] = clean_type

        headers = {"Authorization": f"Bearer {self._token}"}
        resp = self._request(
            "GET",
            "/api/files",
            headers=headers,
            params=params,
            is_authenticated_request=True,
        )
        data = self._parse_json(resp)
        return FileCollection.from_dict(data)

    # -----------------------------------------------------------------------
    # Internal Request & Error Handling
    # -----------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json: Any = None,
        is_authenticated_request: bool = False,
    ) -> httpx.Response:
        """Execute an HTTP request and map transport errors to sanitized exceptions."""
        self._ensure_open()
        assert self._client is not None

        url = f"{self._base_url}/{path.lstrip('/')}"

        try:
            resp = self._client.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json,
            )
        except httpx.TimeoutException as exc:
            raise ConnectionTimeoutError(
                "Connection timed out while contacting server"
            ) from exc
        except (httpx.NetworkError, httpx.ConnectError) as exc:
            raise ClientConnectionError(
                "Network connection failure while contacting server"
            ) from exc
        except httpx.HTTPError as exc:
            raise ClientConnectionError(
                "HTTP transport failure while contacting server"
            ) from exc

        if resp.is_success:
            return resp

        # Map HTTP errors
        error_msg = self._extract_error_detail(resp)
        status_code = resp.status_code

        if status_code == 401:
            if is_authenticated_request:
                # Clear stored token and scrub header when an authenticated
                # request returns 401
                self._token = None
                if self._client is not None:
                    self._client.headers.pop("Authorization", None)
            raise AuthenticationError(error_msg, status_code=401)
        if status_code == 403:
            # Do NOT clear token on 403 (authorization failure)
            raise AuthorizationError(error_msg, status_code=403)
        if status_code == 404:
            raise NotFoundError(error_msg, status_code=404)
        if 500 <= status_code <= 599:
            raise ServerError(error_msg, status_code=status_code)

        raise HTTPResponseError(error_msg, status_code=status_code)

    def _parse_json(self, resp: httpx.Response) -> dict[str, Any]:
        """Safely parse response JSON into a dictionary."""
        try:
            data = resp.json()
        except Exception as exc:
            raise ValidationError("Server response is not valid JSON") from exc

        if not isinstance(data, dict):
            raise ValidationError(
                f"Expected JSON object in server response, got {type(data).__name__}"
            )
        return data

    def _extract_error_detail(self, resp: httpx.Response) -> str:
        """Extract sanitized error detail from response body if available."""
        try:
            data = resp.json()
            if isinstance(data, dict):
                detail = data.get("detail")
                if isinstance(detail, str) and detail.strip():
                    return detail.strip()
                if isinstance(detail, list):
                    msgs = [
                        str(item.get("msg"))
                        for item in detail
                        if isinstance(item, dict) and "msg" in item
                    ]
                    if msgs:
                        return "; ".join(msgs)
        except Exception:
            pass

        return f"Request failed with status HTTP {resp.status_code}"


__all__ = [
    "APIClient",
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT",
    "validate_base_url",
]
