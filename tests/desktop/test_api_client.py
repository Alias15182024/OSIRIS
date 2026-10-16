"""Unit tests for the OSIRIS Desktop secure REST API client.

Tests cover:
A. URL security rules and normalization.
B. Response model validation and error handling.
C. Successful authentication lifecycle.
D. Failed authentication lifecycle.
E. System status and health checks.
F. Transport, timeout, and HTTP failure mapping.
G. Client resource lifecycle and context management.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest
import respx

from desktop.client import (
    DEFAULT_BASE_URL,
    APIClient,
    AuthenticationError,
    AuthorizationError,
    ClientConnectionError,
    ConnectionError,
    ConnectionTimeoutError,
    HealthStatus,
    HTTPResponseError,
    OSIRISClientError,
    SystemStatus,
    TokenInfo,
    User,
    ValidationError,
    validate_base_url,
)
from desktop.client.api_client import _normalize_iso_timestamp

# Test constants
SAMPLE_USER_DICT = {
    "id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "username": "analyst_alice",
    "display_name": "Alice Analyst",
    "role": "analyst",
    "is_active": True,
    "created_at": "2026-10-13T12:00:00Z",
}

SAMPLE_TOKEN_DICT = {
    "access_token": "secret.jwt.token",
    "token_type": "bearer",
    "user": SAMPLE_USER_DICT,
}

SAMPLE_STATUS_DICT = {
    "status": "healthy",
    "system": "osiris",
    "database": "connected",
    "host_id": "osiris-host-01",
}

SAMPLE_HEALTH_DICT = {
    "status": "ok",
    "system": "osiris",
}


# ============================================================================
# A. URL & Security Validation Tests
# ============================================================================


class TestBaseURLValidation:
    """Tests for validate_base_url security rules and normalization."""

    def test_default_base_url_is_valid(self) -> None:
        assert validate_base_url(DEFAULT_BASE_URL) == "http://127.0.0.1:8001"

    def test_valid_http_loopback_hosts(self) -> None:
        assert validate_base_url("http://127.0.0.1:8001") == "http://127.0.0.1:8001"
        assert validate_base_url("http://localhost:8001") == "http://localhost:8001"
        assert validate_base_url("http://localhost") == "http://localhost"
        assert validate_base_url("http://127.0.0.2:8080") == "http://127.0.0.2:8080"

    def test_valid_ipv6_loopback_syntax(self) -> None:
        assert validate_base_url("http://[::1]:8001") == "http://[::1]:8001"
        assert validate_base_url("http://[::1]") == "http://[::1]"
        assert validate_base_url("https://[::1]:8443") == "https://[::1]:8443"

    def test_valid_https_remote_hosts(self) -> None:
        assert (
            validate_base_url("https://api.osiris-sec.org", allow_remote=True)
            == "https://api.osiris-sec.org"
        )
        assert (
            validate_base_url("https://soc.corp:8443/api", allow_remote=True)
            == "https://soc.corp:8443/api"
        )
        assert (
            validate_base_url("https://10.0.0.5:8443", allow_remote=True)
            == "https://10.0.0.5:8443"
        )

    def test_reject_remote_hosts_by_default(self) -> None:
        with pytest.raises(ValidationError, match="Remote API base URL"):
            validate_base_url("https://api.osiris-sec.org")

        with pytest.raises(ValidationError, match="Remote API base URL"):
            validate_base_url("https://10.0.0.5:8443")

        with pytest.raises(ValidationError, match="Remote API base URL"):
            validate_base_url("http://192.168.1.50:8001")

    def test_reject_insecure_http_on_remote_hosts(self) -> None:
        with pytest.raises(ValidationError, match="Insecure plain HTTP"):
            validate_base_url("http://osiris.remote.com:8001", allow_remote=True)

        with pytest.raises(ValidationError, match="Insecure plain HTTP"):
            validate_base_url("http://192.168.1.50:8001", allow_remote=True)

        with pytest.raises(ValidationError, match="Insecure plain HTTP"):
            validate_base_url("http://10.0.0.1:8001", allow_remote=True)

    def test_reject_embedded_credentials(self) -> None:
        with pytest.raises(ValidationError, match="embedded user credentials"):
            validate_base_url("http://admin:secret@127.0.0.1:8001")

        with pytest.raises(ValidationError, match="embedded user credentials"):
            validate_base_url("https://user@osiris.example.com", allow_remote=True)

    def test_reject_query_parameters_and_fragments(self) -> None:
        with pytest.raises(ValidationError, match="query parameters"):
            validate_base_url("http://127.0.0.1:8001?env=prod")

        with pytest.raises(ValidationError, match="URL fragments"):
            validate_base_url("http://127.0.0.1:8001#section")

    def test_reject_invalid_schemes(self) -> None:
        with pytest.raises(ValidationError, match="Only HTTP and HTTPS"):
            validate_base_url("ftp://127.0.0.1:8001")

        with pytest.raises(ValidationError, match="Only HTTP and HTTPS"):
            validate_base_url("ws://127.0.0.1:8001")

    def test_reject_malformed_and_empty_urls(self) -> None:
        with pytest.raises(ValidationError, match="non-empty string"):
            validate_base_url("")

        with pytest.raises(ValidationError, match="non-empty string"):
            validate_base_url("   ")

        with pytest.raises(ValidationError):
            validate_base_url("://bad-url")

    def test_reject_invalid_port_numbers(self) -> None:
        with pytest.raises(ValidationError, match="Port"):
            validate_base_url("http://127.0.0.1:0")

        with pytest.raises(ValidationError, match="invalid port"):
            validate_base_url("http://127.0.0.1:99999")

    def test_deterministic_trailing_slash_normalization(self) -> None:
        assert validate_base_url("http://127.0.0.1:8001/") == "http://127.0.0.1:8001"
        assert validate_base_url("http://127.0.0.1:8001///") == "http://127.0.0.1:8001"
        assert (
            validate_base_url("https://soc.org/api/v1/", allow_remote=True)
            == "https://soc.org/api/v1"
        )


# ============================================================================
# B. Model Validation Tests
# ============================================================================


class TestModelValidation:
    """Tests for User, TokenInfo, SystemStatus, and HealthStatus models."""

    def test_user_valid_construction(self) -> None:
        user = User.from_dict(SAMPLE_USER_DICT)
        assert user.id == "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"
        assert user.username == "analyst_alice"
        assert user.display_name == "Alice Analyst"
        assert user.role == "analyst"
        assert user.is_active is True
        assert user.created_at == "2026-10-13T12:00:00Z"
        assert user.to_dict()["username"] == "analyst_alice"

    def test_user_optional_display_name_none(self) -> None:
        data = dict(SAMPLE_USER_DICT)
        data["display_name"] = None
        user = User.from_dict(data)
        assert user.display_name is None

    def test_user_missing_required_fields_raises(self) -> None:
        for field in ("id", "username", "role", "is_active", "created_at"):
            data = dict(SAMPLE_USER_DICT)
            del data[field]
            with pytest.raises(
                ValidationError, match=f"Missing required field.*{field}"
            ):
                User.from_dict(data)

    def test_user_invalid_types_raises(self) -> None:
        data = dict(SAMPLE_USER_DICT)
        data["is_active"] = "yes"  # Not a bool
        with pytest.raises(ValidationError, match="must be a boolean"):
            User.from_dict(data)

        data = dict(SAMPLE_USER_DICT)
        data["display_name"] = 12345
        with pytest.raises(ValidationError, match="must be a string or None"):
            User.from_dict(data)

    def test_token_info_valid_construction(self) -> None:
        token_info = TokenInfo.from_dict(SAMPLE_TOKEN_DICT)
        assert token_info.access_token == "secret.jwt.token"
        assert token_info.token_type == "bearer"
        assert token_info.user.username == "analyst_alice"
        assert token_info.to_dict()["access_token"] == "secret.jwt.token"

    def test_token_info_case_insensitive_bearer(self) -> None:
        data = dict(SAMPLE_TOKEN_DICT)
        data["token_type"] = "Bearer"
        token_info = TokenInfo.from_dict(data)
        assert token_info.token_type == "bearer"

    def test_token_info_unsupported_token_type_raises(self) -> None:
        data = dict(SAMPLE_TOKEN_DICT)
        data["token_type"] = "basic"
        with pytest.raises(ValidationError, match="Unsupported token_type"):
            TokenInfo.from_dict(data)

    def test_token_info_missing_fields_raises(self) -> None:
        with pytest.raises(ValidationError, match="access_token"):
            TokenInfo.from_dict({"token_type": "bearer", "user": SAMPLE_USER_DICT})

        with pytest.raises(ValidationError, match="user"):
            TokenInfo.from_dict({"access_token": "tok", "token_type": "bearer"})

    def test_system_status_valid_construction(self) -> None:
        status = SystemStatus.from_dict(SAMPLE_STATUS_DICT)
        assert status.status == "healthy"
        assert status.system == "osiris"
        assert status.database == "connected"
        assert status.host_id == "osiris-host-01"
        assert not hasattr(status, "collector")

    def test_system_status_missing_field_raises(self) -> None:
        data = dict(SAMPLE_STATUS_DICT)
        del data["database"]
        with pytest.raises(ValidationError, match="database"):
            SystemStatus.from_dict(data)

    def test_health_status_valid_construction(self) -> None:
        health = HealthStatus.from_dict(SAMPLE_HEALTH_DICT)
        assert health.status == "ok"
        assert health.system == "osiris"

    def test_health_status_missing_field_raises(self) -> None:
        with pytest.raises(ValidationError, match="status"):
            HealthStatus.from_dict({"system": "osiris"})

    def test_validation_errors_do_not_leak_secret_payloads(self) -> None:
        secret = "SecretPassword!123"
        with pytest.raises(ValidationError) as exc_info:
            User.from_dict({"bad": secret})
        assert secret not in str(exc_info.value)


# ============================================================================
# C. Successful Authentication Lifecycle Tests
# ============================================================================


class TestSuccessfulAuthentication:
    """Tests for login, current-user retrieval, and logout flows."""

    @respx.mock
    def test_login_successful_flow(self) -> None:
        respx.post("http://127.0.0.1:8001/api/auth/login").mock(
            return_value=httpx.Response(200, json=SAMPLE_TOKEN_DICT)
        )

        client = APIClient()
        assert not client.is_authenticated

        token_info = client.login("analyst_alice", "ValidPassword123!")
        assert isinstance(token_info, TokenInfo)
        assert token_info.access_token == "secret.jwt.token"
        assert client.is_authenticated is True

    @respx.mock
    def test_get_current_user_includes_bearer_header(self) -> None:
        respx.post("http://127.0.0.1:8001/api/auth/login").mock(
            return_value=httpx.Response(200, json=SAMPLE_TOKEN_DICT)
        )
        me_route = respx.get("http://127.0.0.1:8001/api/auth/me").mock(
            return_value=httpx.Response(200, json=SAMPLE_USER_DICT)
        )

        client = APIClient()
        client.login("analyst_alice", "ValidPassword123!")

        user = client.get_current_user()
        assert isinstance(user, User)
        assert user.username == "analyst_alice"

        assert me_route.called
        sent_request = me_route.calls.last.request
        assert sent_request.headers["authorization"] == "Bearer secret.jwt.token"

    def test_logout_clears_authentication_state(self) -> None:
        client = APIClient()
        client._token = "some.token"
        assert client.is_authenticated is True

        client.logout()
        assert client.is_authenticated is False
        assert client._token is None

    def test_logout_repeated_is_safe(self) -> None:
        client = APIClient()
        client.logout()
        client.logout()
        assert client.is_authenticated is False


# ============================================================================
# D. Failed Authentication Lifecycle Tests
# ============================================================================


class TestFailedAuthentication:
    """Tests for authentication errors, token clearing, and authorization failures."""

    @respx.mock
    def test_failed_login_clears_and_retains_no_token(self) -> None:
        respx.post("http://127.0.0.1:8001/api/auth/login").mock(
            return_value=httpx.Response(
                401,
                json={"detail": "Invalid username or password"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        )

        client = APIClient()
        with pytest.raises(AuthenticationError) as exc_info:
            client.login("analyst_alice", "WrongPassword!")

        assert exc_info.value.status_code == 401
        assert "Invalid username or password" in str(exc_info.value)
        assert client.is_authenticated is False
        assert client._token is None

    @respx.mock
    def test_failed_relogin_clears_prior_valid_token(self) -> None:
        client = APIClient()
        client._token = "previously_valid_token"
        assert client.is_authenticated is True

        respx.post("http://127.0.0.1:8001/api/auth/login").mock(
            return_value=httpx.Response(
                401, json={"detail": "Invalid username or password"}
            )
        )

        with pytest.raises(AuthenticationError):
            client.login("analyst_alice", "WrongPassword!")

        assert client.is_authenticated is False
        assert client._token is None

    @respx.mock
    def test_login_inactive_user_returns_403(self) -> None:
        respx.post("http://127.0.0.1:8001/api/auth/login").mock(
            return_value=httpx.Response(403, json={"detail": "Inactive user account"})
        )

        client = APIClient()
        with pytest.raises(AuthorizationError) as exc_info:
            client.login("inactive_bob", "Password123!")

        assert exc_info.value.status_code == 403
        assert "Inactive user account" in str(exc_info.value)
        assert client.is_authenticated is False

    @respx.mock
    def test_login_malformed_response_does_not_install_token(self) -> None:
        respx.post("http://127.0.0.1:8001/api/auth/login").mock(
            return_value=httpx.Response(200, json={"corrupt": "missing token fields"})
        )

        client = APIClient()
        with pytest.raises(ValidationError):
            client.login("alice", "pass")

        assert client.is_authenticated is False
        assert client._token is None

    def test_get_current_user_unauthenticated_raises(self) -> None:
        client = APIClient()
        assert not client.is_authenticated
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.get_current_user()

    @respx.mock
    def test_get_current_user_401_clears_token(self) -> None:
        client = APIClient()
        client._token = "expired_token"
        assert client.is_authenticated is True

        respx.get("http://127.0.0.1:8001/api/auth/me").mock(
            return_value=httpx.Response(401, json={"detail": "Token has expired"})
        )

        with pytest.raises(AuthenticationError, match="Token has expired"):
            client.get_current_user()

        # Token must be cleared on 401
        assert client.is_authenticated is False
        assert client._token is None

    @respx.mock
    def test_get_current_user_403_does_not_clear_token(self) -> None:
        client = APIClient()
        client._token = "valid_token"
        assert client.is_authenticated is True

        respx.get("http://127.0.0.1:8001/api/auth/me").mock(
            return_value=httpx.Response(403, json={"detail": "Inactive user account"})
        )

        with pytest.raises(AuthorizationError, match="Inactive user account"):
            client.get_current_user()

        # Token must NOT be cleared on 403 (authorization failure)
        assert client.is_authenticated is True
        assert client._token == "valid_token"

    def test_credentials_not_leaked_in_exceptions(self) -> None:
        password = "SuperSecretPassword123!"
        client = APIClient()
        with pytest.raises(ValidationError) as exc_info:
            client.login("", password)
        assert password not in str(exc_info.value)


# ============================================================================
# E. Status and Health Tests
# ============================================================================


class TestStatusAndHealth:
    """Tests for /api/status and /health endpoints."""

    @respx.mock
    def test_get_status_healthy(self) -> None:
        respx.get("http://127.0.0.1:8001/api/status").mock(
            return_value=httpx.Response(200, json=SAMPLE_STATUS_DICT)
        )

        client = APIClient()
        status = client.get_status()
        assert isinstance(status, SystemStatus)
        assert status.status == "healthy"
        assert status.database == "connected"
        assert status.host_id == "osiris-host-01"

    @respx.mock
    def test_get_status_degraded(self) -> None:
        degraded = dict(SAMPLE_STATUS_DICT)
        degraded["status"] = "degraded"
        degraded["database"] = "disconnected"
        respx.get("http://127.0.0.1:8001/api/status").mock(
            return_value=httpx.Response(200, json=degraded)
        )

        client = APIClient()
        status = client.get_status()
        assert status.status == "degraded"
        assert status.database == "disconnected"

    @respx.mock
    def test_get_status_malformed_raises_validation_error(self) -> None:
        # Missing required fields in status response
        respx.get("http://127.0.0.1:8001/api/status").mock(
            return_value=httpx.Response(200, json={"status": "healthy"})
        )

        client = APIClient()
        with pytest.raises(ValidationError):
            client.get_status()

    @respx.mock
    def test_health_check_ok(self) -> None:
        respx.get("http://127.0.0.1:8001/health").mock(
            return_value=httpx.Response(200, json=SAMPLE_HEALTH_DICT)
        )

        client = APIClient()
        health = client.health_check()
        assert isinstance(health, HealthStatus)
        assert health.status == "ok"
        assert health.system == "osiris"

    @respx.mock
    def test_health_check_malformed_raises(self) -> None:
        respx.get("http://127.0.0.1:8001/health").mock(
            return_value=httpx.Response(200, json={"bad": "response"})
        )

        client = APIClient()
        with pytest.raises(ValidationError):
            client.health_check()


# ============================================================================
# F. Transport and HTTP Failures Tests
# ============================================================================


class TestTransportAndHTTPFailures:
    """Tests for network timeout, connection refused, and HTTP 4xx/5xx mapping."""

    @respx.mock
    def test_connection_timeout_mapped_to_connection_timeout_error(self) -> None:
        respx.get("http://127.0.0.1:8001/health").mock(
            side_effect=httpx.ReadTimeout("Server read timeout")
        )

        client = APIClient()
        with pytest.raises(ConnectionTimeoutError, match="timed out"):
            client.health_check()

    @respx.mock
    def test_connect_failure_mapped_to_client_connection_error(self) -> None:
        respx.get("http://127.0.0.1:8001/health").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        client = APIClient()
        with pytest.raises(ClientConnectionError, match="connection failure"):
            client.health_check()

    def test_connection_error_alias_matches(self) -> None:
        assert ConnectionError is ClientConnectionError

    @respx.mock
    def test_http_404_mapped_to_http_response_error(self) -> None:
        respx.get("http://127.0.0.1:8001/api/status").mock(
            return_value=httpx.Response(404, json={"detail": "Not Found"})
        )

        client = APIClient()
        with pytest.raises(HTTPResponseError) as exc_info:
            client.get_status()

        assert exc_info.value.status_code == 404
        assert "Not Found" in str(exc_info.value)

    @respx.mock
    def test_http_500_mapped_to_http_response_error(self) -> None:
        respx.get("http://127.0.0.1:8001/health").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        client = APIClient()
        with pytest.raises(HTTPResponseError) as exc_info:
            client.health_check()

        assert exc_info.value.status_code == 500

    @respx.mock
    def test_http_422_detail_list_sanitized(self) -> None:
        respx.post("http://127.0.0.1:8001/api/auth/login").mock(
            return_value=httpx.Response(
                422,
                json={
                    "detail": [
                        {"loc": ["body", "username"], "msg": "Field required"}
                    ]
                },
            )
        )

        client = APIClient()
        with pytest.raises(HTTPResponseError) as exc_info:
            client._request("POST", "/api/auth/login", json={})

        assert exc_info.value.status_code == 422
        assert "Field required" in str(exc_info.value)

    @respx.mock
    def test_malformed_json_response_raises_validation_error(self) -> None:
        respx.get("http://127.0.0.1:8001/health").mock(
            return_value=httpx.Response(200, text="<html>502 Bad Gateway</html>")
        )

        client = APIClient()
        with pytest.raises(ValidationError, match="not valid JSON"):
            client.health_check()


# ============================================================================
# G. Resource Lifecycle Tests
# ============================================================================


class TestResourceLifecycle:
    """Tests for instantiation, close(), and context manager behaviors."""

    def test_constructor_issues_zero_network_requests(self) -> None:
        client = APIClient()
        assert client.base_url == DEFAULT_BASE_URL
        assert not client.is_closed
        client.close()

    def test_close_and_idempotence(self) -> None:
        client = APIClient()
        assert not client.is_closed
        client.close()
        assert client.is_closed
        assert client._client is None

        # Repeated close must be safe and idempotent
        client.close()
        assert client.is_closed

    def test_requests_after_close_fail_predictably(self) -> None:
        client = APIClient()
        client.close()

        with pytest.raises(OSIRISClientError, match="closed"):
            client.health_check()

        with pytest.raises(OSIRISClientError, match="closed"):
            client.login("user", "pass")

        with pytest.raises(OSIRISClientError, match="closed"):
            client.get_current_user()

        with pytest.raises(OSIRISClientError, match="closed"):
            client.get_status()

    @respx.mock
    def test_context_manager_usage(self) -> None:
        respx.get("http://127.0.0.1:8001/health").mock(
            return_value=httpx.Response(200, json=SAMPLE_HEALTH_DICT)
        )

        with APIClient() as client:
            assert not client.is_closed
            health = client.health_check()
            assert health.status == "ok"

        # Exiting context manager must close the client
        assert client.is_closed
        with pytest.raises(OSIRISClientError, match="closed"):
            client.health_check()


# ============================================================================
# H. Validation and Error Mapping Gaps
# ============================================================================


class TestApiClientValidationAndErrorGaps:
    """Tests for edge case validation and error mapping in APIClient."""

    def test_validate_base_url_invalid_syntax_and_missing_host(self) -> None:
        with pytest.raises(ValidationError, match="valid host"):
            validate_base_url("http://:8080")

        with pytest.raises(ValidationError, match="valid host"):
            validate_base_url("http:///path")

    def test_normalize_iso_timestamp_naive_datetime(self) -> None:
        naive = datetime(2026, 3, 1, 8, 0, 0)
        iso_str, dt_obj = _normalize_iso_timestamp(naive, "test_field")
        assert dt_obj.tzinfo == timezone.utc
        assert iso_str.endswith("+00:00")

    def test_login_empty_password_raises_validation_error(self) -> None:
        client = APIClient()
        with pytest.raises(ValidationError, match="Password must be"):
            client.login("user", "")

    def test_get_events_parameter_validation_errors(self) -> None:
        client = APIClient()
        client._token = "valid_token"

        with pytest.raises(ValidationError, match="host_id"):
            client.get_events(host_id="not-a-uuid")

        with pytest.raises(ValidationError, match="process_id"):
            client.get_events(process_id="not-a-uuid")

        with pytest.raises(ValidationError, match="source"):
            client.get_events(source="   ")

        with pytest.raises(ValidationError, match="event_type"):
            client.get_events(event_type="   ")

        with pytest.raises(ValidationError, match="severity"):
            client.get_events(severity="   ")

        with pytest.raises(ValidationError, match="Invalid severity"):
            client.get_events(severity="invalid_choice")

        with pytest.raises(ValidationError, match="pid"):
            client.get_events(pid=-1)

        with pytest.raises(ValidationError, match="pid"):
            client.get_events(pid=True)  # type: ignore[arg-type]

    def test_get_event_empty_id_raises_validation_error(self) -> None:
        client = APIClient()
        client._token = "valid_token"
        with pytest.raises(ValidationError, match="event_id"):
            client.get_event("")

    @respx.mock
    def test_transport_httpx_generic_error_mapped(self) -> None:
        respx.get("http://127.0.0.1:8001/health").mock(
            side_effect=httpx.ProtocolError("protocol breakdown")
        )
        client = APIClient()
        with pytest.raises(ClientConnectionError, match="transport failure"):
            client.health_check()

    @respx.mock
    def test_response_json_array_raises_validation_error(self) -> None:
        respx.get("http://127.0.0.1:8001/health").mock(
            return_value=httpx.Response(200, json=["unexpected", "array"])
        )
        client = APIClient()
        with pytest.raises(ValidationError, match="Expected JSON object"):
            client.health_check()

    def test_validate_base_url_malformed_ipv6_syntax_error(self) -> None:
        with pytest.raises(ValidationError, match="Invalid base URL syntax"):
            validate_base_url("http://[")

    def test_user_model_validation_fallbacks(self) -> None:
        with pytest.raises(ValidationError, match="Expected JSON object"):
            User.from_dict(["not", "a", "dict"])

        base_user = {
            "id": "11111111-1111-4111-8111-111111111111",
            "username": "alice",
            "role": "admin",
            "is_active": True,
            "created_at": "2026-01-01T00:00:00Z",
        }
        with pytest.raises(ValidationError, match="must be a non-empty string"):
            User.from_dict({**base_user, "id": "   "})
        with pytest.raises(ValidationError, match="must be a non-empty string"):
            User.from_dict({**base_user, "username": ""})
        with pytest.raises(ValidationError, match="must be a non-empty string"):
            User.from_dict({**base_user, "role": "  "})
        with pytest.raises(ValidationError, match="must be a non-empty string"):
            User.from_dict({**base_user, "created_at": " "})

    def test_token_info_validation_fallbacks(self) -> None:
        with pytest.raises(ValidationError, match="Expected JSON object"):
            TokenInfo.from_dict("invalid")

        valid_user = {
            "id": "11111111-1111-4111-8111-111111111111",
            "username": "alice",
            "role": "admin",
            "is_active": True,
            "created_at": "2026-01-01T00:00:00Z",
        }
        with pytest.raises(ValidationError, match="Field 'access_token'"):
            TokenInfo.from_dict(
                {
                    "access_token": " ",
                    "token_type": "bearer",
                    "user": valid_user,
                }
            )
        with pytest.raises(ValidationError, match="Missing required field"):
            TokenInfo.from_dict(
                {"access_token": "tok", "user": valid_user}
            )
        with pytest.raises(ValidationError, match="Field 'token_type'"):
            TokenInfo.from_dict(
                {
                    "access_token": "tok",
                    "token_type": "  ",
                    "user": valid_user,
                }
            )

    def test_status_and_health_models_validation_and_to_dict(self) -> None:
        with pytest.raises(ValidationError, match="Expected JSON object"):
            SystemStatus.from_dict(42)
        with pytest.raises(ValidationError, match="must be a non-empty string"):
            SystemStatus.from_dict(
                {
                    "status": "ok",
                    "system": " ",
                    "database": "ok",
                    "host_id": "h",
                }
            )
        s = SystemStatus.from_dict(
            {
                "status": "ok",
                "system": "osiris",
                "database": "ok",
                "host_id": "h1",
            }
        )
        assert s.to_dict()["system"] == "osiris"

        with pytest.raises(ValidationError, match="Expected JSON object"):
            HealthStatus.from_dict(False)
        with pytest.raises(ValidationError, match="must be a non-empty string"):
            HealthStatus.from_dict({"status": "ok", "system": ""})
        h = HealthStatus.from_dict({"status": "ok", "system": "osiris"})
        assert h.to_dict()["status"] == "ok"

    def test_event_and_event_collection_models_validation(self) -> None:
        from desktop.client.models import Event, EventCollection

        col = EventCollection(items=(), total=0, limit=50, offset=0)
        assert col.to_dict()["total"] == 0

        valid_event = {
            "id": "11111111-1111-4111-8111-111111111111",
            "host_id": "22222222-2222-4222-8222-222222222222",
            "timestamp": "2026-01-01T00:00:00Z",
            "ingested_at": "2026-01-01T00:00:00Z",
            "created_at": "2026-01-01T00:00:00Z",
            "source": "audit",
            "event_type": "auth",
            "action": "login",
            "severity": "info",
        }
        with pytest.raises(
            ValidationError, match="must be a non-empty ISO 8601"
        ):
            Event.from_dict({**valid_event, "timestamp": "  "})
        with pytest.raises(ValidationError, match="must be a non-empty string"):
            Event.from_dict({**valid_event, "source": " "})
        with pytest.raises(ValidationError, match="must be a non-empty string"):
            Event.from_dict({**valid_event, "severity": " "})
        with pytest.raises(ValidationError, match="must be a string or None"):
            Event.from_dict({**valid_event, "username": 1234})
        with pytest.raises(ValidationError, match="must be a boolean or None"):
            Event.from_dict({**valid_event, "success": "yes"})
        with pytest.raises(ValidationError, match="must be a dict or None"):
            Event.from_dict({**valid_event, "payload": ["not", "dict"]})

