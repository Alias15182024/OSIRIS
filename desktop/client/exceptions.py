"""OSIRIS Desktop API client exception hierarchy.

Provides distinct, sanitized client exceptions for transport, authentication,
authorization, HTTP error status, and response validation failures.
"""

from __future__ import annotations


class OSIRISClientError(Exception):
    """Base class for all OSIRIS desktop API client errors.

    Attributes:
        message: Sanitized, human-readable error description.
        status_code: Optional HTTP status code when associated with an HTTP response.
    """

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def __str__(self) -> str:
        return self.message


class AuthenticationError(OSIRISClientError):
    """Raised when authentication fails or credentials are invalid (HTTP 401)."""

    def __init__(
        self,
        message: str = "Authentication failed",
        status_code: int | None = 401,
    ) -> None:
        super().__init__(message, status_code=status_code)


class AuthorizationError(OSIRISClientError):
    """Raised when the user lacks permissions or account is inactive (HTTP 403)."""

    def __init__(
        self,
        message: str = "Authorization failed",
        status_code: int | None = 403,
    ) -> None:
        super().__init__(message, status_code=status_code)


class ConnectionTimeoutError(OSIRISClientError):
    """Raised when an HTTP connection or read operation times out."""

    def __init__(
        self,
        message: str = "Connection timed out",
        status_code: int | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code)


class ClientConnectionError(OSIRISClientError):
    """Raised when network transport or connection to the API server fails.

    Named ClientConnectionError deliberately to avoid shadowing Python's
    built-in ConnectionError in unrelated code.
    """

    def __init__(
        self,
        message: str = "Connection to server failed",
        status_code: int | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code)


# Deliberate alias provided for callers expecting ConnectionError under client namespace
ConnectionError = ClientConnectionError


class HTTPResponseError(OSIRISClientError):
    """Raised when the server returns an unexpected 4xx or 5xx HTTP response."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message, status_code=status_code)


class NotFoundError(HTTPResponseError):
    """Raised when the requested resource is not found (HTTP 404)."""

    def __init__(
        self,
        message: str = "Resource not found",
        status_code: int | None = 404,
    ) -> None:
        super().__init__(message, status_code=status_code)


class ServerError(HTTPResponseError):
    """Raised when the server encounters an internal error (HTTP 5xx)."""

    def __init__(
        self,
        message: str = "Internal server error",
        status_code: int | None = 500,
    ) -> None:
        super().__init__(message, status_code=status_code)


class ValidationError(OSIRISClientError):
    """Raised when URL config, response payloads, or schemas fail validation."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message, status_code=status_code)


__all__ = [
    "AuthenticationError",
    "AuthorizationError",
    "ClientConnectionError",
    "ConnectionError",
    "ConnectionTimeoutError",
    "HTTPResponseError",
    "NotFoundError",
    "OSIRISClientError",
    "ServerError",
    "ValidationError",
]
