"""OSIRIS Desktop REST API client package.

Provides the secure API client, response data models, and exception hierarchy
for communicating with the OSIRIS backend API.
"""

from __future__ import annotations

from desktop.client.api_client import (
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT,
    APIClient,
    validate_base_url,
)
from desktop.client.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ClientConnectionError,
    ConnectionError,
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
    File,
    FileCollection,
    FileRecord,
    FileRecordCollection,
    HealthStatus,
    Process,
    ProcessCollection,
    ResourceSnapshot,
    ResourceSnapshotCollection,
    SystemStatus,
    TokenInfo,
    User,
)

__all__ = [
    "APIClient",
    "AuthenticationError",
    "AuthorizationError",
    "ClientConnectionError",
    "ConnectionError",
    "ConnectionTimeoutError",
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT",
    "Event",
    "EventCollection",
    "File",
    "FileCollection",
    "FileRecord",
    "FileRecordCollection",
    "HTTPResponseError",
    "HealthStatus",
    "NotFoundError",
    "OSIRISClientError",
    "Process",
    "ProcessCollection",
    "ResourceSnapshot",
    "ResourceSnapshotCollection",
    "ServerError",
    "SystemStatus",
    "TokenInfo",
    "User",
    "VALID_FILE_TYPES",
    "VALID_SEVERITIES",
    "ValidationError",
    "validate_base_url",
]
