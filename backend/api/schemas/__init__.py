"""OSIRIS API request and response schemas.

Central export module for all Phase 1.5 Pydantic v2 schemas:
- Authentication models (`LoginRequest`, `TokenResponse`, `UserResponse`)
- Event models (`EventQueryParams`, `EventResponse`, `PaginatedEventResponse`)
- Process models (`ProcessQueryParams`, `ProcessResponse`, `PaginatedProcessResponse`)
- Resource models (`ResourceSnapshotQueryParams`, `ResourceSnapshotResponse`, `PaginatedResourceSnapshotResponse`)
- File models (`FileQueryParams`, `FileResponse`, `PaginatedFileResponse`)
- Status and error models (`StatusResponse`, `ErrorDetail`)
"""

from backend.api.schemas.auth import LoginRequest, TokenResponse, UserResponse
from backend.api.schemas.events import (
    EventQueryParams,
    EventResponse,
    PaginatedEventResponse,
)
from backend.api.schemas.files import (
    FileQueryParams,
    FileResponse,
    PaginatedFileResponse,
)
from backend.api.schemas.processes import (
    PaginatedProcessResponse,
    ProcessQueryParams,
    ProcessResponse,
)
from backend.api.schemas.resources import (
    PaginatedResourceSnapshotResponse,
    ResourceSnapshotQueryParams,
    ResourceSnapshotResponse,
)
from backend.api.schemas.status import ErrorDetail, StatusResponse

__all__ = [
    "ErrorDetail",
    "EventQueryParams",
    "EventResponse",
    "FileQueryParams",
    "FileResponse",
    "LoginRequest",
    "PaginatedEventResponse",
    "PaginatedFileResponse",
    "PaginatedProcessResponse",
    "PaginatedResourceSnapshotResponse",
    "ProcessQueryParams",
    "ProcessResponse",
    "ResourceSnapshotQueryParams",
    "ResourceSnapshotResponse",
    "StatusResponse",
    "TokenResponse",
    "UserResponse",
]
