"""Domain constants, types, and exceptions for OSIRIS Incident Management."""

from __future__ import annotations

from enum import Enum


class IncidentStatus(str, Enum):
    """Supported incident lifecycle statuses."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentSeverity(str, Enum):
    """Supported incident severities."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class EvidenceType(str, Enum):
    """Supported forensic evidence types."""

    DETECTION = "detection"
    EVENT = "event"
    FIM_DEVIATION = "fim_deviation"
    SESSION = "session"
    SNAPSHOT = "snapshot"
    PROCESS = "process"
    FILE = "file"
    CUSTOM = "custom"


class HistoryChangeType(str, Enum):
    """Auditable change types recorded in incident history."""

    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    STATUS_CHANGE = "status_change"
    SEVERITY_CHANGE = "severity_change"
    ASSIGNMENT = "assignment"
    NOTE_ADDED = "note_added"
    EVIDENCE_ADDED = "evidence_added"
    EVENT_LINKED = "event_linked"


class IncidentError(Exception):
    """Base exception for all incident management operations."""


class IncidentNotFoundError(IncidentError):
    """Raised when an incident identifier cannot be found."""


class InvalidTransitionError(IncidentError):
    """Raised when an invalid lifecycle transition is attempted."""


class InvalidSeverityError(IncidentError):
    """Raised when an unknown or invalid severity level is specified."""


class SeverityDowngradeError(IncidentError):
    """Raised when an unauthorized or unreasoned severity downgrade is attempted."""


class HostMismatchError(IncidentError):
    """Raised when evidence from a different host is associated with a host-scoped incident."""


class EvidenceDuplicateError(IncidentError):
    """Raised when duplicate evidence association is attempted."""


class EvidenceNotFoundError(IncidentError):
    """Raised when referenced evidence cannot be found."""


class UserNotFoundError(IncidentError):
    """Raised when a referenced user account cannot be found."""
