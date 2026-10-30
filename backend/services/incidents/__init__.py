"""Incident management service package for OSIRIS Phase 2 Milestone 2.6."""

from backend.services.incidents.models import (
    EvidenceDuplicateError,
    EvidenceNotFoundError,
    EvidenceType,
    HistoryChangeType,
    HostMismatchError,
    IncidentError,
    IncidentNotFoundError,
    IncidentSeverity,
    IncidentStatus,
    InvalidSeverityError,
    InvalidTransitionError,
    SeverityDowngradeError,
    UserNotFoundError,
)
from backend.services.incidents.service import IncidentService
from backend.services.incidents.evidence_manager import EvidenceManager
from backend.services.incidents.correlator import DetectionCorrelator
from backend.services.incidents.report import ReportGenerator

__all__ = [
    "DetectionCorrelator",
    "EvidenceDuplicateError",
    "EvidenceManager",
    "EvidenceNotFoundError",
    "EvidenceType",
    "HistoryChangeType",
    "HostMismatchError",
    "IncidentError",
    "IncidentNotFoundError",
    "IncidentReportGenerator",
    "IncidentService",
    "IncidentSeverity",
    "IncidentStatus",
    "InvalidSeverityError",
    "InvalidTransitionError",
    "ReportGenerator",
    "SeverityDowngradeError",
    "UserNotFoundError",
]
