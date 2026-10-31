"""OSIRIS database models — Phase 1 & Phase 2.

Import all models here so Alembic autogenerate can discover them.
"""

from backend.db.models.app_audit_log import AppAuditLog
from backend.db.models.app_user import AppUser
from backend.db.models.detection import Detection
from backend.db.models.detection_rule import DetectionRule
from backend.db.models.event import Event
from backend.db.models.file import File
from backend.db.models.fim_baseline import FimBaseline
from backend.db.models.fim_baseline_file import FimBaselineFile
from backend.db.models.fim_deviation import FimDeviation
from backend.db.models.host import Host
from backend.db.models.incident import Incident
from backend.db.models.incident_event import IncidentEvent
from backend.db.models.incident_evidence import IncidentEvidence
from backend.db.models.incident_history import IncidentHistory
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.resource_snapshot import ResourceSnapshot
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession
from backend.db.models.workspace import Workspace
from backend.db.models.evidence_tag import EvidenceTag
from backend.db.models.evidence_tag_association import EvidenceTagAssociation
from backend.db.models.evidence_annotation import EvidenceAnnotation

__all__ = [
    "AppAuditLog",
    "AppUser",
    "Detection",
    "DetectionRule",
    "Event",
    "EvidenceAnnotation",
    "EvidenceTag",
    "EvidenceTagAssociation",
    "File",
    "FimBaseline",
    "FimBaselineFile",
    "FimDeviation",
    "Host",
    "Incident",
    "IncidentEvent",
    "IncidentEvidence",
    "IncidentHistory",
    "LinuxUser",
    "Process",
    "ResourceSnapshot",
    "Snapshot",
    "UserSession",
    "Workspace",
]
