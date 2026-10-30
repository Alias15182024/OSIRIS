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
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.resource_snapshot import ResourceSnapshot
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession

__all__ = [
    "AppAuditLog",
    "AppUser",
    "Detection",
    "DetectionRule",
    "Event",
    "File",
    "FimBaseline",
    "FimBaselineFile",
    "FimDeviation",
    "Host",
    "LinuxUser",
    "Process",
    "ResourceSnapshot",
    "Snapshot",
    "UserSession",
]
