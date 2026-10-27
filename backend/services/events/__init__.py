"""OSIRIS Event Processing Layer.

This package is the single authoritative layer for transforming
raw collector observations into validated, normalized, enriched
common events.

Public API
----------
- ``RawObservation``  — collector input contract
- ``NormalizedEvent`` — processor output contract
- ``EventProcessor``  — orchestrator (validate → normalize → enrich)
- ``EventRepository`` — persistence (NormalizedEvent → PostgreSQL)
- ``IdentityResolver`` — identity resolution abstraction
- ``DatabaseIdentityResolver`` — database-backed resolver
- ``LinuxUserSynchronizer`` — host account discovery and synchronization
- ``ProcessLifecycleService`` — process entity lifecycle maintenance
"""

from backend.services.events.schemas import NormalizedEvent, RawObservation
from backend.services.events.processor import EventProcessor
from backend.services.events.process_lifecycle import ProcessLifecycleService
from backend.services.events.repository import EventRepository
from backend.services.events.resolver import (
    DatabaseIdentityResolver,
    IdentityResolver,
    NoOpIdentityResolver,
)
from backend.services.events.user_sync import LinuxUserSynchronizer

__all__ = [
    "DatabaseIdentityResolver",
    "EventProcessor",
    "EventRepository",
    "IdentityResolver",
    "LinuxUserSynchronizer",
    "NoOpIdentityResolver",
    "NormalizedEvent",
    "ProcessLifecycleService",
    "RawObservation",
]
