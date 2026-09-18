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
"""

from backend.services.events.schemas import NormalizedEvent, RawObservation
from backend.services.events.processor import EventProcessor
from backend.services.events.repository import EventRepository

__all__ = [
    "EventProcessor",
    "EventRepository",
    "NormalizedEvent",
    "RawObservation",
]
