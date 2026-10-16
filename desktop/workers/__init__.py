"""OSIRIS background worker package."""

from __future__ import annotations

from desktop.workers.api_worker import ApiWorker, ApiWorkerSignals

__all__ = [
    "ApiWorker",
    "ApiWorkerSignals",
]
