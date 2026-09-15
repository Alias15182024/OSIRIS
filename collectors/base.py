"""Base collector interface for OSIRIS.

All Linux-specific collectors inherit from BaseCollector.
This ensures a consistent interface between the collection layer
and the OSIRIS core event processing layer.

Collectors are responsible for:
  - Gathering raw data from a specific Linux subsystem.
  - Performing source-specific parsing of that raw data.
  - Identifying themselves as a named source.

Collectors are NOT responsible for:
  - Final event normalization (owned by Event Processing Layer).
  - Event ID assignment (owned by Event Processing Layer).
  - Timestamp normalization to UTC (owned by Event Processing Layer).
  - Enrichment such as UID-to-username resolution (owned by Event Processing Layer).

See docs/event-model.md §10 for the full event lifecycle.
"""

from abc import ABC, abstractmethod
from typing import Any


class BaseCollector(ABC):
    """Abstract base class for all OSIRIS collectors.

    Each collector is responsible for:
    1. Gathering raw data from a specific Linux subsystem.
    2. Parsing that data into source-specific observation dicts.
    3. Identifying itself as a named source.

    The Event Processing Layer is the authoritative place for
    validation, normalization, enrichment, and event ID assignment.
    """

    def __init__(self, host_id: str) -> None:
        self.host_id = host_id
        self._running = False

    @abstractmethod
    def collect(self) -> list[dict[str, Any]]:
        """Collect raw data from the Linux subsystem.

        Returns a list of raw observation dictionaries.
        """

    @abstractmethod
    def parse(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        """Perform source-specific parsing of a raw observation.

        Converts raw subsystem output into a structured dict that the
        Event Processing Layer can validate and normalize into a
        common event.

        This method may extract fields, map subsystem-specific names
        to OSIRIS field names, and attach source metadata.  It must
        NOT assign event IDs, normalize timestamps to UTC, or perform
        cross-source enrichment — those are Event Processing Layer
        responsibilities.

        Args:
            raw_data: A single raw observation dictionary.

        Returns:
            A structured observation dict ready for the Event
            Processing Layer.
        """

    @abstractmethod
    def get_source_name(self) -> str:
        """Return the name of this collector's data source."""

    def start(self) -> None:
        """Start the collector."""
        self._running = True

    def stop(self) -> None:
        """Stop the collector."""
        self._running = False

    @property
    def is_running(self) -> bool:
        """Whether this collector is currently active."""
        return self._running
