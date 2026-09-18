"""Event Processing Layer orchestrator.

``EventProcessor`` is the single entry point for converting raw
collector observations into validated, normalized, enriched common
events.

Pipeline per observation::

    RawObservation
        → validate
        → normalize (timestamp → UTC, assign UUID, set ingested_at)
        → enrich
        → NormalizedEvent

The processor never silently discards malformed observations.  Every
failure is reported in the result object with actionable error messages.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from backend.services.events.enricher import enrich
from backend.services.events.normalizer import normalize_observation
from backend.services.events.schemas import NormalizedEvent, RawObservation
from backend.services.events.validator import validate_raw_observation


@dataclass
class ProcessingResult:
    """Result of processing a single raw observation."""

    event: NormalizedEvent | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.event is not None and not self.errors


@dataclass
class BatchResult:
    """Result of processing a batch of raw observations."""

    events: list[NormalizedEvent] = field(default_factory=list)
    errors: list[tuple[int, list[str]]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.events) + len(self.errors)

    @property
    def succeeded(self) -> int:
        return len(self.events)

    @property
    def failed(self) -> int:
        return len(self.errors)


class EventProcessor:
    """Authoritative OSIRIS event processor.

    Transforms ``RawObservation`` instances into ``NormalizedEvent``
    instances through validation, normalization, and enrichment.

    Usage::

        processor = EventProcessor()
        result = processor.process(raw_observation)
        if result.success:
            repository.save(result.event)
        else:
            log_errors(result.errors)
    """

    def process(self, observation: RawObservation) -> ProcessingResult:
        """Process a single raw observation.

        Returns a ``ProcessingResult`` containing either a
        ``NormalizedEvent`` on success or error messages on failure.
        """
        # Step 1: Validate
        errors = validate_raw_observation(observation)
        if errors:
            return ProcessingResult(errors=errors)

        # Step 2: Normalize (timestamp → UTC, assign UUID, set ingested_at)
        try:
            normalized = normalize_observation(observation)
        except (ValueError, TypeError) as exc:
            return ProcessingResult(errors=[str(exc)])

        # Step 3: Enrich
        enriched = enrich(normalized)

        return ProcessingResult(event=enriched)

    def process_batch(
        self, observations: list[RawObservation]
    ) -> BatchResult:
        """Process multiple observations.

        Each observation is processed independently.  Failures in one
        observation do not affect others.

        Returns a ``BatchResult`` with all successful events and all
        per-observation errors indexed by position.
        """
        result = BatchResult()

        for idx, obs in enumerate(observations):
            single = self.process(obs)
            if single.success:
                assert single.event is not None
                result.events.append(single.event)
            else:
                result.errors.append((idx, single.errors))

        return result
