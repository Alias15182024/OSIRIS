"""Raw-observation validation for the Event Processing Layer.

Validates a ``RawObservation`` *before* normalization.  Returns a list
of human-readable error strings — an empty list means the observation
is valid.

Validation is deliberately performed as a separate step so that the
processor can collect *all* errors for a single observation rather
than failing on the first one.
"""

from __future__ import annotations

from datetime import datetime

from backend.services.events.schemas import VALID_SEVERITIES, RawObservation


def _parse_timestamp(value: datetime | str | None) -> datetime | None:
    """Try to parse a timestamp value; return None on failure."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except (ValueError, TypeError):
            return None
    return None


def validate_raw_observation(obs: RawObservation) -> list[str]:
    """Return validation errors for *obs* (empty list = valid).

    Rules
    -----
    - ``source`` must be a non-empty string.
    - ``event_type`` must be a non-empty string.
    - ``action`` must be a non-empty string.
    - ``host_id`` must be present (enforced by Pydantic, but double-checked).
    - ``severity`` must be one of the canonical values.
    - ``observed_at`` must be parseable as a datetime (string or datetime).
    - ``observed_at`` must be timezone-aware (naive → rejected).
    - ``uid`` must be >= 0 when present.
    - ``pid`` must be >= 0 when present.
    """
    errors: list[str] = []

    # Required non-empty strings
    if not obs.source or not obs.source.strip():
        errors.append("source is required and must be non-empty")
    if not obs.event_type or not obs.event_type.strip():
        errors.append("event_type is required and must be non-empty")
    if not obs.action or not obs.action.strip():
        errors.append("action is required and must be non-empty")

    # Severity
    if obs.severity not in VALID_SEVERITIES:
        errors.append(
            f"severity must be one of {sorted(VALID_SEVERITIES)}, "
            f"got {obs.severity!r}"
        )

    # Timestamp
    if obs.observed_at is None:
        errors.append("observed_at (timestamp) is required")
    else:
        ts = _parse_timestamp(obs.observed_at)
        if ts is None:
            errors.append(
                f"observed_at is not a valid timestamp: {obs.observed_at!r}"
            )
        elif ts.tzinfo is None:
            errors.append(
                "observed_at must be timezone-aware; "
                "naive timestamps are rejected (OSIRIS does not guess timezones)"
            )

    # Numeric constraints
    if obs.uid is not None and obs.uid < 0:
        errors.append(f"uid must be >= 0, got {obs.uid}")
    if obs.pid is not None and obs.pid < 0:
        errors.append(f"pid must be >= 0, got {obs.pid}")
    if obs.ppid is not None and obs.ppid < 0:
        errors.append(f"ppid must be >= 0, got {obs.ppid}")

    return errors
