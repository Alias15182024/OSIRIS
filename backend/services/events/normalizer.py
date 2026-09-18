"""Timestamp and field normalization for the Event Processing Layer.

Responsibilities owned exclusively by this module:

- Parse ISO 8601 timestamp strings into ``datetime`` objects.
- Convert timezone-aware timestamps to UTC.
- Reject naive (timezone-unaware) timestamps.
- Build a ``NormalizedEvent`` from a validated ``RawObservation``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from backend.services.events.schemas import NormalizedEvent, RawObservation


def normalize_timestamp(value: datetime | str | None) -> datetime:
    """Convert *value* to a timezone-aware UTC datetime.

    Parameters
    ----------
    value:
        A ``datetime`` (must be tz-aware) or an ISO 8601 string.

    Returns
    -------
    datetime
        The equivalent UTC datetime with ``tzinfo=timezone.utc``.

    Raises
    ------
    ValueError
        If *value* is ``None``, a naive datetime, or an unparseable string.
    """
    if value is None:
        raise ValueError("timestamp is required; received None")

    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"timestamp is not a valid ISO 8601 string: {value!r}"
            ) from exc

    if not isinstance(value, datetime):
        raise ValueError(
            f"timestamp must be a datetime or ISO 8601 string, got {type(value).__name__}"
        )

    if value.tzinfo is None:
        raise ValueError(
            "timestamp must be timezone-aware; naive datetimes are rejected. "
            "OSIRIS does not guess timezones."
        )

    # Convert to UTC
    return value.astimezone(timezone.utc)


def normalize_observation(
    obs: RawObservation,
    *,
    event_id: uuid.UUID | None = None,
    ingested_at: datetime | None = None,
) -> NormalizedEvent:
    """Transform a validated ``RawObservation`` into a ``NormalizedEvent``.

    This function assumes that *obs* has already passed validation via
    ``validate_raw_observation``.

    Parameters
    ----------
    obs:
        The validated raw observation.
    event_id:
        Override the generated event UUID (useful for testing).
    ingested_at:
        Override the ingestion timestamp (useful for testing).

    Returns
    -------
    NormalizedEvent
        A fully normalized event ready for enrichment and persistence.
    """
    ts = normalize_timestamp(obs.observed_at)
    now = ingested_at or datetime.now(timezone.utc)

    return NormalizedEvent(
        id=event_id or uuid.uuid4(),
        host_id=obs.host_id,
        timestamp=ts,
        ingested_at=now,
        source=obs.source,
        event_type=obs.event_type,
        action=obs.action,
        severity=obs.severity,
        uid=obs.uid,
        username=obs.username,
        pid=obs.pid,
        ppid=obs.ppid,
        command=obs.command,
        process_id=obs.process_id,
        object_type=obs.object_type,
        object_path=obs.object_path,
        success=obs.success,
        result=obs.result,
        payload=obs.payload,
    )
