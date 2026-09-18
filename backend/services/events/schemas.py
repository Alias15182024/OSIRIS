"""Event Processing Layer data contracts.

Two Pydantic v2 models define the boundary between collectors and
the Event Processing Layer:

- ``RawObservation``  — what a collector submits (source-specific)
- ``NormalizedEvent`` — what the processor produces (common event)

These models are deliberately independent from the SQLAlchemy
``Event`` persistence model in ``backend.db.models.event``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

# Canonical severity levels — must match the CHECK constraint on the
# ``events`` table and ``VALID_SEVERITIES`` in ``backend.db.models.event``.
VALID_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})


class RawObservation(BaseModel):
    """Input contract for collectors.

    Collectors produce ``RawObservation`` instances after performing
    source-specific parsing.  The Event Processing Layer is the sole
    authority that validates, normalizes, enriches, and assigns event
    IDs to transform these into ``NormalizedEvent`` instances.

    Fields use permissive types so collectors can pass timestamps as
    either ``datetime`` objects or ISO 8601 strings.
    """

    model_config = ConfigDict(extra="forbid")

    # --- Required ---
    source: str
    host_id: uuid.UUID
    event_type: str
    action: str

    # --- Defaults ---
    severity: str = "info"

    # Timestamp provided by the collector.  May be a tz-aware datetime
    # or an ISO 8601 string.  ``None`` means "use current time" is NOT
    # permitted — the processor will reject it.
    observed_at: datetime | str | None = None

    # --- Actor (optional) ---
    uid: int | None = None
    username: str | None = None

    # --- Process context (optional) ---
    pid: int | None = None
    ppid: int | None = None
    command: str | None = None
    process_id: uuid.UUID | None = None

    # --- Object context (optional) ---
    object_type: str | None = None
    object_path: str | None = None

    # --- Result (optional) ---
    success: bool | None = None
    result: str | None = None

    # --- Source-specific extensibility ---
    payload: dict[str, Any] | None = None


class NormalizedEvent(BaseModel):
    """Output of the Event Processing Layer.

    Represents a fully validated, normalized, enriched common event
    ready for persistence.  Every field that lands in the ``events``
    database table has a corresponding attribute here.

    Invariants enforced by validators:
    - ``id`` is a UUID4
    - ``timestamp`` and ``ingested_at`` are timezone-aware UTC
    - ``severity`` is one of the canonical values
    - ``pid`` and ``uid`` are non-negative when present
    """

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    host_id: uuid.UUID
    timestamp: datetime
    ingested_at: datetime
    source: str
    event_type: str
    action: str
    severity: str

    # Actor
    uid: int | None = None
    username: str | None = None

    # Process context
    pid: int | None = None
    ppid: int | None = None
    command: str | None = None
    process_id: uuid.UUID | None = None

    # Object context
    object_type: str | None = None
    object_path: str | None = None

    # Result
    success: bool | None = None
    result: str | None = None

    # Payload
    payload: dict[str, Any] | None = None

    # --- Validators ---------------------------------------------------

    @field_validator("severity")
    @classmethod
    def _severity_valid(cls, v: str) -> str:
        if v not in VALID_SEVERITIES:
            raise ValueError(
                f"severity must be one of {sorted(VALID_SEVERITIES)}, got {v!r}"
            )
        return v

    @field_validator("uid")
    @classmethod
    def _uid_non_negative(cls, v: int | None) -> int | None:
        if v is not None and v < 0:
            raise ValueError(f"uid must be >= 0, got {v}")
        return v

    @field_validator("pid", "ppid")
    @classmethod
    def _pid_non_negative(cls, v: int | None) -> int | None:
        if v is not None and v < 0:
            raise ValueError(f"pid/ppid must be >= 0, got {v}")
        return v

    @field_validator("timestamp", "ingested_at")
    @classmethod
    def _must_be_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware (UTC)")
        return v
