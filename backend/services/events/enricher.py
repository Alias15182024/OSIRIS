"""Deterministic enrichment for the Event Processing Layer.

Phase 1.3 enrichment is intentionally minimal.  It performs only
deterministic transformations that do not depend on live Linux
subsystems, external lookups, or database queries.

Future extension points (Milestone 1.4+):
- UID → username resolution via ``/etc/passwd`` or database lookup.
- PID + host_id + timestamp → ``process_id`` resolution against
  the ``processes`` table.

Those enrichments will be added as separate functions/classes that
compose with this module.
"""

from __future__ import annotations

from backend.services.events.schemas import NormalizedEvent


def enrich(event: NormalizedEvent) -> NormalizedEvent:
    """Apply deterministic enrichments to a normalized event.

    Current enrichments
    -------------------
    1. **source** — stripped and lowercased for consistency.
    2. **event_type** — stripped and lowercased for consistency.
    3. **username** — leading/trailing whitespace stripped.
    4. **command** — if absent and present in ``payload["command"]``,
       copied to the top-level field.

    Parameters
    ----------
    event:
        A ``NormalizedEvent`` produced by the normalizer.

    Returns
    -------
    NormalizedEvent
        A new instance with enrichments applied (Pydantic models are
        treated as immutable).
    """
    updates: dict = {}

    # 1. Normalize source casing
    updates["source"] = event.source.strip().lower()

    # 2. Normalize event_type casing
    updates["event_type"] = event.event_type.strip().lower()

    # 3. Strip username whitespace
    if event.username is not None:
        stripped = event.username.strip()
        updates["username"] = stripped if stripped else None

    # 4. Copy command from payload if top-level field is absent
    if event.command is None and event.payload and "command" in event.payload:
        cmd = event.payload["command"]
        if isinstance(cmd, str) and cmd.strip():
            updates["command"] = cmd.strip()

    return event.model_copy(update=updates)
