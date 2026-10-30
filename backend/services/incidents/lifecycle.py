"""Incident lifecycle state machine and transition validation."""

from __future__ import annotations

from typing import Optional

from backend.services.incidents.models import (
    IncidentSeverity,
    IncidentStatus,
    InvalidSeverityError,
    InvalidTransitionError,
    SEVERITY_ORDER,
    SeverityDowngradeError,
)

# Allowed lifecycle transitions
VALID_TRANSITIONS: dict[str, set[str]] = {
    IncidentStatus.OPEN.value: {
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.CONTAINED.value,
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
    },
    IncidentStatus.INVESTIGATING.value: {
        IncidentStatus.CONTAINED.value,
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
        IncidentStatus.OPEN.value,
    },
    IncidentStatus.CONTAINED.value: {
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
    },
    IncidentStatus.RESOLVED.value: {
        IncidentStatus.CLOSED.value,
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.OPEN.value,
    },
    IncidentStatus.CLOSED.value: {
        IncidentStatus.OPEN.value,
        IncidentStatus.INVESTIGATING.value,
    },
}


def validate_transition(
    current_status: str,
    new_status: str,
    reason: Optional[str] = None,
) -> None:
    """Validate a requested lifecycle status transition.

    Parameters
    ----------
    current_status : str
        The incident's current status.
    new_status : str
        The requested target status.
    reason : Optional[str]
        Optional explanation or justification. Reopening closed/resolved
        incidents strictly requires a reason.

    Raises
    ------
    InvalidTransitionError
        If the transition is forbidden by the state machine or lacks justification.
    """
    current_norm = current_status.lower()
    new_norm = new_status.lower()

    if new_norm == current_norm:
        raise InvalidTransitionError(
            f"Incident is already in status '{current_norm}'."
        )

    allowed = VALID_TRANSITIONS.get(current_norm, set())
    if new_norm not in allowed:
        raise InvalidTransitionError(
            f"Invalid lifecycle transition from '{current_norm}' to '{new_norm}'. "
            f"Allowed next states: {sorted(list(allowed))}."
        )

    # Reopening from closed or resolved requires explicit justification notes
    if current_norm in (IncidentStatus.CLOSED.value, IncidentStatus.RESOLVED.value) and new_norm in (
        IncidentStatus.OPEN.value,
        IncidentStatus.INVESTIGATING.value,
    ):
        if not reason or not reason.strip():
            raise InvalidTransitionError(
                f"Reopening incident from '{current_norm}' to '{new_norm}' requires an explicit reason or note."
            )


def compare_severities(sev_a: str, sev_b: str) -> int:
    """Compare two severities by relative rank.

    Returns:
      -1 if sev_a < sev_b
       0 if sev_a == sev_b
       1 if sev_a > sev_b
    """
    sev_a_norm = sev_a.lower()
    sev_b_norm = sev_b.lower()

    rank_a = SEVERITY_ORDER.get(sev_a_norm)
    rank_b = SEVERITY_ORDER.get(sev_b_norm)

    if rank_a is None:
        raise InvalidSeverityError(f"Invalid severity value: '{sev_a}'")
    if rank_b is None:
        raise InvalidSeverityError(f"Invalid severity value: '{sev_b}'")

    if rank_a < rank_b:
        return -1
    if rank_a > rank_b:
        return 1
    return 0


def validate_severity_change(
    current_severity: str,
    new_severity: str,
    allow_downgrade: bool = False,
    reason: Optional[str] = None,
) -> None:
    """Validate an incident severity change.

    Severity escalation is permitted with or without notes.
    Severity downgrade is NEVER done silently: requires allow_downgrade=True
    and an explicit justification reason.

    Raises
    ------
    InvalidSeverityError
        If an unknown severity string is provided.
    SeverityDowngradeError
        If downgrade is attempted without permission or justification.
    """
    comp = compare_severities(new_severity, current_severity)
    if comp == 0:
        return

    if comp < 0:
        # Requested new severity is lower than current severity
        if not allow_downgrade:
            raise SeverityDowngradeError(
                f"Cannot silently downgrade incident severity from '{current_severity}' to '{new_severity}'. "
                "Explicit downgrade approval and rationale are required."
            )
        if not reason or not reason.strip():
            raise SeverityDowngradeError(
                "Downgrading incident severity requires an explicit explanation or reason."
            )
