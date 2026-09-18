"""Persistence layer for normalized events.

``EventRepository`` maps ``NormalizedEvent`` instances to the
SQLAlchemy ``Event`` ORM model and persists them using a caller-provided
session.

Transaction management is the caller's responsibility.  The repository
calls ``session.flush()`` to ensure database errors surface immediately
but does NOT call ``session.commit()`` — the caller decides when to
commit or rollback.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from backend.db.models.event import Event
from backend.services.events.schemas import NormalizedEvent


class EventRepository:
    """Maps normalized events to the SQLAlchemy ORM and persists them.

    Parameters
    ----------
    session:
        An active SQLAlchemy ``Session``.  The caller is responsible for
        committing or rolling back the transaction.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def _to_orm(self, event: NormalizedEvent) -> Event:
        """Convert a ``NormalizedEvent`` to an ``Event`` ORM instance."""
        return Event(
            id=event.id,
            host_id=event.host_id,
            process_id=event.process_id,
            timestamp=event.timestamp,
            ingested_at=event.ingested_at,
            source=event.source,
            event_type=event.event_type,
            action=event.action,
            severity=event.severity,
            uid=event.uid,
            username=event.username,
            pid=event.pid,
            ppid=event.ppid,
            command=event.command,
            object_type=event.object_type,
            object_path=event.object_path,
            success=event.success,
            result=event.result,
            payload=event.payload,
        )

    def save(self, event: NormalizedEvent) -> Event:
        """Persist a single normalized event.

        Returns the ORM ``Event`` instance after flushing.

        Raises
        ------
        sqlalchemy.exc.IntegrityError
            If a database constraint is violated (e.g. FK to a
            non-existent host).
        """
        orm_event = self._to_orm(event)
        self._session.add(orm_event)
        self._session.flush()
        return orm_event

    def save_batch(self, events: list[NormalizedEvent]) -> list[Event]:
        """Persist multiple normalized events in a single flush.

        All events succeed or the entire batch fails (no partial writes).

        Returns
        -------
        list[Event]
            The ORM ``Event`` instances after flushing.
        """
        orm_events = [self._to_orm(e) for e in events]
        self._session.add_all(orm_events)
        self._session.flush()
        return orm_events
