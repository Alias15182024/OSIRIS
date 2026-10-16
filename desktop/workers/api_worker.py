"""Reusable Qt background worker for non-blocking asynchronous operations.

Provides ApiWorker, a QRunnable-based worker executing arbitrary callables
in a QThreadPool worker thread and delivering outcomes back to the Qt event
loop via thread-safe signals.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, Signal


class ApiWorkerSignals(QObject):
    """Qt signal interface for ApiWorker execution lifecycle.

    Signals:
        result: Emitted upon successful execution with the returned value.
        error: Emitted when the callable raises an Exception.
        finished: Emitted on completion regardless of success or failure.
    """

    result = Signal(object)
    error = Signal(Exception)
    finished = Signal()


class ApiWorker(QRunnable):
    """Generic background worker executing a callable on a QThreadPool thread.

    Parameters:
        fn: The callable to execute asynchronously.
        *args: Positional arguments forwarded to fn.
        **kwargs: Keyword arguments forwarded to fn.

    Example::

        worker = ApiWorker(client.login, username, password)
        worker.signals.result.connect(self._on_success)
        worker.signals.error.connect(self._on_error)
        worker.signals.finished.connect(self._on_finished)
        QThreadPool.globalInstance().start(worker)
    """

    def __init__(
        self,
        fn: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__()
        self.signals = ApiWorkerSignals()
        self._fn: Callable[..., Any] | None = fn
        self._args: tuple[Any, ...] = args
        self._kwargs: dict[str, Any] = kwargs
        self.setAutoDelete(True)

    def run(self) -> None:
        """Execute the target callable off the GUI thread and emit outcome signals."""
        fn = self._fn
        args = self._args
        kwargs = self._kwargs

        try:
            if fn is None:
                return
            result = fn(*args, **kwargs)
            self.signals.result.emit(result)
        except Exception as exc:
            self.signals.error.emit(exc)
        finally:
            # Release callable and argument references to prevent retaining
            # sensitive objects (e.g. credentials) in memory longer than necessary.
            self._fn = None
            self._args = ()
            self._kwargs = {}
            self.signals.finished.emit()


__all__ = [
    "ApiWorker",
    "ApiWorkerSignals",
]
