"""Tests for the reusable Qt background worker (ApiWorker).

Verifies:
1. Instantiation and signal interface.
2. Successful callable execution and result emission.
3. Error propagation on exception.
4. Finished signal emission under both success and error outcomes.
5. Execution off the GUI thread on QThreadPool.
6. Argument forwarding to callables.
7. Memory cleanup: callable and arguments cleared in finally block.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QEventLoop, QThread, QThreadPool, QTimer
from PySide6.QtWidgets import QApplication

from desktop.workers.api_worker import ApiWorker, ApiWorkerSignals


def test_api_worker_signals_interface() -> None:
    """Verify ApiWorkerSignals defines result, error, and finished signals."""
    signals = ApiWorkerSignals()
    assert hasattr(signals, "result")
    assert hasattr(signals, "error")
    assert hasattr(signals, "finished")


def test_api_worker_initialization() -> None:
    """Verify ApiWorker initializes with auto-delete enabled and stores inputs."""
    def sample_func(x: int, y: str = "default") -> str:
        return f"{x}-{y}"

    worker = ApiWorker(sample_func, 42, y="custom")
    assert worker.autoDelete() is True
    assert isinstance(worker.signals, ApiWorkerSignals)
    assert worker._fn is sample_func
    assert worker._args == (42,)
    assert worker._kwargs == {"y": "custom"}


def test_api_worker_success_execution_direct() -> None:
    """Verify direct run() execution emits result and finished, clearing references."""
    results: list[Any] = []
    errors: list[Exception] = []
    finished_called: list[bool] = []

    def compute(a: int, b: int) -> int:
        return a + b

    worker = ApiWorker(compute, 10, b=20)
    worker.signals.result.connect(results.append)
    worker.signals.error.connect(errors.append)
    worker.signals.finished.connect(lambda: finished_called.append(True))

    worker.run()

    assert results == [30]
    assert errors == []
    assert finished_called == [True]
    # Verify memory cleanup
    assert worker._fn is None
    assert worker._args == ()
    assert worker._kwargs == {}


def test_api_worker_error_execution_direct() -> None:
    """Verify run() on exception emits error and finished, clearing references."""
    results: list[Any] = []
    errors: list[Exception] = []
    finished_called: list[bool] = []

    def failing_task() -> None:
        raise ValueError("Simulated network failure")

    worker = ApiWorker(failing_task)
    worker.signals.result.connect(results.append)
    worker.signals.error.connect(errors.append)
    worker.signals.finished.connect(lambda: finished_called.append(True))

    worker.run()

    assert results == []
    assert len(errors) == 1
    assert isinstance(errors[0], ValueError)
    assert str(errors[0]) == "Simulated network failure"
    assert finished_called == [True]
    # Verify memory cleanup
    assert worker._fn is None
    assert worker._args == ()
    assert worker._kwargs == {}


def test_api_worker_run_with_none_fn_is_noop() -> None:
    """Verify run() does not crash or emit result when _fn is None."""
    results: list[Any] = []
    finished_called: list[bool] = []

    worker = ApiWorker(lambda: 1)
    worker._fn = None
    worker.signals.result.connect(results.append)
    worker.signals.finished.connect(lambda: finished_called.append(True))

    worker.run()

    assert results == []
    assert finished_called == [True]


def test_api_worker_executes_off_gui_thread(qapp: QApplication) -> None:
    """Verify ApiWorker runs in a worker thread separate from QApplication thread."""
    main_thread = qapp.thread()
    worker_threads: list[QThread] = []
    results: list[str] = []

    def background_task(msg: str) -> str:
        worker_threads.append(QThread.currentThread())
        return f"processed: {msg}"

    worker = ApiWorker(background_task, "test-data")
    loop = QEventLoop()

    worker.signals.result.connect(results.append)
    worker.signals.finished.connect(loop.quit)

    # 5-second safeguard timeout
    timer = QTimer()
    timer.setSingleShot(True)
    timer.timeout.connect(loop.quit)
    timer.start(5000)

    QThreadPool.globalInstance().start(worker)
    loop.exec()

    assert results == ["processed: test-data"]
    assert len(worker_threads) == 1
    assert worker_threads[0] != main_thread
