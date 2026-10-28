"""Standalone Collector Runner for OSIRIS.

Provides a dedicated, independently executable entry point (`python -m collectors.runner`)
for running OSIRIS Linux system collectors outside of the FastAPI web application.
Can be managed by systemd as a background daemon or executed for bounded testing cycles.

Exit Codes:
-----------
0: Clean exit after completion of bounded cycles or clean signal shutdown (SIGINT/SIGTERM).
1: Unrecoverable runtime or collector startup failure.
2: Configuration or CLI argument validation error.
"""

from __future__ import annotations

import argparse
import logging
import math
import signal
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Callable

from sqlalchemy.orm import Session

from backend.config import ConfigurationError, settings
from collectors.filesystem.inotify import InotifyBackend, MockInotifyBackend
from collectors.orchestrator import (
    CollectorOrchestrator,
    CollectorStartupError,
    CycleResult,
    OrchestratorConfig,
    OrchestratorError,
    OrchestratorState,
    resolve_host_uuid,
)

logger = logging.getLogger("osiris.collectors.runner")

# Sentinel for default session factory resolution
_DEFAULT_FACTORY = object()


def create_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser for the collector runner."""
    parser = argparse.ArgumentParser(
        prog="python -m collectors.runner",
        description="OSIRIS Standalone Collector Runner daemon and CLI entry point.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        default=False,
        help="Run exactly one collection cycle and exit.",
    )
    parser.add_argument(
        "--cycles",
        type=int,
        default=None,
        metavar="N",
        help="Run a bounded number of collection cycles (N >= 1) and exit.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="Delay between collection cycles in seconds (> 0, default 2.0s).",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        default=False,
        help="Run continuously until interrupted by SIGINT or SIGTERM.",
    )
    parser.add_argument(
        "--host-id",
        type=str,
        default=None,
        metavar="ID",
        help="Monitored host UUID or identifier string (default from OSIRIS_HOST_ID).",
    )
    parser.add_argument(
        "--proc-dir",
        type=str,
        default=None,
        metavar="PATH",
        help="Optional procfs path override (default: /proc).",
    )
    parser.add_argument(
        "--passwd-file",
        type=str,
        default=None,
        metavar="PATH",
        help="Optional passwd file path override (default: /etc/passwd).",
    )
    parser.add_argument(
        "--watch-path",
        action="append",
        dest="watch_paths",
        default=[],
        metavar="PATH",
        help="Optional repeatable watch path for filesystem monitoring.",
    )
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Validate argument values and combination semantics according to L-1 contract."""
    # 1. Bounded cycles validation
    if args.cycles is not None and args.cycles < 1:
        parser.error(f"--cycles must be an integer >= 1, got {args.cycles}")

    # 2. Interval validation
    if args.interval is not None and (not math.isfinite(args.interval) or args.interval <= 0):
        parser.error(f"--interval must be a positive finite number (> 0), got {args.interval}")

    # 3. Mode mutual exclusivity and combination semantics
    if args.once and args.watch:
        parser.error("Cannot combine --once and --watch modes")

    if args.cycles is not None and args.watch:
        parser.error("Cannot combine --cycles and --watch modes")

    if args.once and args.cycles is not None:
        if args.cycles != 1:
            parser.error("Cannot combine --once with --cycles != 1")

    # 4. Resolve default mode: if none specified, default to continuous watch mode
    if not args.once and args.cycles is None and not args.watch:
        args.watch = True

    # 5. Default host_id from application settings
    if args.host_id is None:
        args.host_id = settings.host_id


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and validate command line arguments."""
    parser = create_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    return args


class CollectorRunner:
    """Standalone OSIRIS Collector Runner for managing collector cycles.

    Executes collector cycles independently of the FastAPI web application,
    either once, for a fixed number of cycles, or continuously as a daemon.
    """

    def __init__(
        self,
        orchestrator: CollectorOrchestrator | None = None,
        *,
        config: OrchestratorConfig | None = None,
        once: bool = False,
        cycles: int | None = None,
        interval: float = 2.0,
        watch: bool = False,
        host_id: uuid.UUID | str | None = None,
        proc_dir: Path | str | None = None,
        passwd_file: Path | str | None = None,
        watch_paths: list[Path | str] | None = None,
        fs_backend: InotifyBackend | None = None,
        session_factory: Callable[[], Session] | None | object = _DEFAULT_FACTORY,
        session: Session | None = None,
        force_all: bool = True,
    ) -> None:
        # Validate arguments
        if cycles is not None and cycles < 1:
            raise ValueError(f"cycles must be an integer >= 1, got {cycles}")
        if not math.isfinite(interval) or interval <= 0:
            raise ValueError(f"interval must be a positive finite number (> 0), got {interval}")
        if once and watch:
            raise ValueError("Cannot combine once and watch modes")
        if cycles is not None and watch:
            raise ValueError("Cannot combine cycles and watch modes")
        if once and cycles is not None and cycles != 1:
            raise ValueError("Cannot combine once with cycles != 1")

        # Determine execution bounds
        if once:
            self.cycles: int | None = 1
            self.watch: bool = False
        elif cycles is not None:
            self.cycles = cycles
            self.watch = False
        else:
            self.cycles = None
            self.watch = True

        self.interval = float(interval)
        self.force_all = force_all
        self._shutdown_event = threading.Event()
        self._cycle_count = 0
        self._total_persisted_events = 0
        self._is_running = False

        # Host ID resolution
        effective_host_id = host_id if host_id is not None else settings.host_id
        self.host_uuid = resolve_host_uuid(effective_host_id)

        # Inotify backend cross-platform resolution
        effective_fs_backend = fs_backend
        if effective_fs_backend is None and sys.platform != "linux":
            effective_fs_backend = MockInotifyBackend()

        # Orchestrator setup
        if orchestrator is not None:
            self.orchestrator = orchestrator
            if hasattr(orchestrator, "host_uuid") and orchestrator.host_uuid is not None:
                self.host_uuid = orchestrator.host_uuid
        else:
            orch_config = config or OrchestratorConfig(
                host_id=self.host_uuid,
                process_interval=self.interval,
                resource_interval=self.interval,
                proc_dir=proc_dir if proc_dir is not None else "/proc",
                passwd_file=passwd_file if passwd_file is not None else "/etc/passwd",
                filesystem_paths=list(watch_paths or []),
                fs_backend=effective_fs_backend,
            )

            if session is not None:
                # Caller-owned session: runner will not commit top-level or close
                self.orchestrator = CollectorOrchestrator(orch_config, session=session)
            elif session_factory is not _DEFAULT_FACTORY:
                # Injected factory (or None for pure in-memory mode)
                self.orchestrator = CollectorOrchestrator(
                    orch_config, session_factory=session_factory
                )
            else:
                # Default standalone daemon behavior: use SessionLocal from backend.db.session
                from backend.db.session import SessionLocal

                self.orchestrator = CollectorOrchestrator(
                    orch_config, session_factory=SessionLocal
                )

    @classmethod
    def from_args(
        cls,
        args: argparse.Namespace,
        *,
        orchestrator: CollectorOrchestrator | None = None,
        fs_backend: InotifyBackend | None = None,
        session_factory: Callable[[], Session] | None | object = _DEFAULT_FACTORY,
        session: Session | None = None,
        force_all: bool = True,
    ) -> CollectorRunner:
        """Construct a CollectorRunner from parsed CLI arguments."""
        cycles = 1 if args.once else args.cycles
        watch = args.watch or (not args.once and args.cycles is None)
        if cycles is not None:
            watch = False

        return cls(
            orchestrator=orchestrator,
            cycles=cycles,
            interval=args.interval,
            watch=watch,
            host_id=args.host_id,
            proc_dir=args.proc_dir,
            passwd_file=args.passwd_file,
            watch_paths=args.watch_paths,
            fs_backend=fs_backend,
            session_factory=session_factory,
            session=session,
            force_all=force_all,
        )

    @classmethod
    def from_argv(
        cls,
        argv: list[str] | None = None,
        *,
        orchestrator: CollectorOrchestrator | None = None,
        fs_backend: InotifyBackend | None = None,
        session_factory: Callable[[], Session] | None | object = _DEFAULT_FACTORY,
        session: Session | None = None,
        force_all: bool = True,
    ) -> CollectorRunner:
        """Construct a CollectorRunner directly from command line arguments."""
        args = parse_args(argv)
        return cls.from_args(
            args,
            orchestrator=orchestrator,
            fs_backend=fs_backend,
            session_factory=session_factory,
            session=session,
            force_all=force_all,
        )

    @property
    def cycle_count(self) -> int:
        """Total number of cycles executed by this runner instance."""
        return self._cycle_count

    @property
    def total_persisted_events(self) -> int:
        """Total number of healthy events successfully persisted by this runner."""
        return self._total_persisted_events

    @property
    def shutdown_event(self) -> threading.Event:
        """Interruptible event signaling shutdown."""
        return self._shutdown_event

    @property
    def is_running(self) -> bool:
        """True if the runner cycle loop is currently active."""
        return self._is_running

    def stop(self) -> None:
        """Signal the runner and orchestrator to stop gracefully."""
        self._shutdown_event.set()
        if self.orchestrator is not None and hasattr(self.orchestrator, "stop"):
            try:
                self.orchestrator.stop()
            except Exception as exc:
                logger.warning("Error stopping orchestrator: %s", exc)

    def _handle_signal(self, signum: int, frame: Any) -> None:
        """Handle termination signals (SIGINT, SIGTERM) gracefully."""
        sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
        logger.info("Received %s signal, initiating clean shutdown...", sig_name)
        self.stop()

    def run(self) -> int:
        """Execute collector cycles according to configuration.

        Returns
        -------
        int
            Exit code: 0 for clean completion/shutdown, 1 for fatal error.
        """
        # Register signal handlers when executing in the main thread
        old_sigint = None
        old_sigterm = None
        try:
            old_sigint = signal.signal(signal.SIGINT, self._handle_signal)
            old_sigterm = signal.signal(signal.SIGTERM, self._handle_signal)
        except (ValueError, AttributeError):
            logger.debug("Signal handlers could not be installed (likely running in worker thread)")

        self._is_running = True
        try:
            # Start orchestrator if stopped
            state = getattr(self.orchestrator, "state", None)
            is_stopped = (
                state in (OrchestratorState.STOPPED, "stopped")
                or state is None
                or not isinstance(state, OrchestratorState)
            )
            if hasattr(self.orchestrator, "start") and is_stopped:
                logger.info(
                    "Starting collector orchestrator for host %s...",
                    self.host_uuid,
                )
                try:
                    self.orchestrator.start(background=False)
                except Exception as exc:
                    logger.critical(
                        "Fatal failure during collector startup: %s",
                        exc,
                        exc_info=True,
                    )
                    return 1

            # Cycle execution loop
            while not self._shutdown_event.is_set():
                try:
                    result: CycleResult = self.orchestrator.run_cycle(
                        force_all=self.force_all
                    )
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as exc:
                    logger.critical(
                        "Unrecoverable runtime error during collector cycle: %s",
                        exc,
                        exc_info=True,
                    )
                    return 1

                self._cycle_count += 1
                persisted_count = len(result.events) if result.events else 0
                self._total_persisted_events += persisted_count

                # Cycle reporting and degraded status handling
                if result.collector_errors:
                    logger.warning(
                        "Collector cycle %d completed in degraded state (collector errors: %s). "
                        "Persisted %d healthy events.",
                        self._cycle_count,
                        result.collector_errors,
                        persisted_count,
                    )
                elif not result.success:
                    logger.warning(
                        "Collector cycle %d completed with errors: sink_errors=%s, processing_errors=%s. "
                        "Persisted %d events.",
                        self._cycle_count,
                        result.sink_errors,
                        result.processing_errors,
                        persisted_count,
                    )
                else:
                    logger.info(
                        "Collector cycle %d succeeded: %d observations, %d events persisted in %.2fms.",
                        self._cycle_count,
                        result.observations_count,
                        persisted_count,
                        result.duration_ms,
                    )

                # Check bounded cycle completion
                if self.cycles is not None and self._cycle_count >= self.cycles:
                    logger.info(
                        "Completed %d requested cycle(s), exiting cleanly.",
                        self._cycle_count,
                    )
                    break

                # Sleep interruptibly until next cycle
                if self._shutdown_event.wait(timeout=self.interval):
                    logger.info("Shutdown event received during interval wait.")
                    break

            return 0

        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt received, shutting down cleanly...")
            self.stop()
            return 0
        except Exception as exc:
            logger.critical("Fatal failure in collector runner: %s", exc, exc_info=True)
            return 1
        finally:
            self._is_running = False
            if self.orchestrator is not None and hasattr(self.orchestrator, "stop"):
                try:
                    self.orchestrator.stop()
                except Exception as exc:
                    logger.warning("Error stopping orchestrator during cleanup: %s", exc)

            # Restore original signal handlers
            if old_sigint is not None:
                try:
                    signal.signal(signal.SIGINT, old_sigint)
                except (ValueError, AttributeError):
                    pass
            if old_sigterm is not None:
                try:
                    signal.signal(signal.SIGTERM, old_sigterm)
                except (ValueError, AttributeError):
                    pass


def main(
    argv: list[str] | None = None,
    *,
    orchestrator: CollectorOrchestrator | None = None,
    fs_backend: InotifyBackend | None = None,
    session_factory: Callable[[], Session] | None | object = _DEFAULT_FACTORY,
    session: Session | None = None,
    force_all: bool = True,
) -> int:
    """Main CLI entry point for the OSIRIS standalone collector runner.

    Parameters
    ----------
    argv:
        Command-line argument list (default: sys.argv[1:]).
    orchestrator:
        Optional injected CollectorOrchestrator for testing.
    fs_backend:
        Optional custom inotify backend.
    session_factory:
        Optional injected session factory.
    session:
        Optional injected caller-owned Session (M-4 contract).
    force_all:
        Whether run_cycle forces collection across all sources (default: True).

    Returns
    -------
    int
        Exit code (0: clean exit, 1: fatal error, 2: config/args error).
    """
    try:
        runner = CollectorRunner.from_argv(
            argv,
            orchestrator=orchestrator,
            fs_backend=fs_backend,
            session_factory=session_factory,
            session=session,
            force_all=force_all,
        )
    except SystemExit:
        # Re-raise argparse SystemExit (e.g. exit code 2 on validation failure)
        raise
    except (ValueError, ConfigurationError) as exc:
        logger.error("Configuration error: %s", exc)
        return 2
    except Exception as exc:
        logger.critical("Fatal startup failure: %s", exc, exc_info=True)
        return 1

    try:
        return runner.run()
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 1
    except Exception as exc:
        logger.critical("Fatal unhandled runner exception: %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    sys.exit(main())
