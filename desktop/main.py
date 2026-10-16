"""OSIRIS Desktop application entrypoint."""

from __future__ import annotations

import argparse
import sys

from PySide6.QtWidgets import QApplication, QDialog

from desktop.client.api_client import (
    DEFAULT_BASE_URL,
    APIClient,
    validate_base_url,
)
from desktop.client.exceptions import ValidationError
from desktop.ui import load_stylesheet
from desktop.ui.login_dialog import LoginDialog
from desktop.ui.main_window import MainWindow, is_root_execution


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for the desktop application."""
    parser = argparse.ArgumentParser(
        description="OSIRIS Desktop Security Console",
        prog="osiris-desktop",
    )
    parser.add_argument(
        "--api-url",
        dest="api_url",
        default=DEFAULT_BASE_URL,
        help="Base URL for the OSIRIS API server (default: %(default)s)",
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        default=False,
        help="Allow non-loopback remote API base URLs",
    )
    args_list = [] if argv is None else argv
    return parser.parse_args(args_list)


def main(argv: list[str] | None = None) -> int:
    """Launch the OSIRIS Desktop application and coordinate authentication.

    Initializes the Qt application instance, loads the centralized stylesheet,
    validates API connection configuration, enforces loopback restrictions,
    checks for root privileges, and presents the modal LoginDialog. If
    authentication succeeds (dialog accepted), displays MainWindow and enters
    the event loop. Cleans up session and network state upon exit.
    """
    parsed = parse_args(argv)

    try:
        base_url = validate_base_url(
            parsed.api_url, allow_remote=parsed.allow_remote
        )
    except ValidationError as exc:
        sys.stderr.write(f"Configuration error: {exc}\n")
        return 2

    inst = QApplication.instance()
    app = inst if isinstance(inst, QApplication) else QApplication(sys.argv)

    app.setApplicationName("OSIRIS Desktop")
    app.setStyleSheet(load_stylesheet())

    is_root = is_root_execution()
    client = APIClient(base_url=base_url, allow_remote=parsed.allow_remote)
    try:
        dialog = LoginDialog(client)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return 0
        user = dialog.authenticated_user
        if user is None:
            return 0
        window = MainWindow(client=client, user=user, is_root=is_root)
        window.show()
        return app.exec()
    finally:
        client.logout()
        client.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
