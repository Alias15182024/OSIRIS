"""Tests for the OSIRIS Desktop application entrypoint."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from PySide6.QtWidgets import QApplication, QDialog

from desktop.client.models import User
from desktop.main import main
from desktop.ui import load_stylesheet
from desktop.ui.app_shell import AppShell
from desktop.ui.main_window import MainWindow


def _sample_user() -> User:
    """Return a representative authenticated User instance for tests."""
    return User(
        id="u-001",
        username="secops_lead",
        display_name="Lead Security Analyst",
        role="admin",
        is_active=True,
        created_at="2026-01-01T00:00:00Z",
    )


def test_main_entrypoint_importable() -> None:
    """Verify desktop.main module imports and exposes a callable entrypoint."""
    assert callable(main)


def test_qapplication_name(qapp: QApplication) -> None:
    """Verify QApplication can initialize with the correct application name."""
    assert isinstance(qapp, QApplication)
    qapp.setApplicationName("OSIRIS Desktop")
    assert qapp.applicationName() == "OSIRIS Desktop"


def test_desktop_assembly_smoke(qapp: QApplication) -> None:
    """Smoke test: the entrypoint construction sequence assembles successfully.

    Reproduces the same steps as main() — set the application name, load and
    apply the stylesheet, instantiate MainWindow, and show it — without entering
    the blocking event loop.
    """
    qapp.setApplicationName("OSIRIS Desktop")
    qapp.setStyleSheet(load_stylesheet())

    user = _sample_user()
    window = MainWindow(user=user)
    window.show()

    assert window.isVisible()
    assert window.windowTitle() == "OSIRIS Desktop"

    # Verify the shell is in place with authenticated identity
    assert isinstance(window.centralWidget(), AppShell)
    assert window.shell.current_page_name == "Overview"
    assert window.shell.user is user

    # Verify stylesheet was applied
    assert len(qapp.styleSheet()) > 0

    # Clean up
    window.close()
    qapp.setStyleSheet("")


def test_main_rejected_login_exits_zero(qapp: QApplication) -> None:
    """Verify main() exits with 0 and cleans up when login dialog is rejected."""
    with (
        patch("desktop.main.LoginDialog") as mock_dialog_cls,
        patch("desktop.main.APIClient") as mock_client_cls,
        patch("desktop.main.MainWindow") as mock_window_cls,
    ):
        mock_dialog = MagicMock()
        mock_dialog.exec.return_value = QDialog.DialogCode.Rejected
        mock_dialog_cls.return_value = mock_dialog

        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        exit_code = main()

        assert exit_code == 0
        mock_dialog.exec.assert_called_once()
        mock_window_cls.assert_not_called()
        mock_client.logout.assert_called_once()
        mock_client.close.assert_called_once()


def test_main_accepted_login_without_user_exits_zero(qapp: QApplication) -> None:
    """Verify main() exits 0 if dialog is accepted without an authenticated user."""
    with (
        patch("desktop.main.LoginDialog") as mock_dialog_cls,
        patch("desktop.main.APIClient") as mock_client_cls,
        patch("desktop.main.MainWindow") as mock_window_cls,
    ):
        mock_dialog = MagicMock()
        mock_dialog.exec.return_value = QDialog.DialogCode.Accepted
        mock_dialog.authenticated_user = None
        mock_dialog_cls.return_value = mock_dialog

        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        exit_code = main()

        assert exit_code == 0
        mock_dialog.exec.assert_called_once()
        mock_window_cls.assert_not_called()
        mock_client.logout.assert_called_once()
        mock_client.close.assert_called_once()


def test_main_accepted_login_passes_session_to_main_window(
    qapp: QApplication,
) -> None:
    """Verify main() passes existing APIClient and authenticated User to MainWindow."""
    user = _sample_user()
    with (
        patch("desktop.main.LoginDialog") as mock_dialog_cls,
        patch("desktop.main.APIClient") as mock_client_cls,
        patch("desktop.main.MainWindow") as mock_window_cls,
        patch.object(qapp, "exec", return_value=42) as mock_exec,
    ):
        mock_dialog = MagicMock()
        mock_dialog.exec.return_value = QDialog.DialogCode.Accepted
        mock_dialog.authenticated_user = user
        mock_dialog_cls.return_value = mock_dialog

        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        mock_window = MagicMock()
        mock_window_cls.return_value = mock_window

        exit_code = main()

        assert exit_code == 42
        mock_dialog.exec.assert_called_once()
        mock_window_cls.assert_called_once_with(
            client=mock_client, user=user, is_root=False
        )
        mock_window.show.assert_called_once()
        mock_exec.assert_called_once()
        mock_client.logout.assert_called_once()
        mock_client.close.assert_called_once()


def test_main_cleans_up_client_on_exception(qapp: QApplication) -> None:
    """Verify client logout and close occur even if an unhandled exception occurs."""
    with (
        patch("desktop.main.LoginDialog") as mock_dialog_cls,
        patch("desktop.main.APIClient") as mock_client_cls,
    ):
        mock_dialog = MagicMock()
        mock_dialog.exec.side_effect = RuntimeError("Fatal UI crash")
        mock_dialog_cls.return_value = mock_dialog

        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        try:
            main()
        except RuntimeError:
            pass

        mock_client.logout.assert_called_once()
        mock_client.close.assert_called_once()
