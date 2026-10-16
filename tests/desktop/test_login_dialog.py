"""Tests for the OSIRIS Desktop Login Dialog (LoginDialog).

Verifies:
1. Dialog instantiation, window properties, and widget hierarchy.
2. Immediate inline validation for empty or whitespace credentials.
3. Password field clearing upon submission.
4. UI busy state and control disabling while authenticating.
5. Asynchronous authentication success via ApiWorker.
6. Sanitized inline error messages for authentication, authorization,
   network connection, validation, and unexpected exceptions.
7. Cancellation and window close safeguards during in-flight authentication.
8. End-to-end HTTP integration with real APIClient and respx.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import respx
from httpx import Response
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QApplication, QDialog, QLineEdit

from desktop.client.api_client import APIClient
from desktop.client.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ClientConnectionError,
    ConnectionTimeoutError,
    OSIRISClientError,
    ValidationError,
)
from desktop.client.models import TokenInfo, User
from desktop.ui.login_dialog import LoginDialog


def _wait_for_dialog(dialog: LoginDialog, timeout_ms: int = 5000) -> None:
    """Wait for the dialog's background worker to finish execution."""
    if not dialog.is_authenticating and dialog._active_worker is None:
        QApplication.processEvents()
        return

    loop = QEventLoop()
    timer = QTimer()
    timer.setSingleShot(True)
    timer.timeout.connect(loop.quit)

    if dialog._active_worker is not None:
        dialog._active_worker.signals.finished.connect(loop.quit)

    timer.start(timeout_ms)
    loop.exec()
    QApplication.processEvents()


def test_login_dialog_instantiation(qapp: QApplication) -> None:
    """Verify LoginDialog initializes with correct window and state properties."""
    client = MagicMock(spec=APIClient)
    dialog = LoginDialog(client)

    assert dialog.objectName() == "LoginDialog"
    assert dialog.windowTitle() == "OSIRIS — Security Console Sign In"
    assert dialog.isModal() is True
    assert dialog.width() == 400
    assert dialog.client is client
    assert dialog.authenticated_user is None
    assert dialog.is_authenticating is False

    # Password input must use password echo mode
    assert dialog._password_input.echoMode() == QLineEdit.EchoMode.Password
    assert dialog._feedback_label.isHidden() is True


def test_login_dialog_validation_empty_username(qapp: QApplication) -> None:
    """Verify submitting with empty username shows error without calling client."""
    client = MagicMock(spec=APIClient)
    dialog = LoginDialog(client)
    dialog.show()

    dialog._username_input.setText("")
    dialog._password_input.setText("secret-pass")
    dialog._handle_submit()

    assert dialog.is_authenticating is False
    assert client.login.call_count == 0
    assert dialog._feedback_label.isVisible() is True
    assert dialog._feedback_label.text() == "Please enter your username."
    assert dialog._feedback_label.property("isError") == "true"


def test_login_dialog_validation_whitespace_username(qapp: QApplication) -> None:
    """Verify whitespace-only username is rejected after stripping."""
    client = MagicMock(spec=APIClient)
    dialog = LoginDialog(client)
    dialog.show()

    dialog._username_input.setText("   ")
    dialog._password_input.setText("secret-pass")
    dialog._handle_submit()

    assert dialog.is_authenticating is False
    assert client.login.call_count == 0
    assert dialog._feedback_label.text() == "Please enter your username."


def test_login_dialog_validation_empty_password(qapp: QApplication) -> None:
    """Verify submitting with empty password shows error without calling client."""
    client = MagicMock(spec=APIClient)
    dialog = LoginDialog(client)
    dialog.show()

    dialog._username_input.setText("validuser")
    dialog._password_input.setText("")
    dialog._handle_submit()

    assert dialog.is_authenticating is False
    assert client.login.call_count == 0
    assert dialog._feedback_label.isVisible() is True
    assert dialog._feedback_label.text() == "Please enter your password."
    assert dialog._feedback_label.property("isError") == "true"


def test_login_dialog_password_cleared_on_submit(qapp: QApplication) -> None:
    """Verify password field is cleared immediately when submit is initiated."""
    client = MagicMock(spec=APIClient)
    client.login.return_value = TokenInfo(
        access_token="tok",
        token_type="bearer",
        user=User(
            id="u1",
            username="admin",
            display_name="Admin",
            role="admin",
            is_active=True,
            created_at="2026-01-01T00:00:00Z",
        ),
    )
    dialog = LoginDialog(client)
    dialog.show()

    dialog._username_input.setText("admin")
    dialog._password_input.setText("my_secret_password")

    dialog._handle_submit()

    # Password field must be cleared immediately after reading
    assert dialog._password_input.text() == ""

    _wait_for_dialog(dialog)


def test_login_dialog_successful_authentication(qapp: QApplication) -> None:
    """Verify successful login accepts dialog and sets authenticated_user."""
    user = User(
        id="usr-123",
        username="secops",
        display_name="Security Analyst",
        role="analyst",
        is_active=True,
        created_at="2026-01-01T00:00:00Z",
    )
    token_info = TokenInfo(
        access_token="jwt-token-xyz",
        token_type="bearer",
        user=user,
    )
    client = MagicMock(spec=APIClient)
    client.login.return_value = token_info

    dialog = LoginDialog(client)
    dialog.show()
    dialog._username_input.setText("secops")
    dialog._password_input.setText("SuperSecret123!")

    dialog._handle_submit()
    _wait_for_dialog(dialog)

    assert dialog.result() == QDialog.DialogCode.Accepted
    assert dialog.authenticated_user == user
    assert dialog.is_authenticating is False
    assert dialog._submit_btn.isEnabled() is True


def test_login_dialog_authentication_error(qapp: QApplication) -> None:
    """Verify AuthenticationError displays sanitized invalid credential message."""
    client = MagicMock(spec=APIClient)
    client.login.side_effect = AuthenticationError("Invalid username or password")

    dialog = LoginDialog(client)
    dialog.show()
    dialog._username_input.setText("unknown_user")
    dialog._password_input.setText("wrong_password")

    dialog._handle_submit()
    _wait_for_dialog(dialog)

    assert dialog.result() != QDialog.DialogCode.Accepted
    assert dialog.authenticated_user is None
    assert dialog.is_authenticating is False
    assert dialog._feedback_label.isVisible() is True
    assert (
        dialog._feedback_label.text()
        == "Invalid username or password. Please try again."
    )
    assert dialog._feedback_label.property("isError") == "true"
    assert dialog._submit_btn.isEnabled() is True


def test_login_dialog_authorization_error(qapp: QApplication) -> None:
    """Verify AuthorizationError displays deactivated account message."""
    client = MagicMock(spec=APIClient)
    client.login.side_effect = AuthorizationError("User is deactivated")

    dialog = LoginDialog(client)
    dialog.show()
    dialog._username_input.setText("banned_user")
    dialog._password_input.setText("some_password")

    dialog._handle_submit()
    _wait_for_dialog(dialog)

    assert dialog.result() != QDialog.DialogCode.Accepted
    assert dialog.authenticated_user is None
    assert (
        dialog._feedback_label.text()
        == "User account is deactivated or unauthorized."
    )


def test_login_dialog_connection_errors(qapp: QApplication) -> None:
    """Verify connection and timeout errors display sanitized network feedback."""
    for error_cls in (ClientConnectionError, ConnectionTimeoutError):
        client = MagicMock(spec=APIClient)
        client.login.side_effect = error_cls("Cannot connect to host: 127.0.0.1:8000")

        dialog = LoginDialog(client)
        dialog.show()
        dialog._username_input.setText("admin")
        dialog._password_input.setText("pass")

        dialog._handle_submit()
        _wait_for_dialog(dialog)

        assert (
            dialog._feedback_label.text()
            == "Unable to connect to the authentication service. "
            "Please verify that the server is online."
        )


def test_login_dialog_validation_error(qapp: QApplication) -> None:
    """Verify ValidationError displays sanitized format failure feedback."""
    client = MagicMock(spec=APIClient)
    client.login.side_effect = ValidationError("Invalid payload structure")

    dialog = LoginDialog(client)
    dialog.show()
    dialog._username_input.setText("admin")
    dialog._password_input.setText("pass")

    dialog._handle_submit()
    _wait_for_dialog(dialog)

    assert (
        dialog._feedback_label.text()
        == "Authentication request failed due to invalid data format."
    )


def test_login_dialog_client_custom_error(qapp: QApplication) -> None:
    """Verify OSIRISClientError displays its message safely."""
    client = MagicMock(spec=APIClient)
    client.login.side_effect = OSIRISClientError("Custom gateway timeout")

    dialog = LoginDialog(client)
    dialog.show()
    dialog._username_input.setText("admin")
    dialog._password_input.setText("pass")

    dialog._handle_submit()
    _wait_for_dialog(dialog)

    assert dialog._feedback_label.text() == "Custom gateway timeout"


def test_login_dialog_unexpected_exception(qapp: QApplication) -> None:
    """Verify unhandled Exception displays generic message without leaking details."""
    client = MagicMock(spec=APIClient)
    client.login.side_effect = RuntimeError("Fatal DB stack trace / token leaked")

    dialog = LoginDialog(client)
    dialog.show()
    dialog._username_input.setText("admin")
    dialog._password_input.setText("pass")

    dialog._handle_submit()
    _wait_for_dialog(dialog)

    # Must NOT contain the raw internal error details
    assert "Fatal DB stack trace" not in dialog._feedback_label.text()
    assert (
        dialog._feedback_label.text()
        == "An unexpected error occurred during authentication."
    )


def test_login_dialog_cancel_button_idle(qapp: QApplication) -> None:
    """Verify Cancel button rejects dialog when idle."""
    client = MagicMock(spec=APIClient)
    dialog = LoginDialog(client)

    dialog._cancel_btn.click()
    assert dialog.result() == QDialog.DialogCode.Rejected


def test_login_dialog_cancellation_ignored_when_busy(qapp: QApplication) -> None:
    """Verify cancel and reject are blocked while authentication is in flight."""
    client = MagicMock(spec=APIClient)
    dialog = LoginDialog(client)
    dialog.show()
    assert dialog.isVisible() is True

    # When authenticating, cancel and reject are ignored; dialog remains visible
    dialog._is_authenticating = True
    dialog._handle_cancel()
    assert dialog.isVisible() is True

    dialog.reject()
    assert dialog.isVisible() is True

    # When idle, cancel closes the dialog
    dialog._is_authenticating = False
    dialog._handle_cancel()
    assert dialog.isVisible() is False
    assert dialog.result() == QDialog.DialogCode.Rejected


def test_login_dialog_close_event_ignored_when_busy(qapp: QApplication) -> None:
    """Verify window close event is ignored when authenticating."""
    client = MagicMock(spec=APIClient)
    dialog = LoginDialog(client)

    event = QCloseEvent()
    dialog._is_authenticating = True
    dialog.closeEvent(event)
    assert event.isAccepted() is False

    event2 = QCloseEvent()
    dialog._is_authenticating = False
    dialog.closeEvent(event2)
    assert event2.isAccepted() is True


@respx.mock
def test_login_dialog_respx_end_to_end_integration(qapp: QApplication) -> None:
    """Verify end-to-end authentication flow using real APIClient and respx."""
    base_url = "http://127.0.0.1:8000"
    respx.post(f"{base_url}/api/auth/login").mock(
        return_value=Response(
            200,
            json={
                "access_token": "mock-real-access-token",
                "token_type": "bearer",
                "user": {
                    "id": "e2e-user-123",
                    "username": "lead_investigator",
                    "display_name": "Lead Investigator",
                    "role": "admin",
                    "is_active": True,
                    "created_at": "2026-01-01T00:00:00Z",
                },
            },
        )
    )

    client = APIClient(base_url=base_url)
    try:
        dialog = LoginDialog(client)
        dialog._username_input.setText("lead_investigator")
        dialog._password_input.setText("correct-horse-battery-staple")

        dialog._handle_submit()
        _wait_for_dialog(dialog)

        assert dialog.result() == QDialog.DialogCode.Accepted
        assert dialog.authenticated_user is not None
        assert dialog.authenticated_user.username == "lead_investigator"
        assert client.is_authenticated is True
        assert client._token == "mock-real-access-token"
    finally:
        client.logout()
        client.close()
