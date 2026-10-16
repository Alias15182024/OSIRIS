"""OSIRIS Desktop Login Dialog.

Provides LoginDialog, a modal security console authentication dialog
coordinating asynchronous credential verification via ApiWorker and APIClient.
"""

from __future__ import annotations

from PySide6.QtCore import QThreadPool
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

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
from desktop.ui.design_tokens import (
    SPACE_2,
    SPACE_3,
    SPACE_4,
    SPACE_6,
)
from desktop.workers.api_worker import ApiWorker


class LoginDialog(QDialog):
    """Modal authentication dialog for the OSIRIS Desktop security console.

    Accepts an injected APIClient instance, validates user input, executes
    login requests asynchronously off the GUI thread via ApiWorker, and
    provides sanitized inline feedback.
    """

    def __init__(
        self,
        client: APIClient,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("LoginDialog")
        self.setWindowTitle("OSIRIS — Security Console Sign In")
        self.setModal(True)
        self.setFixedWidth(400)

        self._client = client
        self._is_authenticating: bool = False
        self._authenticated_user: User | None = None
        self._active_worker: ApiWorker | None = None

        self._build_ui()

    # -----------------------------------------------------------------------
    # UI Construction
    # -----------------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACE_6, SPACE_6, SPACE_6, SPACE_6)
        layout.setSpacing(SPACE_4)

        # Brand header
        brand_block = QWidget(self)
        brand_block.setObjectName("LoginBrandContainer")
        brand_ly = QVBoxLayout(brand_block)
        brand_ly.setContentsMargins(0, 0, 0, 0)
        brand_ly.setSpacing(SPACE_2)

        title = QLabel("OSIRIS", brand_block)
        title.setObjectName("LoginBrandTitle")

        subtitle = QLabel("Endpoint Intelligence", brand_block)
        subtitle.setObjectName("LoginBrandSubtitle")

        desc = QLabel(
            "Sign in to access the security operations console.",
            brand_block,
        )
        desc.setObjectName("LoginDescription")
        desc.setWordWrap(True)

        brand_ly.addWidget(title)
        brand_ly.addWidget(subtitle)
        brand_ly.addWidget(desc)
        layout.addWidget(brand_block)

        # Input fields
        form_block = QWidget(self)
        form_block.setObjectName("LoginFormContainer")
        form_ly = QVBoxLayout(form_block)
        form_ly.setContentsMargins(0, 0, 0, 0)
        form_ly.setSpacing(SPACE_3)

        user_label = QLabel("Username", form_block)
        user_label.setObjectName("LoginUsernameLabel")
        self._username_input = QLineEdit(form_block)
        self._username_input.setObjectName("LoginUsernameInput")
        self._username_input.setPlaceholderText("Enter username")
        self._username_input.returnPressed.connect(self._handle_submit)

        pass_label = QLabel("Password", form_block)
        pass_label.setObjectName("LoginPasswordLabel")
        self._password_input = QLineEdit(form_block)
        self._password_input.setObjectName("LoginPasswordInput")
        self._password_input.setPlaceholderText("Enter password")
        self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_input.returnPressed.connect(self._handle_submit)

        form_ly.addWidget(user_label)
        form_ly.addWidget(self._username_input)
        form_ly.addWidget(pass_label)
        form_ly.addWidget(self._password_input)
        layout.addWidget(form_block)

        # Inline feedback / error label
        self._feedback_label = QLabel("", self)
        self._feedback_label.setObjectName("LoginFeedbackLabel")
        self._feedback_label.setWordWrap(True)
        self._feedback_label.setVisible(False)
        layout.addWidget(self._feedback_label)

        # Buttons
        btn_block = QWidget(self)
        btn_block.setObjectName("LoginButtonContainer")
        btn_ly = QHBoxLayout(btn_block)
        btn_ly.setContentsMargins(0, 0, 0, 0)
        btn_ly.setSpacing(SPACE_3)

        self._cancel_btn = QPushButton("Cancel", btn_block)
        self._cancel_btn.setObjectName("LoginCancelButton")
        self._cancel_btn.clicked.connect(self._handle_cancel)

        self._submit_btn = QPushButton("Sign In", btn_block)
        self._submit_btn.setObjectName("LoginSubmitButton")
        self._submit_btn.setDefault(True)
        self._submit_btn.clicked.connect(self._handle_submit)

        btn_ly.addStretch(1)
        btn_ly.addWidget(self._cancel_btn)
        btn_ly.addWidget(self._submit_btn)
        layout.addWidget(btn_block)

        # Set initial focus
        self._username_input.setFocus()

    # -----------------------------------------------------------------------
    # Submission & Authentication
    # -----------------------------------------------------------------------

    def _handle_submit(self) -> None:
        """Validate inputs and initiate asynchronous login via ApiWorker."""
        if self._is_authenticating:
            return

        username = self._username_input.text().strip()
        password = self._password_input.text()

        # Immediate inline input validation
        if not username:
            self._set_feedback("Please enter your username.", is_error=True)
            self._username_input.setFocus()
            return

        if not password:
            self._set_feedback("Please enter your password.", is_error=True)
            self._password_input.setFocus()
            return

        # Clear password input immediately after reading values
        self._password_input.clear()

        # Update UI to authenticating state
        self._is_authenticating = True
        self._set_ui_busy(True)
        self._set_feedback("Authenticating...", is_error=False)

        # Launch worker on QThreadPool
        worker = ApiWorker(self._client.login, username, password)
        worker.signals.result.connect(self._on_login_success)
        worker.signals.error.connect(self._on_login_error)
        worker.signals.finished.connect(self._on_login_finished)

        self._active_worker = worker
        QThreadPool.globalInstance().start(worker)

    def _on_login_success(self, result: object) -> None:
        """Handle successful authentication result from worker."""
        if isinstance(result, TokenInfo):
            self._authenticated_user = result.user
        elif isinstance(result, User):
            self._authenticated_user = result
        self.accept()

    def _on_login_error(self, exc: Exception) -> None:
        """Translate exception into safe, sanitized user-facing feedback."""
        if isinstance(exc, AuthenticationError):
            message = "Invalid username or password. Please try again."
        elif isinstance(exc, AuthorizationError):
            message = "User account is deactivated or unauthorized."
        elif isinstance(exc, (ConnectionTimeoutError, ClientConnectionError)):
            message = (
                "Unable to connect to the authentication service. "
                "Please verify that the server is online."
            )
        elif isinstance(exc, ValidationError):
            message = "Authentication request failed due to invalid data format."
        elif isinstance(exc, OSIRISClientError):
            message = exc.message or "Authentication request failed."
        else:
            message = "An unexpected error occurred during authentication."

        self._set_feedback(message, is_error=True)
        self._password_input.setFocus()

    def _on_login_finished(self) -> None:
        """Re-enable form controls on completion."""
        self._is_authenticating = False
        self._active_worker = None
        self._set_ui_busy(False)

    def _set_ui_busy(self, busy: bool) -> None:
        """Toggle control availability while authentication request is in flight."""
        self._username_input.setEnabled(not busy)
        self._password_input.setEnabled(not busy)
        self._submit_btn.setEnabled(not busy)
        self._cancel_btn.setEnabled(not busy)
        self._submit_btn.setText("Authenticating..." if busy else "Sign In")

    def _set_feedback(self, text: str, is_error: bool = False) -> None:
        """Update inline feedback label with message text and styling."""
        self._feedback_label.setText(text)
        self._feedback_label.setProperty("isError", "true" if is_error else "false")
        self._feedback_label.setVisible(bool(text))
        style = self._feedback_label.style()
        if style is not None:
            style.unpolish(self._feedback_label)
            style.polish(self._feedback_label)

    # -----------------------------------------------------------------------
    # Cancellation & Lifecycle Safeguards
    # -----------------------------------------------------------------------

    def _handle_cancel(self) -> None:
        """Handle Cancel button click."""
        if self._is_authenticating:
            return
        self.reject()

    def reject(self) -> None:
        """Prevent dialog rejection while an authentication request is in flight."""
        if self._is_authenticating:
            return
        super().reject()

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        """Ignore window close events while authentication is in progress."""
        if self._is_authenticating:
            event.ignore()
            return
        super().closeEvent(event)

    # -----------------------------------------------------------------------
    # Public Properties
    # -----------------------------------------------------------------------

    @property
    def authenticated_user(self) -> User | None:
        """Return the User instance acquired upon successful login."""
        return self._authenticated_user

    @property
    def client(self) -> APIClient:
        """Return the injected APIClient instance."""
        return self._client

    @property
    def is_authenticating(self) -> bool:
        """Return True if an authentication request is currently active."""
        return self._is_authenticating


__all__ = [
    "LoginDialog",
]
