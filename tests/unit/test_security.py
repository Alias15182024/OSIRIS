"""Unit tests for OSIRIS Phase 1.5 security utilities.

Tests:
- Password hashing (PBKDF2-HMAC-SHA256) and constant-time verification.
- Token issuance, HMAC-SHA256 signing, tampering detection, and expiration.
- Application audit-log recorder with SQLAlchemy session lifecycle.
"""

from __future__ import annotations

import time
import uuid
from datetime import timedelta

import pytest
from sqlalchemy.orm import Session

from backend.api.security import (
    DEFAULT_PBKDF2_ITERATIONS,
    TokenError,
    TokenExpiredError,
    TokenInvalidError,
    create_access_token,
    decode_access_token,
    hash_password,
    record_audit_log,
    verify_access_token,
    verify_password,
)
from backend.db.models.app_audit_log import AppAuditLog
from backend.db.models.app_user import AppUser


class TestPasswordSecurity:
    """Tests for PBKDF2-HMAC-SHA256 password hashing and verification."""

    def test_password_hash_different_from_plaintext(self) -> None:
        raw_password = "SuperSecretPassword123!"
        hashed = hash_password(raw_password)

        assert hashed != raw_password
        assert hashed.startswith("pbkdf2_sha256$")
        assert len(hashed.split("$")) == 4

    def test_password_verification_succeeds_for_correct_password(self) -> None:
        raw_password = "CorrectHorseBatteryStaple"
        hashed = hash_password(raw_password)

        assert verify_password(raw_password, hashed) is True

    def test_password_verification_fails_for_incorrect_password(self) -> None:
        raw_password = "CorrectPassword"
        hashed = hash_password(raw_password)

        assert verify_password("WrongPassword", hashed) is False
        assert verify_password("correctpassword", hashed) is False
        assert verify_password("", hashed) is False

    def test_random_salt_generates_distinct_hashes_for_same_password(self) -> None:
        raw_password = "IdenticalPassword"
        hash_1 = hash_password(raw_password)
        hash_2 = hash_password(raw_password)

        assert hash_1 != hash_2
        assert verify_password(raw_password, hash_1) is True
        assert verify_password(raw_password, hash_2) is True

    def test_custom_iterations_and_salt(self) -> None:
        raw_password = "CustomIterationTest"
        salt = b"0123456789abcdef"
        hashed = hash_password(raw_password, iterations=50_000, salt=salt)

        parts = hashed.split("$")
        assert parts[1] == "50000"
        assert parts[2] == salt.hex()
        assert verify_password(raw_password, hashed) is True

    def test_malformed_and_unsupported_hashes_fail_safely(self) -> None:
        raw_password = "test_password"

        # Not enough parts
        assert verify_password(raw_password, "invalid_hash_string") is False
        assert verify_password(raw_password, "pbkdf2_sha256$1000$abcd") is False

        # Unsupported algorithm
        assert verify_password(raw_password, "bcrypt$1000$abcd$ef01") is False
        assert verify_password(raw_password, "$2b$12$TEST_HASH_NOT_REAL") is False

        # Non-integer iterations
        assert verify_password(raw_password, "pbkdf2_sha256$not_an_int$abcd$ef01") is False

        # Negative iterations
        assert verify_password(raw_password, "pbkdf2_sha256$-100$abcd$ef01") is False

        # Non-hex salt or hash
        assert verify_password(raw_password, "pbkdf2_sha256$1000$not_hex!$ef01") is False
        assert verify_password(raw_password, "pbkdf2_sha256$1000$abcd$not_hex!") is False

        # Empty strings and non-string types
        assert verify_password("", "") is False
        assert verify_password(None, "pbkdf2_sha256$1000$abcd$ef01") is False  # type: ignore[arg-type]
        assert verify_password("pw", None) is False  # type: ignore[arg-type]

    def test_invalid_hash_inputs_raise_appropriate_exceptions(self) -> None:
        with pytest.raises(TypeError):
            hash_password(12345)  # type: ignore[arg-type]

        with pytest.raises(ValueError):
            hash_password("password", salt=b"short")  # Salt < 8 bytes


class TestTokenSecurity:
    """Tests for HMAC-SHA256 signed access token issuance and verification."""

    def test_token_issued_and_verified_successfully(self) -> None:
        user_id = uuid.uuid4()
        username = "investigator_alice"
        role = "analyst"

        token = create_access_token(
            user_id=user_id,
            username=username,
            role=role,
            expires_in_minutes=30,
        )

        assert isinstance(token, str)
        assert len(token.split(".")) == 3

        payload = verify_access_token(token)
        assert payload is not None
        assert payload["sub"] == str(user_id)
        assert payload["username"] == username
        assert payload["role"] == role
        assert "iat" in payload
        assert "exp" in payload
        assert payload["exp"] > payload["iat"]

    def test_decode_access_token_returns_payload(self) -> None:
        user_id = uuid.uuid4()
        token = create_access_token(user_id=user_id, username="admin", role="admin")

        payload = decode_access_token(token)
        assert payload["sub"] == str(user_id)
        assert payload["username"] == "admin"
        assert payload["role"] == "admin"

    def test_modified_payload_fails_verification(self) -> None:
        user_id = uuid.uuid4()
        token = create_access_token(user_id=user_id, username="alice", role="viewer")

        parts = token.split(".")
        # Tamper with the payload (middle segment)
        tampered_token = f"{parts[0]}.eyJhZG1pbiI6dHJ1ZX0.{parts[2]}"

        assert verify_access_token(tampered_token) is None
        with pytest.raises(TokenInvalidError, match="Invalid token signature"):
            decode_access_token(tampered_token)

    def test_modified_signature_fails_verification(self) -> None:
        user_id = uuid.uuid4()
        token = create_access_token(user_id=user_id, username="alice")

        parts = token.split(".")
        # Change the first character of the signature to ensure actual encoded bytes are altered
        corrupt_sig = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        tampered_token = f"{parts[0]}.{parts[1]}.{corrupt_sig}"

        assert verify_access_token(tampered_token) is None
        with pytest.raises(TokenInvalidError, match="Invalid token signature"):
            decode_access_token(tampered_token)

    def test_token_signed_with_wrong_secret_fails_verification(self) -> None:
        token = create_access_token(
            user_id=uuid.uuid4(),
            username="bob",
            secret_key="secret-key-alpha",
        )

        # Verification with different secret
        assert verify_access_token(token, secret_key="secret-key-beta") is None
        with pytest.raises(TokenInvalidError, match="Invalid token signature"):
            decode_access_token(token, secret_key="secret-key-beta")

    def test_expired_token_fails_verification(self) -> None:
        # Create a token that expired 10 seconds ago
        token = create_access_token(
            user_id=uuid.uuid4(),
            username="charlie",
            expires_delta=timedelta(seconds=-10),
        )

        assert verify_access_token(token) is None
        with pytest.raises(TokenExpiredError, match="Token has expired"):
            decode_access_token(token)

    def test_token_with_negative_minutes_fails_verification(self) -> None:
        token = create_access_token(
            user_id=uuid.uuid4(),
            username="charlie",
            expires_in_minutes=-5,
        )

        assert verify_access_token(token) is None
        with pytest.raises(TokenExpiredError, match="Token has expired"):
            decode_access_token(token)

    def test_malformed_tokens_fail_safely(self) -> None:
        assert verify_access_token("") is None
        assert verify_access_token("only-one-segment") is None
        assert verify_access_token("segment1.segment2") is None
        assert verify_access_token("a.b.c.d") is None
        assert verify_access_token("invalid_b64.invalid_b64.invalid_b64") is None

        with pytest.raises(TokenInvalidError):
            decode_access_token("not-a-token")


class TestAuditLogRecorder:
    """Tests for application audit-log helper with database session."""

    def test_record_audit_log_with_all_fields(
        self,
        db_session: Session,
        sample_app_user: AppUser,
    ) -> None:
        action = "user_login"
        target_id = uuid.uuid4()
        details = {"method": "password", "user_agent": "Mozilla/5.0"}
        ip_addr = "192.168.1.50"

        entry = record_audit_log(
            session=db_session,
            action=action,
            user_id=sample_app_user.id,
            target_type="session",
            target_id=target_id,
            details=details,
            ip_address=ip_addr,
        )

        assert isinstance(entry, AppAuditLog)
        assert entry.id is not None
        assert entry.action == action
        assert entry.user_id == sample_app_user.id
        assert entry.target_type == "session"
        assert entry.target_id == target_id
        assert entry.details == details
        assert entry.ip_address == ip_addr
        assert entry.created_at is not None

        # Verify entry is queryable in the active transaction
        queried = db_session.get(AppAuditLog, entry.id)
        assert queried is not None
        assert queried.action == action
        assert queried.user is not None
        assert queried.user.username == sample_app_user.username

    def test_record_audit_log_without_user(self, db_session: Session) -> None:
        # Anonymous action (e.g. failed login attempt with unknown username)
        entry = record_audit_log(
            session=db_session,
            action="login_failed",
            target_type="app_user",
            details={"attempted_username": "ghost_user"},
            ip_address="10.0.0.99",
        )

        assert entry.id is not None
        assert entry.user_id is None
        assert entry.action == "login_failed"

        queried = db_session.get(AppAuditLog, entry.id)
        assert queried is not None
        assert queried.user_id is None

    def test_record_audit_log_string_uuids_converted(
        self,
        db_session: Session,
        sample_app_user: AppUser,
    ) -> None:
        user_id_str = str(sample_app_user.id)
        target_id = uuid.uuid4()
        target_id_str = str(target_id)

        entry = record_audit_log(
            session=db_session,
            action="config_update",
            user_id=user_id_str,
            target_id=target_id_str,
        )

        assert entry.user_id == sample_app_user.id
        assert entry.target_id == target_id

    def test_record_audit_log_invalid_uuid_raises_type_error(
        self,
        db_session: Session,
    ) -> None:
        with pytest.raises(TypeError):
            record_audit_log(session=db_session, action="test", user_id=12345)  # type: ignore[arg-type]

        with pytest.raises(TypeError):
            record_audit_log(session=db_session, action="test", target_id=12345)  # type: ignore[arg-type]

    def test_record_audit_log_flushes_without_committing(
        self,
        db_session: Session,
    ) -> None:
        # The helper calls session.flush() but not session.commit()
        entry = record_audit_log(
            session=db_session,
            action="pre_commit_action",
        )

        assert entry.id is not None
        # Transaction is still active and managed by caller
        assert db_session.is_active is True
