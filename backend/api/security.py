"""Security, password hashing, token issuance, and audit-logging utilities for OSIRIS.

Provides foundational cryptographic and audit primitives for Phase 1.5 Backend API:
- PBKDF2-HMAC-SHA256 password hashing and constant-time verification.
- HMAC-SHA256 signed access token issuance and verification (pure Python standard library).
- Application audit-log recording for the ``app_audit_log`` table.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Any
import uuid

from sqlalchemy.orm import Session

from backend.config import settings
from backend.db.models.app_audit_log import AppAuditLog

logger = logging.getLogger("osiris.api.security")

DEFAULT_PBKDF2_ITERATIONS = 100_000
DEFAULT_TOKEN_EXPIRE_MINUTES = 60


class SecurityError(Exception):
    """Base exception for security-related errors."""


class TokenError(SecurityError):
    """Base exception for token validation errors."""


class TokenExpiredError(TokenError):
    """Raised when an access token has expired."""


class TokenInvalidError(TokenError):
    """Raised when an access token is malformed, tampered, or invalid."""


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string without trailing '=' padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _base64url_decode(data: str) -> bytes:
    """Decode base64url string with or without '=' padding."""
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data.encode("ascii"))


def hash_password(
    password: str,
    *,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    salt: bytes | None = None,
) -> str:
    """Hash a plaintext password using PBKDF2-HMAC-SHA256.

    Parameters
    ----------
    password:
        The plaintext password to hash.
    iterations:
        Number of PBKDF2 iterations. Default: 100,000.
    salt:
        Optional 16-byte salt. If not provided, a cryptographically secure
        random salt is generated via ``secrets.token_bytes(16)``.

    Returns
    -------
    str
        Formatted hash string: ``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>``.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string")

    if salt is None:
        salt = secrets.token_bytes(16)
    elif not isinstance(salt, bytes) or len(salt) < 8:
        raise ValueError("Salt must be at least 8 bytes")

    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return f"pbkdf2_sha256${iterations}${salt.hex()}${derived.hex()}"


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored password hash.

    Parameters
    ----------
    plain_password:
        Plaintext password attempt.
    password_hash:
        Stored hash string (e.g. ``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>``).

    Returns
    -------
    bool
        True if the password matches, False otherwise (including malformed hashes).
    """
    if not isinstance(plain_password, str) or not isinstance(password_hash, str):
        return False

    parts = password_hash.split("$")
    if len(parts) != 4:
        return False

    algorithm, iterations_str, salt_hex, hash_hex = parts
    if algorithm != "pbkdf2_sha256":
        return False

    try:
        iterations = int(iterations_str)
        if iterations <= 0:
            return False
        salt = bytes.fromhex(salt_hex)
        expected_derived = bytes.fromhex(hash_hex)
    except (ValueError, TypeError):
        return False

    actual_derived = hashlib.pbkdf2_hmac(
        "sha256", plain_password.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(actual_derived, expected_derived)


def create_access_token(
    user_id: uuid.UUID | str,
    username: str,
    role: str = "viewer",
    *,
    expires_in_minutes: int | float = DEFAULT_TOKEN_EXPIRE_MINUTES,
    expires_delta: timedelta | None = None,
    secret_key: str | None = None,
) -> str:
    """Create an HMAC-SHA256 signed access token.

    Parameters
    ----------
    user_id:
        UUID or string identifying the application user.
    username:
        Username of the application user.
    role:
        Role of the application user (default: "viewer").
    expires_in_minutes:
        Token lifetime in minutes (default: 60).
    expires_delta:
        Optional timedelta overriding ``expires_in_minutes``.
    secret_key:
        Optional secret key. Defaults to ``settings.secret_key``.

    Returns
    -------
    str
        URL-safe signed token string: ``header.payload.signature``.
    """
    key = secret_key if secret_key is not None else settings.secret_key
    if not key:
        raise ValueError("Secret key cannot be empty")

    now = int(time.time())
    if expires_delta is not None:
        exp = int(now + expires_delta.total_seconds())
    else:
        exp = int(now + (expires_in_minutes * 60))

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": now,
        "exp": exp,
    }

    header_b64 = _base64url_encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    payload_b64 = _base64url_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{header_b64}.{payload_b64}"

    sig = hmac.new(
        key.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256
    ).digest()
    sig_b64 = _base64url_encode(sig)

    return f"{signing_input}.{sig_b64}"


def decode_access_token(
    token: str,
    *,
    secret_key: str | None = None,
) -> dict[str, Any]:
    """Decode and validate an HMAC-SHA256 signed access token.

    Parameters
    ----------
    token:
        The token string to decode.
    secret_key:
        Optional secret key. Defaults to ``settings.secret_key``.

    Returns
    -------
    dict[str, Any]
        The decoded token payload.

    Raises
    ------
    TokenInvalidError
        If the token is malformed, has an invalid signature, or is missing required claims.
    TokenExpiredError
        If the token has expired.
    """
    if not isinstance(token, str) or not token:
        raise TokenInvalidError("Token must be a non-empty string")

    parts = token.split(".")
    if len(parts) != 3:
        raise TokenInvalidError(
            f"Malformed token: expected 3 segments, got {len(parts)}"
        )

    header_b64, payload_b64, sig_b64 = parts

    key = secret_key if secret_key is not None else settings.secret_key
    if not key:
        raise TokenInvalidError("Secret key cannot be empty")

    # 1. Verify signature in constant time
    signing_input = f"{header_b64}.{payload_b64}"
    expected_sig = hmac.new(
        key.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256
    ).digest()

    try:
        actual_sig = _base64url_decode(sig_b64)
    except Exception as exc:
        raise TokenInvalidError("Invalid signature encoding") from exc

    if not hmac.compare_digest(actual_sig, expected_sig):
        raise TokenInvalidError("Invalid token signature")

    # 2. Decode header and payload
    try:
        header_raw = _base64url_decode(header_b64)
        header = json.loads(header_raw.decode("utf-8"))
    except Exception as exc:
        raise TokenInvalidError("Invalid header encoding or JSON") from exc

    if not isinstance(header, dict) or header.get("alg") != "HS256":
        raise TokenInvalidError("Unsupported or missing token algorithm")

    try:
        payload_raw = _base64url_decode(payload_b64)
        payload = json.loads(payload_raw.decode("utf-8"))
    except Exception as exc:
        raise TokenInvalidError("Invalid payload encoding or JSON") from exc

    if not isinstance(payload, dict):
        raise TokenInvalidError("Token payload must be a JSON object")

    # 3. Validate required claims
    for claim in ("sub", "username", "exp"):
        if claim not in payload:
            raise TokenInvalidError(f"Missing required claim: {claim}")

    # 4. Check expiration
    exp = payload["exp"]
    if not isinstance(exp, (int, float)):
        raise TokenInvalidError("Claim 'exp' must be a numeric timestamp")

    now = time.time()
    if now >= exp:
        raise TokenExpiredError("Token has expired")

    return payload


def verify_access_token(
    token: str,
    *,
    secret_key: str | None = None,
) -> dict[str, Any] | None:
    """Verify an access token and return its payload, or None if invalid/expired.

    Safe helper that catches ``TokenError`` and returns ``None``.
    """
    try:
        return decode_access_token(token, secret_key=secret_key)
    except TokenError:
        return None


def record_audit_log(
    session: Session,
    action: str,
    *,
    user_id: uuid.UUID | str | None = None,
    target_type: str | None = None,
    target_id: uuid.UUID | str | None = None,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> AppAuditLog:
    """Record an application audit log entry.

    Adds the audit log record to the provided session and flushes to detect
    constraint violations immediately. Does NOT commit the transaction.

    Parameters
    ----------
    session:
        Active SQLAlchemy Session.
    action:
        Name of the application action (e.g., "login", "login_failed", "config_change").
    user_id:
        Optional UUID or UUID string of the application user performing the action.
    target_type:
        Optional type of target entity affected (e.g., "app_user", "host").
    target_id:
        Optional UUID or UUID string of the target entity.
    details:
        Optional structured metadata dictionary for the audit entry.
    ip_address:
        Optional IP address string of the client.

    Returns
    -------
    AppAuditLog
        The flushed audit log ORM model instance.
    """
    resolved_user_id: uuid.UUID | None = None
    if user_id is not None:
        if isinstance(user_id, uuid.UUID):
            resolved_user_id = user_id
        elif isinstance(user_id, str):
            resolved_user_id = uuid.UUID(user_id)
        else:
            raise TypeError(f"user_id must be UUID or str, got {type(user_id)}")

    resolved_target_id: uuid.UUID | None = None
    if target_id is not None:
        if isinstance(target_id, uuid.UUID):
            resolved_target_id = target_id
        elif isinstance(target_id, str):
            resolved_target_id = uuid.UUID(target_id)
        else:
            raise TypeError(f"target_id must be UUID or str, got {type(target_id)}")

    entry = AppAuditLog(
        user_id=resolved_user_id,
        action=action,
        target_type=target_type,
        target_id=resolved_target_id,
        details=details,
        ip_address=ip_address,
    )
    session.add(entry)
    session.flush()
    return entry


__all__ = [
    "DEFAULT_PBKDF2_ITERATIONS",
    "DEFAULT_TOKEN_EXPIRE_MINUTES",
    "SecurityError",
    "TokenError",
    "TokenExpiredError",
    "TokenInvalidError",
    "create_access_token",
    "decode_access_token",
    "hash_password",
    "record_audit_log",
    "verify_access_token",
    "verify_password",
]
