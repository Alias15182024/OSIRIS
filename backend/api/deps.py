"""FastAPI dependencies for OSIRIS Phase 1.5 Backend API.

Provides:
- ``get_db``: SQLAlchemy database session lifecycle management.
- ``get_current_user``: Bearer token authentication and active AppUser resolution.
"""

from __future__ import annotations

from typing import Generator, Optional
import uuid

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from backend.api.security import (
    TokenError,
    TokenExpiredError,
    decode_access_token,
)
from backend.db.models.app_user import AppUser
from backend.db.session import SessionLocal

bearer_scheme = HTTPBearer(auto_error=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a SQLAlchemy database session.

    The session is closed when the request finishes. Transaction commit
    and rollback remain the responsibility of the caller/route.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> AppUser:
    """FastAPI dependency to extract and authenticate the current application user.

    Validates the bearer token from the Authorization header, decodes subject identity,
    and retrieves the corresponding active ``AppUser`` from the database.

    Raises
    ------
    HTTPException(401)
        If the Authorization header is missing, malformed, invalid, or expired,
        or if the referenced user does not exist.
    HTTPException(403)
        If the user account is deactivated (is_active is False).
    """
    if auth is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if auth.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme; Bearer required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth.credentials
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(token)
    except TokenExpiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or malformed token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    sub = payload.get("sub")
    try:
        user_id = uuid.UUID(sub)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid subject claim in token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = db.get(AppUser, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account",
        )

    return user


__all__ = [
    "bearer_scheme",
    "get_current_user",
    "get_db",
]
