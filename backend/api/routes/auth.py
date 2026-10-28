"""Authentication route handlers for OSIRIS Phase 1.5 Backend API."""

from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user, get_db
from backend.api.schemas.auth import LoginRequest, TokenResponse, UserResponse
from backend.api.security import (
    create_access_token,
    record_audit_log,
    verify_password,
)
from backend.db.models.app_user import AppUser

logger = logging.getLogger("osiris.api.auth")

router = APIRouter()


def _extract_client_ip(request: Request) -> str | None:
    """Extract client IP address from the direct client connection.

    In Phase 1, OSIRIS does not configure trusted upstream proxy CIDRs or proxy
    headers middleware. To prevent client IP spoofing via attacker-controlled
    forwarding headers (such as X-Forwarded-For), the direct connection address
    (`request.client.host`) is used as the authoritative client IP.
    """
    if request.client and request.client.host:
        cleaned = request.client.host.strip()
        if cleaned:
            return cleaned[:45]
    return None


def _record_audit_event(
    db: Session,
    action: str,
    target_type: str,
    target_id: UUID | None,
    user_id: UUID | None,
    details: dict | None,
    ip_address: str | None,
) -> None:
    """Record an audit log entry and commit immediately within a guarded transaction.

    Rolls back cleanly and raises HTTP 500 without leaking database errors or credentials
    if audit log persistence fails.
    """
    try:
        record_audit_log(
            session=db,
            action=action,
            user_id=user_id,
            target_type=target_type,
            target_id=target_id,
            details=details,
            ip_address=ip_address,
        )
        db.commit()
    except Exception as exc:
        logger.error(
            "Failed to persist %s audit log: [%s]",
            action,
            exc.__class__.__name__,
        )
        try:
            db.rollback()
        except Exception as rb_exc:
            logger.error(
                "Database rollback failed after %s audit error: [%s]",
                action,
                rb_exc.__class__.__name__,
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service unavailable",
        ) from None


@router.post("/login", response_model=TokenResponse)
def login(
    req: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate an application user and return a signed access token.

    Verifies submitted credentials against the stored password hash,
    records login actions (successful or failed) to the application audit log,
    and returns a bearer token and user profile on success.
    """
    if "\x00" in req.username:
        user = None
    else:
        try:
            stmt = select(AppUser).where(AppUser.username == req.username)
            user = db.execute(stmt).scalar_one_or_none()
        except Exception as exc:
            logger.error(
                "Database query error during login user lookup: [%s]",
                exc.__class__.__name__,
            )
            try:
                db.rollback()
            except Exception as rb_exc:
                logger.error(
                    "Database rollback failed after user lookup error: [%s]",
                    rb_exc.__class__.__name__,
                )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication service unavailable",
            ) from None

    cleaned_username = req.username.replace("\x00", "")[:150]
    ip_address = _extract_client_ip(request)

    if user is None or not verify_password(req.password, user.password_hash):
        target_id = user.id if user is not None else None
        _record_audit_event(
            db=db,
            action="login_failed",
            target_type="app_user",
            target_id=target_id,
            user_id=None,
            details={"attempted_username": cleaned_username},
            ip_address=ip_address,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        _record_audit_event(
            db=db,
            action="login_failed",
            target_type="app_user",
            target_id=user.id,
            user_id=None,
            details={"attempted_username": cleaned_username},
            ip_address=ip_address,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account",
        )

    token = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
    )

    _record_audit_event(
        db=db,
        action="login",
        target_type="app_user",
        target_id=user.id,
        user_id=user.id,
        details=None,
        ip_address=ip_address,
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@router.get("/me", response_model=UserResponse)
def get_me(
    current_user: AppUser = Depends(get_current_user),
) -> UserResponse:
    """Retrieve profile information for the currently authenticated user."""
    return UserResponse.model_validate(current_user)
