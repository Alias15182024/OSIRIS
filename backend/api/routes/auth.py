"""Authentication route handlers for OSIRIS Phase 1.5 Backend API."""

from __future__ import annotations

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

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
def login(
    req: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate an application user and return a signed access token.

    Verifies submitted credentials against the stored password hash,
    records a successful login action to the application audit log,
    and returns a bearer token and user profile.
    """
    stmt = select(AppUser).where(AppUser.username == req.username)
    user = db.execute(stmt).scalar_one_or_none()

    if user is None or not verify_password(req.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account",
        )

    token = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
    )

    ip_address = request.client.host if request.client else None
    record_audit_log(
        session=db,
        action="login",
        user_id=user.id,
        target_type="app_user",
        target_id=user.id,
        ip_address=ip_address,
    )
    db.commit()

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
