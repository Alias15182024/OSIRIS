"""Authentication Pydantic schemas for OSIRIS Phase 1.5 Backend API."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class LoginRequest(BaseModel):
    """User credentials submitted for authentication."""

    username: str
    password: str


class UserResponse(BaseModel):
    """Application user information returned to clients."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    username: str
    display_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime


class TokenResponse(BaseModel):
    """Access token and user profile issued upon successful login."""

    access_token: str
    token_type: str = "bearer"
    user: UserResponse
