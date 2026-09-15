"""OSIRIS database package.

Re-exports core database components for convenient access.
"""

from backend.db.base import Base
from backend.db.session import SessionLocal, engine, get_session

# Import all models so they are registered with Base.metadata.
# This is required for Alembic autogenerate to discover them.
import backend.db.models  # noqa: F401

__all__ = [
    "Base",
    "SessionLocal",
    "engine",
    "get_session",
]
