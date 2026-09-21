"""OSIRIS API route modules."""

from backend.api.routes.auth import router as auth_router
from backend.api.routes.events import router as events_router
from backend.api.routes.files import router as files_router
from backend.api.routes.processes import router as processes_router
from backend.api.routes.resources import router as resources_router
from backend.api.routes.status import router as status_router

__all__ = [
    "auth_router",
    "events_router",
    "files_router",
    "processes_router",
    "resources_router",
    "status_router",
]
