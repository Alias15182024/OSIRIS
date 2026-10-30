"""OSIRIS API route modules."""

from backend.api.routes.auth import router as auth_router
from backend.api.routes.detections import router as detections_router
from backend.api.routes.events import router as events_router
from backend.api.routes.files import router as files_router
from backend.api.routes.fim import router as fim_router
from backend.api.routes.processes import router as processes_router
from backend.api.routes.resources import router as resources_router
from backend.api.routes.sessions import router as sessions_router
from backend.api.routes.snapshots import router as snapshots_router
from backend.api.routes.status import router as status_router
from backend.api.routes.timeline import router as timeline_router

__all__ = [
    "auth_router",
    "detections_router",
    "events_router",
    "files_router",
    "fim_router",
    "processes_router",
    "resources_router",
    "sessions_router",
    "snapshots_router",
    "status_router",
    "timeline_router",
]
