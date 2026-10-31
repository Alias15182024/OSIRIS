from backend.api.routes.annotations import router as annotations_router
from backend.api.routes.auth import router as auth_router
from backend.api.routes.detections import router as detections_router
from backend.api.routes.events import router as events_router
from backend.api.routes.files import router as files_router
from backend.api.routes.fim import router as fim_router
from backend.api.routes.graph import router as graph_router
from backend.api.routes.incidents import router as incidents_router
from backend.api.routes.processes import router as processes_router
from backend.api.routes.resources import router as resources_router
from backend.api.routes.search import router as search_router
from backend.api.routes.sessions import router as sessions_router
from backend.api.routes.snapshots import router as snapshots_router
from backend.api.routes.status import router as status_router
from backend.api.routes.timeline import router as timeline_router
from backend.api.routes.workspaces import router as workspaces_router

__all__ = [
    "annotations_router",
    "auth_router",
    "detections_router",
    "events_router",
    "files_router",
    "fim_router",
    "graph_router",
    "incidents_router",
    "processes_router",
    "resources_router",
    "search_router",
    "sessions_router",
    "snapshots_router",
    "status_router",
    "timeline_router",
    "workspaces_router",
]
