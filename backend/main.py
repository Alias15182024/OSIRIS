"""OSIRIS FastAPI application entry point."""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncGenerator

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

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
from backend.config import settings

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"
TEMPLATES_DIR = FRONTEND_DIR / "templates"
INDEX_HTML_PATH = TEMPLATES_DIR / "index.html"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager enforcing startup validation before serving traffic."""
    settings.validate_secret_key()
    yield


app = FastAPI(
    title="OSIRIS",
    description="Operating System Incident Reconstruction and Intelligence System",
    version="0.1.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def enforce_secret_key_middleware(
    request: Request, call_next: Any
) -> Response:
    """Fail fast before serving any HTTP traffic if secret key is invalid.

    Guarantees that even if ASGI lifespan lifecycle events were bypassed
    (e.g., uvicorn --lifespan off or raw ASGI adapters), no HTTP traffic
    can be served in misconfigured production mode.
    """
    settings.validate_secret_key()
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register route modules
app.include_router(auth_router, prefix="/api/auth", tags=["auth"])
app.include_router(detections_router, prefix="/api/detections", tags=["detections"])
app.include_router(events_router, prefix="/api/events", tags=["events"])
app.include_router(processes_router, prefix="/api/processes", tags=["processes"])
app.include_router(resources_router, prefix="/api/resources", tags=["resources"])
app.include_router(files_router, prefix="/api/files", tags=["files"])
app.include_router(fim_router, prefix="/api/fim", tags=["fim"])
app.include_router(incidents_router, prefix="/api/incidents", tags=["incidents"])
app.include_router(sessions_router, prefix="/api/sessions", tags=["sessions"])
app.include_router(snapshots_router, prefix="/api/snapshots", tags=["snapshots"])
app.include_router(timeline_router, prefix="/api/timeline", tags=["timeline"])
app.include_router(workspaces_router, prefix="/api/workspaces", tags=["workspaces"])
app.include_router(graph_router, prefix="/api/graph", tags=["graph"])
app.include_router(search_router, prefix="/api/search", tags=["search"])
app.include_router(annotations_router, prefix="/api/annotations", tags=["annotations"])
app.include_router(status_router, prefix="/api", tags=["status"])


@app.get("/health")
async def health_check() -> dict:
    """Basic health check endpoint."""
    return {"status": "ok", "system": "osiris"}


# Mount static assets
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=FileResponse)
async def serve_index() -> FileResponse:
    """Serve the main OSIRIS SPA dashboard shell."""
    return FileResponse(str(INDEX_HTML_PATH))
