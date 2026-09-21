"""OSIRIS FastAPI application entry point."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api.routes.auth import router as auth_router
from backend.api.routes.events import router as events_router
from backend.api.routes.files import router as files_router
from backend.api.routes.processes import router as processes_router
from backend.api.routes.resources import router as resources_router
from backend.api.routes.status import router as status_router

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"
TEMPLATES_DIR = FRONTEND_DIR / "templates"
INDEX_HTML_PATH = TEMPLATES_DIR / "index.html"

app = FastAPI(
    title="OSIRIS",
    description="Operating System Incident Reconstruction and Intelligence System",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register route modules
app.include_router(auth_router, prefix="/api/auth", tags=["auth"])
app.include_router(events_router, prefix="/api/events", tags=["events"])
app.include_router(processes_router, prefix="/api/processes", tags=["processes"])
app.include_router(resources_router, prefix="/api/resources", tags=["resources"])
app.include_router(files_router, prefix="/api/files", tags=["files"])
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
