"""OSIRIS FastAPI application entry point."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routes.auth import router as auth_router
from backend.api.routes.events import router as events_router
from backend.api.routes.files import router as files_router
from backend.api.routes.processes import router as processes_router
from backend.api.routes.resources import router as resources_router
from backend.api.routes.status import router as status_router

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
