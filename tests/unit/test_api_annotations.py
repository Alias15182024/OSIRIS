"""Unit tests for OSIRIS Evidence Annotations API routes (Phase 2 Milestone 2.7)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Generator
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from backend.api.deps import get_db
from backend.api.security import create_access_token
from backend.db.base import Base
from backend.db.models.app_user import AppUser
from backend.db.models.host import Host
from backend.db.models.process import Process
from backend.main import app


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def api_session() -> Generator[Session, None, None]:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine)

    yield session

    session.close()
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def client(api_session: Session) -> Generator[TestClient, None, None]:
    app.dependency_overrides[get_db] = lambda: api_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def admin_user(api_session: Session) -> AppUser:
    user = AppUser(
        id=uuid.uuid4(),
        username="admin_alice",
        password_hash="fakehash",
        display_name="Alice Admin",
        role="admin",
        is_active=True,
        created_at=utcnow(),
    )
    api_session.add(user)
    api_session.commit()
    return user


@pytest.fixture
def analyst_user(api_session: Session) -> AppUser:
    user = AppUser(
        id=uuid.uuid4(),
        username="analyst_bob",
        password_hash="fakehash",
        display_name="Bob Analyst",
        role="analyst",
        is_active=True,
        created_at=utcnow(),
    )
    api_session.add(user)
    api_session.commit()
    return user


@pytest.fixture
def viewer_user(api_session: Session) -> AppUser:
    user = AppUser(
        id=uuid.uuid4(),
        username="viewer_carol",
        password_hash="fakehash",
        display_name="Carol Viewer",
        role="viewer",
        is_active=True,
        created_at=utcnow(),
    )
    api_session.add(user)
    api_session.commit()
    return user


@pytest.fixture
def admin_headers(admin_user: AppUser) -> dict[str, str]:
    token = create_access_token(user_id=admin_user.id, username=admin_user.username, role=admin_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers(analyst_user: AppUser) -> dict[str, str]:
    token = create_access_token(user_id=analyst_user.id, username=analyst_user.username, role=analyst_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_headers(viewer_user: AppUser) -> dict[str, str]:
    token = create_access_token(user_id=viewer_user.id, username=viewer_user.username, role=viewer_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def evidence_process(api_session: Session) -> Process:
    host = Host(id=uuid.uuid4(), hostname="anno-host", ip_address="10.9.9.9", created_at=utcnow())
    proc = Process(
        id=uuid.uuid4(),
        host_id=host.id,
        pid=7777,
        command="/usr/bin/nc -lvnp 4444",
        started_at=utcnow(),
    )
    api_session.add_all([host, proc])
    api_session.commit()
    return proc


class TestAnnotationsApi:
    def test_unauthenticated_request_rejected(self, client: TestClient) -> None:
        resp = client.get("/api/annotations/tags")
        assert resp.status_code == 401

    def test_viewer_cannot_create_tag(
        self, client: TestClient, viewer_headers: dict[str, str]
    ) -> None:
        payload = {"name": "Malicious", "color": "#ef4444"}
        resp = client.post("/api/annotations/tags", json=payload, headers=viewer_headers)
        assert resp.status_code == 403

    def test_viewer_cannot_update_tag(
        self, client: TestClient, viewer_headers: dict[str, str], analyst_headers: dict[str, str]
    ) -> None:
        create_resp = client.post(
            "/api/annotations/tags",
            json={"name": "tag-viewer-lock", "color": "#10b981"},
            headers=analyst_headers,
        )
        assert create_resp.status_code == 201
        tag_id = create_resp.json()["id"]
        patch_resp = client.patch(
            f"/api/annotations/tags/{tag_id}",
            json={"name": "tampered-tag"},
            headers=viewer_headers,
        )
        assert patch_resp.status_code == 403

    def test_viewer_cannot_update_note(
        self,
        client: TestClient,
        viewer_headers: dict[str, str],
        analyst_headers: dict[str, str],
        evidence_process: Process,
    ) -> None:
        payload = {
            "evidence_type": "process",
            "evidence_id": str(evidence_process.id),
            "annotation_text": "Original analyst note.",
            "host_id": str(evidence_process.host_id),
        }
        create_resp = client.post("/api/annotations/notes", json=payload, headers=analyst_headers)
        assert create_resp.status_code == 201
        note_id = create_resp.json()["id"]
        patch_resp = client.patch(
            f"/api/annotations/notes/{note_id}",
            json={"annotation_text": "Viewer attempted edit."},
            headers=viewer_headers,
        )
        assert patch_resp.status_code == 403


    def test_create_and_list_tags(
        self, client: TestClient, analyst_headers: dict[str, str]
    ) -> None:
        payload = {
            "name": "c2-beacon",
            "description": "Evidence of C2 beaconing activity",
            "color": "#ef4444",
            "category": "malware",
        }
        create_resp = client.post("/api/annotations/tags", json=payload, headers=analyst_headers)
        assert create_resp.status_code == 201
        tag_id = create_resp.json()["id"]

        list_resp = client.get("/api/annotations/tags", headers=analyst_headers)
        assert list_resp.status_code == 200
        tags = list_resp.json()
        assert any(t["id"] == tag_id for t in tags)

    def test_tag_association_and_query(
        self, client: TestClient, analyst_headers: dict[str, str], evidence_process: Process
    ) -> None:
        # Create tag
        create_tag_resp = client.post(
            "/api/annotations/tags",
            json={"name": "suspicious-shell", "color": "#f97316"},
            headers=analyst_headers,
        )
        tag_id = create_tag_resp.json()["id"]

        # Associate tag with process
        assoc_payload = {
            "tag_id": tag_id,
            "evidence_type": "process",
            "evidence_id": str(evidence_process.id),
            "host_id": str(evidence_process.host_id),
        }
        assoc_resp = client.post("/api/annotations/tags/associate", json=assoc_payload, headers=analyst_headers)
        assert assoc_resp.status_code == 201
        assert assoc_resp.json()["tag_name"] == "suspicious-shell"

        # Query annotations for this process
        query_resp = client.get(
            f"/api/annotations?evidence_type=process&evidence_id={evidence_process.id}",
            headers=analyst_headers,
        )
        assert query_resp.status_code == 200
        data = query_resp.json()
        assert len(data["tags"]) == 1
        assert data["tags"][0]["tag_id"] == tag_id

        # Disassociate tag
        disassoc_payload = {
            "tag_id": tag_id,
            "evidence_type": "process",
            "evidence_id": str(evidence_process.id),
        }
        dis_resp = client.post("/api/annotations/tags/disassociate", json=disassoc_payload, headers=analyst_headers)
        assert dis_resp.status_code == 200

        # Verify tag is removed
        recheck_resp = client.get(
            f"/api/annotations?evidence_type=process&evidence_id={evidence_process.id}",
            headers=analyst_headers,
        )
        assert len(recheck_resp.json()["tags"]) == 0

    def test_notes_crud_lifecycle(
        self, client: TestClient, analyst_headers: dict[str, str], evidence_process: Process
    ) -> None:
        # Create note
        payload = {
            "evidence_type": "process",
            "evidence_id": str(evidence_process.id),
            "annotation_text": "Netcat reverse shell detected listening on port 4444.",
            "host_id": str(evidence_process.host_id),
        }
        create_resp = client.post("/api/annotations/notes", json=payload, headers=analyst_headers)
        assert create_resp.status_code == 201
        note_id = create_resp.json()["id"]
        assert create_resp.json()["annotation_text"] == payload["annotation_text"]

        # Fetch annotations
        get_resp = client.get(
            f"/api/annotations?evidence_type=process&evidence_id={evidence_process.id}",
            headers=analyst_headers,
        )
        assert get_resp.status_code == 200
        notes = get_resp.json()["notes"]
        assert any(n["id"] == note_id for n in notes)

        # Delete note
        del_resp = client.delete(f"/api/annotations/notes/{note_id}", headers=analyst_headers)
        assert del_resp.status_code == 204

    def test_update_tag_route(
        self, client: TestClient, analyst_headers: dict[str, str]
    ) -> None:
        # Create tag
        create_resp = client.post(
            "/api/annotations/tags",
            json={"name": "c2-beacon-v1", "color": "#10b981", "category": "c2"},
            headers=analyst_headers,
        )
        assert create_resp.status_code == 201
        tag_id = create_resp.json()["id"]

        # Update tag
        update_resp = client.patch(
            f"/api/annotations/tags/{tag_id}",
            json={"name": "c2-beacon-v2", "color": "#ef4444", "description": "Updated C2"},
            headers=analyst_headers,
        )
        assert update_resp.status_code == 200
        data = update_resp.json()
        assert data["name"] == "c2-beacon-v2"
        assert data["color"] == "#ef4444"
        assert data["description"] == "Updated C2"

        # Update nonexistent tag
        bad_resp = client.patch(
            f"/api/annotations/tags/{uuid.uuid4()}",
            json={"name": "nonexistent"},
            headers=analyst_headers,
        )
        assert bad_resp.status_code == 404

    def test_update_note_route(
        self, client: TestClient, analyst_headers: dict[str, str], evidence_process: Process
    ) -> None:
        # Create note
        payload = {
            "evidence_type": "process",
            "evidence_id": str(evidence_process.id),
            "annotation_text": "First draft of analyst finding.",
            "host_id": str(evidence_process.host_id),
        }
        create_resp = client.post("/api/annotations/notes", json=payload, headers=analyst_headers)
        assert create_resp.status_code == 201
        note_id = create_resp.json()["id"]

        # Update note
        patch_resp = client.patch(
            f"/api/annotations/notes/{note_id}",
            json={"annotation_text": "Revised draft with IOC corroboration."},
            headers=analyst_headers,
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["annotation_text"] == "Revised draft with IOC corroboration."

        # Nonexistent note
        bad_resp = client.patch(
            f"/api/annotations/notes/{uuid.uuid4()}",
            json={"annotation_text": "Nonexistent"},
            headers=analyst_headers,
        )
        assert bad_resp.status_code == 404

