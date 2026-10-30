"""Forensic incident report generator for OSIRIS."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from backend.db.models.detection import Detection
from backend.db.models.event import Event
from backend.db.models.file import File
from backend.db.models.fim_deviation import FimDeviation
from backend.db.models.incident import Incident
from backend.db.models.incident_event import IncidentEvent
from backend.db.models.incident_evidence import IncidentEvidence
from backend.db.models.incident_history import IncidentHistory
from backend.db.models.process import Process
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession
from backend.services.incidents.models import IncidentNotFoundError


class ReportGenerator:
    """Generates comprehensive forensic incident reports in structured JSON and Markdown."""

    def generate_report(self, db: Session, incident_id: uuid.UUID) -> dict[str, Any]:
        """Generate structured incident investigation report data.

        Read-only operation: guaranteed never to modify database records.
        """
        stmt = (
            select(Incident)
            .execution_options(populate_existing=True)
            .options(
                joinedload(Incident.host),
                joinedload(Incident.created_by),
                joinedload(Incident.assigned_to),
                joinedload(Incident.evidence),
                joinedload(Incident.events).joinedload(IncidentEvent.event),
                joinedload(Incident.history).joinedload(IncidentHistory.user),
            )
            .where(Incident.id == incident_id)
        )
        incident = db.execute(stmt).unique().scalar_one_or_none()
        if incident is None:
            raise IncidentNotFoundError(f"Incident '{incident_id}' not found.")

        # Extract linked evidence items by type
        detections: list[dict[str, Any]] = []
        sessions: list[dict[str, Any]] = []
        fim_deviations: list[dict[str, Any]] = []
        snapshots: list[dict[str, Any]] = []
        evidence_inventory: list[dict[str, Any]] = []

        timeline_entries: list[dict[str, Any]] = []

        for ev in incident.evidence:
            source_exists = True
            source_detail: dict[str, Any] = {}

            if ev.evidence_type == "detection":
                det = db.get(Detection, ev.detection_id) if ev.detection_id else None
                if det is None:
                    try:
                        det = db.get(Detection, uuid.UUID(ev.source_id))
                    except Exception:
                        pass
                if det:
                    source_detail = {
                        "detection_id": str(det.id),
                        "rule_id": str(det.rule_id),
                        "title": det.title,
                        "severity": det.severity,
                        "category": det.category,
                        "timestamp": det.timestamp.isoformat() if det.timestamp else None,
                        "dedup_hash": det.dedup_hash,
                        "matched_conditions": det.matched_conditions,
                    }
                else:
                    source_exists = False
                    source_detail = ev.provenance or {}
                detections.append({
                    "evidence_id": str(ev.id),
                    "source_id": ev.source_id,
                    "title": ev.title,
                    "status": "available" if source_exists else "missing_source",
                    "details": source_detail,
                })

            elif ev.evidence_type == "fim_deviation":
                dev = db.get(FimDeviation, ev.fim_deviation_id) if ev.fim_deviation_id else None
                if dev is None:
                    try:
                        dev = db.get(FimDeviation, uuid.UUID(ev.source_id))
                    except Exception:
                        pass
                if dev:
                    source_detail = {
                        "deviation_id": str(dev.id),
                        "file_path": dev.file_path,
                        "deviation_type": dev.deviation_type,
                        "severity": dev.severity,
                        "is_content_modified": dev.is_content_modified,
                        "is_metadata_modified": dev.is_metadata_modified,
                        "expected_values": dev.expected_values,
                        "observed_values": dev.observed_values,
                        "detected_at": dev.detected_at.isoformat() if dev.detected_at else None,
                    }
                else:
                    source_exists = False
                    source_detail = ev.provenance or {}
                fim_deviations.append({
                    "evidence_id": str(ev.id),
                    "source_id": ev.source_id,
                    "title": ev.title,
                    "status": "available" if source_exists else "missing_source",
                    "details": source_detail,
                })

            elif ev.evidence_type == "session":
                sess = db.get(UserSession, ev.session_id) if ev.session_id else None
                if sess is None:
                    try:
                        sess = db.get(UserSession, uuid.UUID(ev.source_id))
                    except Exception:
                        pass
                if sess:
                    source_detail = {
                        "session_id": str(sess.id),
                        "terminal": sess.terminal,
                        "remote_host": sess.remote_host,
                        "session_type": sess.session_type,
                        "started_at": sess.started_at.isoformat() if sess.started_at else None,
                        "ended_at": sess.ended_at.isoformat() if sess.ended_at else None,
                    }
                else:
                    source_exists = False
                    source_detail = ev.provenance or {}
                sessions.append({
                    "evidence_id": str(ev.id),
                    "source_id": ev.source_id,
                    "title": ev.title,
                    "status": "available" if source_exists else "missing_source",
                    "details": source_detail,
                })

            elif ev.evidence_type == "snapshot":
                snap = db.get(Snapshot, ev.snapshot_id) if ev.snapshot_id else None
                if snap is None:
                    try:
                        snap = db.get(Snapshot, uuid.UUID(ev.source_id))
                    except Exception:
                        pass
                if snap:
                    source_detail = {
                        "snapshot_id": str(snap.id),
                        "snapshot_type": snap.snapshot_type,
                        "timestamp": snap.timestamp.isoformat() if snap.timestamp else None,
                    }
                else:
                    source_exists = False
                    source_detail = ev.provenance or {}
                snapshots.append({
                    "evidence_id": str(ev.id),
                    "source_id": ev.source_id,
                    "title": ev.title,
                    "status": "available" if source_exists else "missing_source",
                    "details": source_detail,
                })

            elif ev.evidence_type == "process":
                proc = db.get(Process, ev.process_id) if ev.process_id else None
                if proc is None:
                    try:
                        proc = db.get(Process, uuid.UUID(ev.source_id))
                    except Exception:
                        pass
                if proc is None:
                    source_exists = False

            elif ev.evidence_type == "file":
                f_rec = db.get(File, ev.file_id) if ev.file_id else None
                if f_rec is None:
                    try:
                        f_rec = db.get(File, uuid.UUID(ev.source_id))
                    except Exception:
                        pass
                if f_rec is None:
                    source_exists = False

            elif ev.evidence_type == "event":
                evt_rec = db.get(Event, ev.event_id) if ev.event_id else None
                if evt_rec is None:
                    try:
                        evt_rec = db.get(Event, uuid.UUID(ev.source_id))
                    except Exception:
                        pass
                if evt_rec is None:
                    source_exists = False

            evidence_inventory.append({
                "id": str(ev.id),
                "evidence_type": ev.evidence_type,
                "source_id": ev.source_id,
                "title": ev.title,
                "description": ev.description,
                "provenance": ev.provenance,
                "created_at": ev.created_at.isoformat() if ev.created_at else None,
                "source_available": source_exists,
            })

            # Add to chronological timeline
            ev_ts = ev.created_at
            if isinstance(ev.provenance, dict) and ev.provenance.get("timestamp"):
                try:
                    ev_ts = datetime.fromisoformat(ev.provenance["timestamp"])
                except Exception:
                    pass
            timeline_entries.append({
                "timestamp": ev_ts.isoformat() if ev_ts else None,
                "category": f"Evidence ({ev.evidence_type})",
                "summary": ev.title,
                "details": ev.description or "Evidence attached to incident",
                "nature": "observed_fact",
            })

        # Add linked events to timeline and structured events list
        linked_events: list[dict[str, Any]] = []
        for inc_evt in incident.events:
            evt = inc_evt.event
            linked_events.append({
                "id": str(inc_evt.id),
                "event_id": str(inc_evt.event_id),
                "relationship": inc_evt.relationship_role,
                "association_timestamp": inc_evt.association_timestamp.isoformat() if inc_evt.association_timestamp else None,
                "investigation_notes": inc_evt.investigation_notes,
                "source_available": evt is not None,
                "event_type": evt.event_type if evt else None,
                "action": evt.action if evt else None,
                "source": evt.source if evt else None,
                "severity": evt.severity if evt else None,
            })
            if evt:
                timeline_entries.append({
                    "timestamp": evt.timestamp.isoformat() if evt.timestamp else None,
                    "category": f"Event ({evt.event_type})",
                    "summary": f"{evt.event_type} [{evt.action}] - {evt.source}",
                    "details": f"PID: {evt.pid}, User: {evt.username}, Command: {evt.command or 'N/A'}",
                    "nature": "observed_fact",
                })
            else:
                timeline_entries.append({
                    "timestamp": inc_evt.association_timestamp.isoformat() if inc_evt.association_timestamp else None,
                    "category": "Event (missing source)",
                    "summary": f"Linked Event ID {inc_evt.event_id}",
                    "details": inc_evt.investigation_notes or "Source event record not found in database",
                    "nature": "observed_fact",
                })

        # Add history & analyst notes to timeline
        investigation_notes: list[dict[str, Any]] = []
        change_history: list[dict[str, Any]] = []

        for h in incident.history:
            user_name = h.user.username if h.user else "System"
            change_history.append({
                "id": str(h.id),
                "change_type": h.change_type,
                "from_status": h.from_status,
                "to_status": h.to_status,
                "from_severity": h.from_severity,
                "to_severity": h.to_severity,
                "user": user_name,
                "notes": h.notes,
                "timestamp": h.created_at.isoformat() if h.created_at else None,
            })

            if h.change_type == "note_added" or (h.notes and h.change_type in ("status_change", "incident_updated")):
                investigation_notes.append({
                    "id": str(h.id),
                    "user": user_name,
                    "notes": h.notes,
                    "timestamp": h.created_at.isoformat() if h.created_at else None,
                })

            timeline_entries.append({
                "timestamp": h.created_at.isoformat() if h.created_at else None,
                "category": f"Lifecycle ({h.change_type})",
                "summary": f"{h.change_type.replace('_', ' ').title()} by {user_name}",
                "details": h.notes or f"Transition to {h.to_status or h.to_severity}",
                "nature": "analyst_interpretation" if h.user_id else "system_lifecycle",
            })

        # Sort timeline chronologically
        timeline_entries.sort(key=lambda t: t.get("timestamp") or "")

        host_info = None
        if incident.host:
            host_info = {
                "id": str(incident.host.id),
                "hostname": incident.host.hostname,
                "ip_address": incident.host.ip_address,
                "os_info": incident.host.os_info,
            }

        assigned_user = None
        if incident.assigned_to:
            assigned_user = {
                "id": str(incident.assigned_to.id),
                "username": incident.assigned_to.username,
                "display_name": incident.assigned_to.display_name,
                "role": incident.assigned_to.role,
            }

        creator_user = None
        if incident.created_by:
            creator_user = {
                "id": str(incident.created_by.id),
                "username": incident.created_by.username,
                "display_name": incident.created_by.display_name,
            }

        return {
            "incident": {
                "id": str(incident.id),
                "title": incident.title,
                "description": incident.description,
                "severity": incident.severity,
                "status": incident.status,
                "category": incident.category,
                "created_at": incident.created_at.isoformat() if incident.created_at else None,
                "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
                "first_observed_at": incident.first_observed_at.isoformat() if incident.first_observed_at else None,
                "last_observed_at": incident.last_observed_at.isoformat() if incident.last_observed_at else None,
                "host": host_info,
                "assigned_to": assigned_user,
                "created_by": creator_user,
            },
            "lifecycle": {
                "status": incident.status,
                "contained_at": incident.contained_at.isoformat() if incident.contained_at else None,
                "containment_summary": incident.containment_summary,
                "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
                "resolution_summary": incident.resolution_summary,
                "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
                "closure_summary": incident.closure_summary,
            },
            "detections": detections,
            "sessions": sessions,
            "fim_deviations": fim_deviations,
            "snapshots": snapshots,
            "events": linked_events,
            "evidence_inventory": evidence_inventory,
            "timeline": timeline_entries,
            "investigation_notes": investigation_notes,
            "change_history": change_history,
        }

    def export_markdown(self, report: dict[str, Any]) -> str:
        """Format structured incident report data into a standardized forensic Markdown document."""
        inc = report["incident"]
        lifecycle = report["lifecycle"]
        host = inc.get("host") or {}
        assigned = inc.get("assigned_to") or {}
        creator = inc.get("created_by") or {}

        md = []
        md.append(f"# OSIRIS Forensic Incident Report: {inc['title']}")
        md.append("")
        md.append(f"**Incident ID:** `{inc['id']}`  ")
        md.append(f"**Severity:** `{inc['severity'].upper()}`  ")
        md.append(f"**Status:** `{inc['status'].upper()}`  ")
        md.append(f"**Category:** `{inc['category']}`  ")
        md.append(f"**Monitored Host:** `{host.get('hostname', 'N/A')}` ({host.get('ip_address', 'N/A')})  ")
        md.append(f"**Assigned Analyst:** {assigned.get('display_name') or assigned.get('username') or 'Unassigned'}  ")
        md.append(f"**Report Generated:** {datetime.now(timezone.utc).isoformat()} UTC  ")
        md.append("")
        md.append("---")
        md.append("")

        # 1. Executive Summary
        md.append("## 1. Executive Summary")
        md.append(f"{inc.get('description') or 'No narrative description provided.'}")
        md.append("")
        md.append("| Metric | Value |")
        md.append("| --- | --- |")
        md.append(f"| First Observed | {inc.get('first_observed_at') or 'N/A'} |")
        md.append(f"| Last Observed | {inc.get('last_observed_at') or 'N/A'} |")
        md.append(f"| Contained At | {lifecycle.get('contained_at') or 'Not Contained'} |")
        md.append(f"| Resolved At | {lifecycle.get('resolved_at') or 'Not Resolved'} |")
        md.append(f"| Closed At | {lifecycle.get('closed_at') or 'Open'} |")
        md.append(f"| Total Evidence Items | {len(report.get('evidence_inventory', []))} |")
        md.append(f"| Related Detections | {len(report.get('detections', []))} |")
        md.append(f"| Related FIM Deviations | {len(report.get('fim_deviations', []))} |")
        md.append(f"| Linked Forensic Events | {len(report.get('events', []))} |")
        md.append(f"| Linked Snapshots | {len(report.get('snapshots', []))} |")
        md.append("")

        # 2. Containment & Resolution Details
        md.append("## 2. Containment & Resolution")
        md.append(f"- **Containment Summary:** {lifecycle.get('containment_summary') or 'None recorded.'}")
        md.append(f"- **Resolution Summary:** {lifecycle.get('resolution_summary') or 'None recorded.'}")
        md.append(f"- **Closure Summary:** {lifecycle.get('closure_summary') or 'None recorded.'}")
        md.append("")

        # 3. Related Detections
        md.append("## 3. Related Security Detections")
        if report.get("detections"):
            for d in report["detections"]:
                det = d.get("details", {})
                status_badge = "[AVAILABLE]" if d.get("status") == "available" else "[SOURCE MISSING]"
                md.append(f"### {d['title']} {status_badge}")
                md.append(f"- **Evidence ID:** `{d['evidence_id']}`")
                md.append(f"- **Detection ID:** `{d['source_id']}`")
                md.append(f"- **Severity:** `{det.get('severity', 'N/A')}` | **Category:** `{det.get('category', 'N/A')}`")
                md.append(f"- **Timestamp:** {det.get('timestamp', 'N/A')}")
                md.append(f"- **Deduplication Hash:** `{det.get('dedup_hash', 'N/A')}`")
                md.append("")
        else:
            md.append("No automated security detections linked to this incident.")
            md.append("")

        # 4. File Integrity Monitoring Deviations
        md.append("## 4. File Integrity Monitoring (FIM) Deviations")
        if report.get("fim_deviations"):
            for f in report["fim_deviations"]:
                dev = f.get("details", {})
                status_badge = "[AVAILABLE]" if f.get("status") == "available" else "[SOURCE MISSING]"
                md.append(f"### {f['title']} {status_badge}")
                md.append(f"- **Evidence ID:** `{f['evidence_id']}`")
                md.append(f"- **File Path:** `{dev.get('file_path', 'N/A')}`")
                md.append(f"- **Deviation Type:** `{dev.get('deviation_type', 'N/A')}` | **Severity:** `{dev.get('severity', 'N/A')}`")
                md.append(f"- **Detected At:** {dev.get('detected_at', 'N/A')}")
                md.append("")
        else:
            md.append("No file integrity deviations linked to this incident.")
            md.append("")

        # 5. Linked User Sessions
        md.append("## 5. Linked User Authentication Sessions")
        if report.get("sessions"):
            for s in report["sessions"]:
                sess = s.get("details", {})
                md.append(f"- **Session ID:** `{s['source_id']}` | **Terminal:** `{sess.get('terminal', 'N/A')}` | **Remote Host:** `{sess.get('remote_host', 'local')}` | **Started:** {sess.get('started_at', 'N/A')}")
            md.append("")
        else:
            md.append("No user login sessions linked to this incident.")
            md.append("")

        # 6. Relevant System Snapshots
        md.append("## 6. Relevant System Snapshots")
        if report.get("snapshots"):
            for snap in report["snapshots"]:
                details = snap.get("details", {})
                status_badge = "[AVAILABLE]" if snap.get("status") == "available" else "[SOURCE MISSING]"
                md.append(f"- **Snapshot Type:** `{details.get('snapshot_type', 'N/A')}` {status_badge} | **Snapshot ID:** `{snap['source_id']}` | **Captured:** {details.get('timestamp', 'N/A')}")
            md.append("")
        else:
            md.append("No point-in-time system snapshots linked to this incident.")
            md.append("")

        # 7. Chronological Forensic Timeline
        md.append("## 7. Chronological Forensic Timeline")
        md.append("> *Note: Items marked [OBSERVED FACT] represent recorded system telemetry and evidentiary artifacts. Items marked [ANALYST INTERPRETATION] represent investigator commentary and status changes.*")
        md.append("")
        md.append("| Timestamp (UTC) | Nature | Category | Summary | Details |")
        md.append("| --- | --- | --- | --- | --- |")
        for t in report.get("timeline", []):
            nature_badge = "**[FACT]**" if t.get("nature") == "observed_fact" else "*[INTERP]*"
            ts = t.get("timestamp") or "Unknown"
            cat = t.get("category") or "General"
            summary = (t.get("summary") or "").replace("|", "\\|")
            details = (t.get("details") or "").replace("|", "\\|")
            md.append(f"| {ts} | {nature_badge} | {cat} | {summary} | {details} |")
        md.append("")

        # 8. Evidence Inventory & Provenance
        md.append("## 8. Evidence Inventory & Provenance")
        md.append("| Evidence ID | Type | Source ID | Title | Available |")
        md.append("| --- | --- | --- | --- | --- |")
        for ev in report.get("evidence_inventory", []):
            avail = "Yes" if ev.get("source_available") else "Missing"
            md.append(f"| `{ev['id']}` | `{ev['evidence_type']}` | `{ev['source_id']}` | {ev['title']} | {avail} |")
        md.append("")

        # 9. Investigation Notes & Change History
        md.append("## 9. Investigation Notes & Change History")
        if report.get("investigation_notes"):
            for n in report["investigation_notes"]:
                md.append(f"- **{n['timestamp']} ({n['user']}):** {n['notes']}")
            md.append("")
        else:
            md.append("No investigation notes recorded.")
            md.append("")

        return "\n".join(md)
