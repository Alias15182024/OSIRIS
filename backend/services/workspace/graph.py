"""Interactive forensic entity graph service (Phase 2 Milestone 2.7)."""

from __future__ import annotations

import logging
from typing import Any, Optional
import uuid

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.api.schemas.graph import (
    EntityPivotResponse,
    GraphDataResponse,
    GraphEdge,
    GraphNode,
)
from backend.db.models.detection import Detection
from backend.db.models.event import Event
from backend.db.models.file import File
from backend.db.models.fim_deviation import FimDeviation
from backend.db.models.host import Host
from backend.db.models.incident import Incident
from backend.db.models.incident_evidence import IncidentEvidence
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession

logger = logging.getLogger("osiris.services.graph")


class EntityGraphService:
    """Constructs and expands bounded forensic entity graphs and pivots."""

    # ── Node & Edge Factory Helpers ──────────────────────────────────────────

    @staticmethod
    def _node_id(entity_type: str, entity_id: Any) -> str:
        return f"{entity_type}:{entity_id}"

    @staticmethod
    def _edge_id(source_id: str, target_id: str, relationship: str) -> str:
        return f"{source_id}->{target_id}:{relationship}"

    def _host_to_node(self, host: Host) -> GraphNode:
        return GraphNode(
            id=self._node_id("host", host.id),
            entity_type="host",
            entity_id=str(host.id),
            label=host.hostname,
            subtitle=host.ip_address or "Local Host",
            host_id=host.id,
            timestamp=host.created_at,
            metadata={"os_info": host.os_info, "ip_address": host.ip_address},
        )

    def _user_to_node(self, user: LinuxUser) -> GraphNode:
        return GraphNode(
            id=self._node_id("user", user.id),
            entity_type="user",
            entity_id=str(user.id),
            label=f"{user.username} (UID {user.uid})",
            subtitle=f"UID: {user.uid}",
            host_id=user.host_id,
            timestamp=user.first_seen_at,
            metadata={"uid": user.uid, "username": user.username},
        )

    def _process_to_node(self, proc: Process) -> GraphNode:
        cmd_snippet = (proc.command[:28] + "...") if len(proc.command) > 28 else proc.command
        return GraphNode(
            id=self._node_id("process", proc.id),
            entity_type="process",
            entity_id=str(proc.id),
            label=f"{cmd_snippet} (PID {proc.pid})",
            subtitle=f"PID {proc.pid} | PPID {proc.ppid or 1}",
            host_id=proc.host_id,
            timestamp=proc.started_at,
            metadata={
                "pid": proc.pid,
                "ppid": proc.ppid,
                "command": proc.command,
                "executable": proc.executable,
                "started_at": proc.started_at.isoformat() if proc.started_at else None,
                "ended_at": proc.ended_at.isoformat() if proc.ended_at else None,
            },
        )

    def _session_to_node(self, sess: UserSession) -> GraphNode:
        target_info = sess.terminal or sess.remote_host or "console"
        return GraphNode(
            id=self._node_id("session", sess.id),
            entity_type="session",
            entity_id=str(sess.id),
            label=f"Session ({sess.session_type.upper()})",
            subtitle=target_info,
            host_id=sess.host_id,
            timestamp=sess.started_at,
            status="active" if sess.ended_at is None else "closed",
            metadata={
                "session_type": sess.session_type,
                "terminal": sess.terminal,
                "remote_host": sess.remote_host,
                "started_at": sess.started_at.isoformat() if sess.started_at else None,
                "ended_at": sess.ended_at.isoformat() if sess.ended_at else None,
            },
        )

    def _event_to_node(self, evt: Event) -> GraphNode:
        return GraphNode(
            id=self._node_id("event", evt.id),
            entity_type="event",
            entity_id=str(evt.id),
            label=f"{evt.event_type}",
            subtitle=f"{evt.source} | {evt.action}",
            severity=evt.severity,
            host_id=evt.host_id,
            timestamp=evt.timestamp,
            metadata={
                "source": evt.source,
                "action": evt.action,
                "uid": evt.uid,
                "pid": evt.pid,
                "command": evt.command,
            },
        )

    def _detection_to_node(self, det: Detection) -> GraphNode:
        return GraphNode(
            id=self._node_id("detection", det.id),
            entity_type="detection",
            entity_id=str(det.id),
            label=det.title,
            subtitle=f"{det.rule_id} ({det.category})",
            severity=det.severity,
            status=det.status,
            host_id=det.host_id,
            timestamp=det.timestamp,
            metadata={
                "rule_id": det.rule_id,
                "category": det.category,
                "severity": det.severity,
                "status": det.status,
            },
        )

    def _fim_deviation_to_node(self, dev: FimDeviation) -> GraphNode:
        filename = dev.file_path.split("/")[-1] or dev.file_path
        return GraphNode(
            id=self._node_id("fim_deviation", dev.id),
            entity_type="fim_deviation",
            entity_id=str(dev.id),
            label=f"FIM: {dev.deviation_type} ({filename})",
            subtitle=dev.file_path,
            severity=dev.severity,
            host_id=dev.host_id,
            timestamp=dev.detected_at,
            metadata={
                "deviation_type": dev.deviation_type,
                "file_path": dev.file_path,
                "severity": dev.severity,
            },
        )

    def _file_to_node(self, file: File) -> GraphNode:
        filename = file.path.split("/")[-1] or file.path
        return GraphNode(
            id=self._node_id("file", file.id),
            entity_type="file",
            entity_id=str(file.id),
            label=filename,
            subtitle=file.path,
            host_id=file.host_id,
            timestamp=file.first_seen_at,
            metadata={"path": file.path, "file_type": file.file_type},
        )

    def _incident_to_node(self, inc: Incident) -> GraphNode:
        return GraphNode(
            id=self._node_id("incident", inc.id),
            entity_type="incident",
            entity_id=str(inc.id),
            label=inc.title,
            subtitle=f"{inc.severity.upper()} | {inc.status}",
            severity=inc.severity,
            status=inc.status,
            host_id=inc.host_id,
            timestamp=inc.created_at,
            metadata={
                "severity": inc.severity,
                "status": inc.status,
                "category": inc.category,
            },
        )

    def _snapshot_to_node(self, snap: Snapshot) -> GraphNode:
        return GraphNode(
            id=self._node_id("snapshot", snap.id),
            entity_type="snapshot",
            entity_id=str(snap.id),
            label=f"{snap.snapshot_type.capitalize()} Snapshot",
            subtitle=snap.timestamp.isoformat() if snap.timestamp else "--",
            host_id=snap.host_id,
            timestamp=snap.timestamp,
            metadata={"snapshot_type": snap.snapshot_type},
        )

    # ── Graph Builder & Expansion ────────────────────────────────────────────

    def build_initial_graph(
        self,
        db: Session,
        host_id: Optional[uuid.UUID] = None,
        root_entity_type: Optional[str] = None,
        root_entity_id: Optional[str] = None,
        depth: int = 1,
        max_nodes: int = 50,
    ) -> GraphDataResponse:
        """Construct the starting graph view centered around a host or specific entity."""
        if root_entity_type and root_entity_id:
            return self.expand_node(
                db=db,
                node_type=root_entity_type,
                node_id=root_entity_id,
                host_id=host_id,
                depth=depth,
                max_nodes=max_nodes,
            )

        nodes: dict[str, GraphNode] = {}
        edges: dict[str, GraphEdge] = {}

        # Default: Pick the host or first available host
        host: Optional[Host] = None
        if host_id is not None:
            host = db.get(Host, host_id)
        else:
            host = db.scalars(select(Host).order_by(Host.created_at.desc())).first()

        if host is None:
            return GraphDataResponse(nodes=[], edges=[], total_nodes=0, total_edges=0)

        host_node = self._host_to_node(host)
        nodes[host_node.id] = host_node

        # Expand host with its key immediate neighbors
        self._expand_host(db, host, nodes, edges, max_nodes)

        valid_node_ids = set(nodes.keys())
        clean_edges = [
            e for e in edges.values()
            if e.source in valid_node_ids and e.target in valid_node_ids
        ]
        truncated = len(nodes) >= max_nodes
        return GraphDataResponse(
            nodes=list(nodes.values()),
            edges=clean_edges,
            total_nodes=len(nodes),
            total_edges=len(clean_edges),
            truncated=truncated,
            max_limit_reached=truncated,
            root_node_id=host_node.id,
        )

    def expand_node(
        self,
        db: Session,
        node_type: str,
        node_id: str,
        host_id: Optional[uuid.UUID] = None,
        depth: int = 1,
        max_nodes: int = 30,
        existing_node_ids: Optional[list[str]] = None,
    ) -> GraphDataResponse:
        """Expand adjacent relationships for a selected entity node."""
        nodes: dict[str, GraphNode] = {}
        edges: dict[str, GraphEdge] = {}

        # Seed existing nodes so we don't duplicate
        existing_set = set(existing_node_ids or [])

        # Step 1: Resolve the root entity
        clean_type = node_type.strip().lower()
        clean_id_str = str(node_id).strip()

        # Try parsing UUID if appropriate
        parsed_uuid: Optional[uuid.UUID] = None
        try:
            parsed_uuid = uuid.UUID(clean_id_str)
        except (ValueError, TypeError):
            pass

        root_node = self._resolve_node(db, clean_type, clean_id_str, parsed_uuid)
        if root_node is None:
            return GraphDataResponse(nodes=[], edges=[], total_nodes=0, total_edges=0)

        nodes[root_node.id] = root_node
        current_host_id = host_id or root_node.host_id

        # Step 2: Expand neighbors according to entity type
        self._expand_entity_type(
            db=db,
            entity_type=clean_type,
            entity_id=clean_id_str,
            parsed_uuid=parsed_uuid,
            root_node=root_node,
            host_id=current_host_id,
            nodes=nodes,
            edges=edges,
            max_nodes=max_nodes,
        )

        # If depth is 2 and we haven't reached max_nodes, expand secondary nodes
        if depth > 1 and len(nodes) < max_nodes:
            secondary_keys = list(nodes.keys())
            for key in secondary_keys:
                if key == root_node.id:
                    continue
                if len(nodes) >= max_nodes:
                    break
                sec_type, sec_id = key.split(":", 1)
                sec_uuid = None
                try:
                    sec_uuid = uuid.UUID(sec_id)
                except (ValueError, TypeError):
                    pass
                self._expand_entity_type(
                    db=db,
                    entity_type=sec_type,
                    entity_id=sec_id,
                    parsed_uuid=sec_uuid,
                    root_node=nodes[key],
                    host_id=current_host_id,
                    nodes=nodes,
                    edges=edges,
                    max_nodes=max_nodes,
                )

        valid_node_ids = set(nodes.keys()) | existing_set
        clean_edges = [
            e for e in edges.values()
            if e.source in valid_node_ids and e.target in valid_node_ids
        ]
        truncated = len(nodes) >= max_nodes
        return GraphDataResponse(
            nodes=list(nodes.values()),
            edges=clean_edges,
            total_nodes=len(nodes),
            total_edges=len(clean_edges),
            truncated=truncated,
            max_limit_reached=truncated,
            root_node_id=root_node.id,
        )

    # ── Internal Entity Expansion Handlers ───────────────────────────────────

    def _resolve_node(
        self,
        db: Session,
        clean_type: str,
        clean_id_str: str,
        parsed_uuid: Optional[uuid.UUID],
    ) -> Optional[GraphNode]:
        if clean_type == "host" and parsed_uuid:
            obj = db.get(Host, parsed_uuid)
            return self._host_to_node(obj) if obj else None
        elif clean_type == "user" and parsed_uuid:
            obj = db.get(LinuxUser, parsed_uuid)
            return self._user_to_node(obj) if obj else None
        elif clean_type == "process" and parsed_uuid:
            obj = db.get(Process, parsed_uuid)
            return self._process_to_node(obj) if obj else None
        elif clean_type == "session" and parsed_uuid:
            obj = db.get(UserSession, parsed_uuid)
            return self._session_to_node(obj) if obj else None
        elif clean_type == "event" and parsed_uuid:
            obj = db.get(Event, parsed_uuid)
            return self._event_to_node(obj) if obj else None
        elif clean_type == "detection" and parsed_uuid:
            obj = db.get(Detection, parsed_uuid)
            return self._detection_to_node(obj) if obj else None
        elif clean_type == "fim_deviation" and parsed_uuid:
            obj = db.get(FimDeviation, parsed_uuid)
            return self._fim_deviation_to_node(obj) if obj else None
        elif clean_type == "file" and parsed_uuid:
            obj = db.get(File, parsed_uuid)
            return self._file_to_node(obj) if obj else None
        elif clean_type == "incident" and parsed_uuid:
            obj = db.get(Incident, parsed_uuid)
            return self._incident_to_node(obj) if obj else None
        elif clean_type == "snapshot" and parsed_uuid:
            obj = db.get(Snapshot, parsed_uuid)
            return self._snapshot_to_node(obj) if obj else None
        return None

    def _expand_entity_type(
        self,
        db: Session,
        entity_type: str,
        entity_id: str,
        parsed_uuid: Optional[uuid.UUID],
        root_node: GraphNode,
        host_id: Optional[uuid.UUID],
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        max_nodes: int,
    ) -> None:
        if entity_type == "host" and parsed_uuid:
            host = db.get(Host, parsed_uuid)
            if host:
                self._expand_host(db, host, nodes, edges, max_nodes)
        elif entity_type == "process" and parsed_uuid:
            proc = db.get(Process, parsed_uuid)
            if proc:
                self._expand_process(db, proc, nodes, edges, max_nodes)
        elif entity_type == "session" and parsed_uuid:
            sess = db.get(UserSession, parsed_uuid)
            if sess:
                self._expand_session(db, sess, nodes, edges, max_nodes)
        elif entity_type == "detection" and parsed_uuid:
            det = db.get(Detection, parsed_uuid)
            if det:
                self._expand_detection(db, det, nodes, edges, max_nodes)
        elif entity_type == "fim_deviation" and parsed_uuid:
            dev = db.get(FimDeviation, parsed_uuid)
            if dev:
                self._expand_fim_deviation(db, dev, nodes, edges, max_nodes)
        elif entity_type == "incident" and parsed_uuid:
            inc = db.get(Incident, parsed_uuid)
            if inc:
                self._expand_incident(db, inc, nodes, edges, max_nodes)
        elif entity_type == "user" and parsed_uuid:
            user = db.get(LinuxUser, parsed_uuid)
            if user:
                self._expand_user(db, user, nodes, edges, max_nodes)
        elif entity_type == "event" and parsed_uuid:
            evt = db.get(Event, parsed_uuid)
            if evt:
                self._expand_event(db, evt, nodes, edges, max_nodes)
        elif entity_type == "file" and parsed_uuid:
            file_obj = db.get(File, parsed_uuid)
            if file_obj:
                self._expand_file(db, file_obj, nodes, edges, max_nodes)
        elif entity_type == "snapshot" and parsed_uuid:
            snap = db.get(Snapshot, parsed_uuid)
            if snap:
                self._expand_snapshot(db, snap, nodes, edges, max_nodes)

    def _expand_host(
        self,
        db: Session,
        host: Host,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        max_nodes: int,
    ) -> None:
        # Host -> Users
        users = db.scalars(
            select(LinuxUser).where(LinuxUser.host_id == host.id).limit(10)
        ).all()
        for u in users:
            if len(nodes) >= max_nodes:
                return
            un = self._user_to_node(u)
            nodes[un.id] = un
            e = GraphEdge(
                id=self._edge_id(nodes[f"host:{host.id}"].id, un.id, "user_on_host"),
                source=f"host:{host.id}",
                target=un.id,
                relationship="user_on_host",
                label="Registered User",
                edge_type="direct_database",
                provenance={"source_table": "linux_users", "fk": "host_id"},
            )
            edges[e.id] = e

        # Host -> Open Incidents
        incidents = db.scalars(
            select(Incident)
            .where(Incident.host_id == host.id, Incident.status.in_(["open", "investigating"]))
            .order_by(Incident.created_at.desc())
            .limit(5)
        ).all()
        for inc in incidents:
            if len(nodes) >= max_nodes:
                return
            in_node = self._incident_to_node(inc)
            nodes[in_node.id] = in_node
            e = GraphEdge(
                id=self._edge_id(nodes[f"host:{host.id}"].id, in_node.id, "incident_on_host"),
                source=f"host:{host.id}",
                target=in_node.id,
                relationship="incident_on_host",
                label="Active Incident",
                edge_type="direct_database",
                provenance={"source_table": "incidents", "fk": "host_id"},
            )
            edges[e.id] = e

        # Host -> Recent Detections
        detections = db.scalars(
            select(Detection)
            .where(Detection.host_id == host.id)
            .order_by(Detection.timestamp.desc())
            .limit(8)
        ).all()
        for det in detections:
            if len(nodes) >= max_nodes:
                return
            dn = self._detection_to_node(det)
            nodes[dn.id] = dn
            e = GraphEdge(
                id=self._edge_id(nodes[f"host:{host.id}"].id, dn.id, "detection_on_host"),
                source=f"host:{host.id}",
                target=dn.id,
                relationship="detection_on_host",
                label="Triggered Alert",
                edge_type="direct_database",
                provenance={"source_table": "detections", "fk": "host_id"},
            )
            edges[e.id] = e

        # Host -> Recent Sessions
        sessions = db.scalars(
            select(UserSession)
            .where(UserSession.host_id == host.id)
            .order_by(UserSession.started_at.desc())
            .limit(5)
        ).all()
        for s in sessions:
            if len(nodes) >= max_nodes:
                return
            sn = self._session_to_node(s)
            nodes[sn.id] = sn
            e = GraphEdge(
                id=self._edge_id(nodes[f"host:{host.id}"].id, sn.id, "session_on_host"),
                source=f"host:{host.id}",
                target=sn.id,
                relationship="session_on_host",
                label="Login Session",
                edge_type="direct_database",
                provenance={"source_table": "sessions", "fk": "host_id"},
            )
            edges[e.id] = e

        # Host -> Recent Processes
        processes = db.scalars(
            select(Process)
            .where(Process.host_id == host.id)
            .order_by(Process.started_at.desc())
            .limit(10)
        ).all()
        for p in processes:
            if len(nodes) >= max_nodes:
                return
            pn = self._process_to_node(p)
            nodes[pn.id] = pn
            e = GraphEdge(
                id=self._edge_id(nodes[f"host:{host.id}"].id, pn.id, "host_owns_process"),
                source=f"host:{host.id}",
                target=pn.id,
                relationship="host_owns_process",
                label="Runs Process",
                edge_type="direct_database",
                provenance={"source_table": "processes", "fk": "host_id"},
            )
            edges[e.id] = e

        # Host -> Recent Snapshots
        snapshots = db.scalars(
            select(Snapshot)
            .where(Snapshot.host_id == host.id)
            .order_by(Snapshot.timestamp.desc())
            .limit(5)
        ).all()
        for snap in snapshots:
            if len(nodes) >= max_nodes:
                return
            sn = self._snapshot_to_node(snap)
            nodes[sn.id] = sn
            e = GraphEdge(
                id=self._edge_id(nodes[f"host:{host.id}"].id, sn.id, "host_has_snapshot"),
                source=f"host:{host.id}",
                target=sn.id,
                relationship="host_has_snapshot",
                label="System Snapshot",
                edge_type="direct_database",
                provenance={"source_table": "snapshots", "fk": "host_id"},
            )
            edges[e.id] = e

    def _expand_snapshot(
        self,
        db: Session,
        snap: Snapshot,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        max_nodes: int,
    ) -> None:
        snap_node_id = f"snapshot:{snap.id}"

        # 1. Host
        if snap.host_id:
            h = db.get(Host, snap.host_id)
            if h and f"host:{h.id}" not in nodes and len(nodes) < max_nodes:
                hn = self._host_to_node(h)
                nodes[hn.id] = hn
            if h:
                e = GraphEdge(
                    id=self._edge_id(snap_node_id, f"host:{h.id}", "snapshot_of_host"),
                    source=snap_node_id,
                    target=f"host:{h.id}",
                    relationship="snapshot_of_host",
                    label="Snapshot Of Host",
                    edge_type="direct_database",
                    provenance={"source_table": "snapshots", "fk": "host_id"},
                )
                edges[e.id] = e

        # 2. Captured Processes
        if snap.timestamp:
            procs = db.scalars(
                select(Process)
                .where(
                    Process.host_id == snap.host_id,
                    Process.started_at <= snap.timestamp,
                    or_(Process.ended_at.is_(None), Process.ended_at >= snap.timestamp),
                )
                .order_by(Process.started_at.desc())
                .limit(8)
            ).all()
            for p in procs:
                if len(nodes) >= max_nodes:
                    break
                p_id = f"process:{p.id}"
                if p_id not in nodes:
                    pn = self._process_to_node(p)
                    nodes[pn.id] = pn
                e = GraphEdge(
                    id=self._edge_id(snap_node_id, p_id, "snapshot_captures_process"),
                    source=snap_node_id,
                    target=p_id,
                    relationship="snapshot_captures_process",
                    label="Captures Process State",
                    edge_type="inferred_correlation",
                    provenance={
                        "rule": "snapshot_process_state",
                        "snapshot_type": snap.snapshot_type,
                        "timestamp": snap.timestamp.isoformat(),
                    },
                )
                edges[e.id] = e

    def _expand_process(
        self,
        db: Session,
        proc: Process,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        max_nodes: int,
    ) -> None:
        p_node_id = f"process:{proc.id}"

        # 1. Host
        if proc.host_id:
            h = db.get(Host, proc.host_id)
            if h and f"host:{h.id}" not in nodes and len(nodes) < max_nodes:
                hn = self._host_to_node(h)
                nodes[hn.id] = hn
            if h and f"host:{h.id}" in nodes:
                e = GraphEdge(
                    id=self._edge_id(f"host:{h.id}", p_node_id, "host_owns_process"),
                    source=f"host:{h.id}",
                    target=p_node_id,
                    relationship="host_owns_process",
                    label="Runs Process",
                    edge_type="direct_database",
                    provenance={"source_table": "processes", "fk": "host_id"},
                )
                edges[e.id] = e

        # 2. Linux User
        if proc.linux_user_id:
            u = db.get(LinuxUser, proc.linux_user_id)
            if u and u.host_id == proc.host_id:
                if f"user:{u.id}" not in nodes and len(nodes) < max_nodes:
                    un = self._user_to_node(u)
                    nodes[un.id] = un
                if f"user:{u.id}" in nodes:
                    e = GraphEdge(
                        id=self._edge_id(f"user:{u.id}", p_node_id, "user_owns_process"),
                        source=f"user:{u.id}",
                        target=p_node_id,
                        relationship="user_owns_process",
                        label="Executes",
                        edge_type="direct_database",
                        provenance={"source_table": "processes", "fk": "linux_user_id"},
                    )
                    edges[e.id] = e

        # 3. Parent Process (via ppid on same host with PID reuse protection)
        if proc.ppid and proc.ppid > 1:
            parent = db.scalars(
                select(Process)
                .where(
                    Process.host_id == proc.host_id,
                    Process.pid == proc.ppid,
                    Process.started_at <= proc.started_at,
                    or_(Process.ended_at.is_(None), Process.ended_at >= proc.started_at),
                )
                .order_by(Process.started_at.desc())
            ).first()
            if parent:
                parent_id = f"process:{parent.id}"
                if parent_id not in nodes and len(nodes) < max_nodes:
                    pn = self._process_to_node(parent)
                    nodes[pn.id] = pn
                if parent_id in nodes:
                    e = GraphEdge(
                        id=self._edge_id(parent_id, p_node_id, "process_spawns_process"),
                        source=parent_id,
                        target=p_node_id,
                        relationship="process_spawns_process",
                        label="Spawns Child",
                        edge_type="direct_database",
                        provenance={"source_table": "processes", "ppid": proc.ppid},
                    )
                    edges[e.id] = e

        # 4. Child Processes (processes with ppid == proc.pid on same host with PID reuse protection)
        child_stmt = (
            select(Process)
            .where(
                Process.host_id == proc.host_id,
                Process.ppid == proc.pid,
                Process.started_at >= proc.started_at,
            )
            .order_by(Process.started_at.asc())
        )
        if proc.ended_at is not None:
            child_stmt = child_stmt.where(Process.started_at <= proc.ended_at)
        children = db.scalars(child_stmt.limit(6)).all()
        for child in children:
            if len(nodes) >= max_nodes:
                break
            child_id = f"process:{child.id}"
            if child_id not in nodes:
                cn = self._process_to_node(child)
                nodes[cn.id] = cn
            if child_id in nodes:
                e = GraphEdge(
                    id=self._edge_id(p_node_id, child_id, "process_spawns_process"),
                    source=p_node_id,
                    target=child_id,
                    relationship="process_spawns_process",
                    label="Spawned Child",
                    edge_type="direct_database",
                    provenance={"source_table": "processes", "ppid": proc.pid},
                )
                edges[e.id] = e

        # 5. Events referencing this process
        events = db.scalars(
            select(Event)
            .where(Event.process_id == proc.id, Event.host_id == proc.host_id)
            .order_by(Event.timestamp.desc())
            .limit(6)
        ).all()
        for evt in events:
            if len(nodes) >= max_nodes:
                break
            ev_id = f"event:{evt.id}"
            if ev_id not in nodes:
                en = self._event_to_node(evt)
                nodes[en.id] = en
            if ev_id in nodes:
                e = GraphEdge(
                    id=self._edge_id(ev_id, p_node_id, "event_references_process"),
                    source=ev_id,
                    target=p_node_id,
                    relationship="event_references_process",
                    label="References Process",
                    edge_type="direct_database",
                    provenance={"source_table": "events", "fk": "process_id"},
                )
                edges[e.id] = e

        # 6. Active Session Containment (Inferred correlation respecting host & lifetime)
        if proc.started_at:
            sess_stmt = (
                select(UserSession)
                .where(
                    UserSession.host_id == proc.host_id,
                    UserSession.started_at <= proc.started_at,
                    or_(
                        UserSession.ended_at.is_(None),
                        UserSession.ended_at >= proc.started_at,
                    ),
                )
                .order_by(UserSession.started_at.desc())
            )
            if proc.linux_user_id:
                sess_stmt = sess_stmt.where(UserSession.linux_user_id == proc.linux_user_id)
            session = db.scalars(sess_stmt).first()
            if session:
                sess_id = f"session:{session.id}"
                if sess_id not in nodes and len(nodes) < max_nodes:
                    sn = self._session_to_node(session)
                    nodes[sn.id] = sn
                if sess_id in nodes:
                    e = GraphEdge(
                        id=self._edge_id(p_node_id, sess_id, "process_in_session"),
                        source=p_node_id,
                        target=sess_id,
                        relationship="process_in_session",
                        label="Active In Session",
                        edge_type="inferred_correlation",
                        provenance={
                            "rule": "temporal_containment",
                            "session_start": session.started_at.isoformat() if session.started_at else None,
                            "proc_start": proc.started_at.isoformat() if proc.started_at else None,
                        },
                    )
                    edges[e.id] = e

    def _expand_session(
        self,
        db: Session,
        sess: UserSession,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        max_nodes: int,
    ) -> None:
        s_node_id = f"session:{sess.id}"

        # Host
        if sess.host_id:
            h = db.get(Host, sess.host_id)
            if h and f"host:{h.id}" not in nodes and len(nodes) < max_nodes:
                hn = self._host_to_node(h)
                nodes[hn.id] = hn
            if h:
                e = GraphEdge(
                    id=self._edge_id(s_node_id, f"host:{h.id}", "session_on_host"),
                    source=s_node_id,
                    target=f"host:{h.id}",
                    relationship="session_on_host",
                    label="Hosted On",
                    edge_type="direct_database",
                    provenance={"source_table": "sessions", "fk": "host_id"},
                )
                edges[e.id] = e

        # Linux User
        if sess.linux_user_id:
            u = db.get(LinuxUser, sess.linux_user_id)
            if u and f"user:{u.id}" not in nodes and len(nodes) < max_nodes:
                un = self._user_to_node(u)
                nodes[un.id] = un
            if u:
                e = GraphEdge(
                    id=self._edge_id(f"user:{u.id}", s_node_id, "user_owns_session"),
                    source=f"user:{u.id}",
                    target=s_node_id,
                    relationship="user_owns_session",
                    label="Logged In",
                    edge_type="direct_database",
                    provenance={"source_table": "sessions", "fk": "linux_user_id"},
                )
                edges[e.id] = e

        # Processes contained in session
        proc_stmt = (
            select(Process)
            .where(
                Process.host_id == sess.host_id,
                Process.started_at >= sess.started_at,
            )
            .order_by(Process.started_at.asc())
            .limit(8)
        )
        if sess.ended_at:
            proc_stmt = proc_stmt.where(Process.started_at <= sess.ended_at)
        if sess.linux_user_id:
            proc_stmt = proc_stmt.where(Process.linux_user_id == sess.linux_user_id)

        procs = db.scalars(proc_stmt).all()
        for p in procs:
            if len(nodes) >= max_nodes:
                break
            pn_id = f"process:{p.id}"
            if pn_id not in nodes:
                pn = self._process_to_node(p)
                nodes[pn.id] = pn
            e = GraphEdge(
                id=self._edge_id(pn_id, s_node_id, "process_in_session"),
                source=pn_id,
                target=s_node_id,
                relationship="process_in_session",
                label="Process In Session",
                edge_type="inferred_correlation",
                provenance={"rule": "temporal_containment"},
            )
            edges[e.id] = e

    def _expand_detection(
        self,
        db: Session,
        det: Detection,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        max_nodes: int,
    ) -> None:
        det_node_id = f"detection:{det.id}"

        # Host
        if det.host_id:
            h = db.get(Host, det.host_id)
            if h and f"host:{h.id}" not in nodes and len(nodes) < max_nodes:
                hn = self._host_to_node(h)
                nodes[hn.id] = hn
            if h:
                e = GraphEdge(
                    id=self._edge_id(det_node_id, f"host:{h.id}", "detection_on_host"),
                    source=det_node_id,
                    target=f"host:{h.id}",
                    relationship="detection_on_host",
                    label="Alert On Host",
                    edge_type="direct_database",
                    provenance={"source_table": "detections", "fk": "host_id"},
                )
                edges[e.id] = e

        # FIM Deviation Link
        if det.fim_deviation_id:
            dev = db.get(FimDeviation, det.fim_deviation_id)
            if dev and f"fim_deviation:{dev.id}" not in nodes and len(nodes) < max_nodes:
                dn = self._fim_deviation_to_node(dev)
                nodes[dn.id] = dn
            if dev:
                e = GraphEdge(
                    id=self._edge_id(f"fim_deviation:{dev.id}", det_node_id, "fim_deviation_links_detection"),
                    source=f"fim_deviation:{dev.id}",
                    target=det_node_id,
                    relationship="fim_deviation_links_detection",
                    label="Triggered By FIM",
                    edge_type="direct_database",
                    provenance={"source_table": "detections", "fk": "fim_deviation_id"},
                )
                edges[e.id] = e

        # Incidents containing this detection as evidence
        evidence_items = db.scalars(
            select(IncidentEvidence).where(
                IncidentEvidence.detection_id == det.id,
                IncidentEvidence.evidence_type == "detection",
            )
        ).all()
        for ev in evidence_items:
            inc = db.get(Incident, ev.incident_id)
            if inc and inc.host_id == det.host_id:
                inc_id = f"incident:{inc.id}"
                if inc_id not in nodes and len(nodes) < max_nodes:
                    inc_node = self._incident_to_node(inc)
                    nodes[inc_node.id] = inc_node
                e = GraphEdge(
                    id=self._edge_id(inc_id, det_node_id, "incident_contains_evidence"),
                    source=inc_id,
                    target=det_node_id,
                    relationship="incident_contains_evidence",
                    label="Evidence In Incident",
                    edge_type="direct_database",
                    provenance={"source_table": "incident_evidence", "evidence_id": str(ev.id)},
                )
                edges[e.id] = e

    def _expand_fim_deviation(
        self,
        db: Session,
        dev: FimDeviation,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        max_nodes: int,
    ) -> None:
        dev_node_id = f"fim_deviation:{dev.id}"

        # Host
        if dev.host_id:
            h = db.get(Host, dev.host_id)
            if h and f"host:{h.id}" not in nodes and len(nodes) < max_nodes:
                hn = self._host_to_node(h)
                nodes[hn.id] = hn
            if h:
                e = GraphEdge(
                    id=self._edge_id(dev_node_id, f"host:{h.id}", "fim_deviation_on_host"),
                    source=dev_node_id,
                    target=f"host:{h.id}",
                    relationship="fim_deviation_on_host",
                    label="Deviation On Host",
                    edge_type="direct_database",
                    provenance={"source_table": "fim_deviations", "fk": "host_id"},
                )
                edges[e.id] = e

        # Linked Detection
        if dev.detection_id:
            det = db.get(Detection, dev.detection_id)
            if det and f"detection:{det.id}" not in nodes and len(nodes) < max_nodes:
                dn = self._detection_to_node(det)
                nodes[dn.id] = dn
            if det:
                e = GraphEdge(
                    id=self._edge_id(dev_node_id, f"detection:{det.id}", "fim_deviation_links_detection"),
                    source=dev_node_id,
                    target=f"detection:{det.id}",
                    relationship="fim_deviation_links_detection",
                    label="Generates Detection",
                    edge_type="direct_database",
                    provenance={"source_table": "fim_deviations", "fk": "detection_id"},
                )
                edges[e.id] = e

        # Target File
        target_file = db.scalars(
            select(File).where(File.host_id == dev.host_id, File.path == dev.file_path)
        ).first()
        if target_file:
            tf_id = f"file:{target_file.id}"
            if tf_id not in nodes and len(nodes) < max_nodes:
                fn = self._file_to_node(target_file)
                nodes[fn.id] = fn
            e = GraphEdge(
                id=self._edge_id(dev_node_id, tf_id, "fim_deviation_on_file"),
                source=dev_node_id,
                target=tf_id,
                relationship="fim_deviation_on_file",
                label="Tampered File",
                edge_type="direct_database",
                provenance={"source_table": "fim_deviations", "path": dev.file_path},
            )
            edges[e.id] = e

    def _expand_incident(
        self,
        db: Session,
        inc: Incident,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        max_nodes: int,
    ) -> None:
        inc_node_id = f"incident:{inc.id}"

        # Host
        if inc.host_id:
            h = db.get(Host, inc.host_id)
            if h and f"host:{h.id}" not in nodes and len(nodes) < max_nodes:
                hn = self._host_to_node(h)
                nodes[hn.id] = hn
            if h:
                e = GraphEdge(
                    id=self._edge_id(inc_node_id, f"host:{h.id}", "incident_on_host"),
                    source=inc_node_id,
                    target=f"host:{h.id}",
                    relationship="incident_on_host",
                    label="Incident On Host",
                    edge_type="direct_database",
                    provenance={"source_table": "incidents", "fk": "host_id"},
                )
                edges[e.id] = e

        # Evidence records
        evidence_items = db.scalars(
            select(IncidentEvidence)
            .where(IncidentEvidence.incident_id == inc.id)
            .limit(15)
        ).all()
        for ev in evidence_items:
            if len(nodes) >= max_nodes:
                break
            target_node: Optional[GraphNode] = None

            if ev.evidence_type == "detection" and ev.detection_id:
                d = db.get(Detection, ev.detection_id)
                if d and d.host_id == inc.host_id:
                    target_node = self._detection_to_node(d)
            elif ev.evidence_type == "event" and ev.event_id:
                evt = db.get(Event, ev.event_id)
                if evt and evt.host_id == inc.host_id:
                    target_node = self._event_to_node(evt)
            elif ev.evidence_type == "fim_deviation" and ev.fim_deviation_id:
                dev = db.get(FimDeviation, ev.fim_deviation_id)
                if dev and dev.host_id == inc.host_id:
                    target_node = self._fim_deviation_to_node(dev)
            elif ev.evidence_type == "session" and ev.session_id:
                s = db.get(UserSession, ev.session_id)
                if s and s.host_id == inc.host_id:
                    target_node = self._session_to_node(s)
            elif ev.evidence_type == "process" and ev.process_id:
                p = db.get(Process, ev.process_id)
                if p and p.host_id == inc.host_id:
                    target_node = self._process_to_node(p)
            elif ev.evidence_type == "file" and ev.file_id:
                f = db.get(File, ev.file_id)
                if f and f.host_id == inc.host_id:
                    target_node = self._file_to_node(f)

            if target_node:
                if target_node.id not in nodes:
                    nodes[target_node.id] = target_node
                e = GraphEdge(
                    id=self._edge_id(inc_node_id, target_node.id, "incident_contains_evidence"),
                    source=inc_node_id,
                    target=target_node.id,
                    relationship="incident_contains_evidence",
                    label=f"Correlated {ev.evidence_type.capitalize()}",
                    edge_type="direct_database",
                    provenance={"source_table": "incident_evidence", "evidence_id": str(ev.id)},
                )
                edges[e.id] = e

    def _expand_user(
        self,
        db: Session,
        user: LinuxUser,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        max_nodes: int,
    ) -> None:
        u_node_id = f"user:{user.id}"

        # Host
        if user.host_id:
            h = db.get(Host, user.host_id)
            if h and f"host:{h.id}" not in nodes and len(nodes) < max_nodes:
                hn = self._host_to_node(h)
                nodes[hn.id] = hn
            if h:
                e = GraphEdge(
                    id=self._edge_id(u_node_id, f"host:{h.id}", "user_on_host"),
                    source=u_node_id,
                    target=f"host:{h.id}",
                    relationship="user_on_host",
                    label="Account On Host",
                    edge_type="direct_database",
                    provenance={"source_table": "linux_users", "fk": "host_id"},
                )
                edges[e.id] = e

        # Recent sessions
        sessions = db.scalars(
            select(UserSession)
            .where(UserSession.host_id == user.host_id, UserSession.linux_user_id == user.id)
            .order_by(UserSession.started_at.desc())
            .limit(5)
        ).all()
        for s in sessions:
            if len(nodes) >= max_nodes:
                break
            sn = self._session_to_node(s)
            nodes[sn.id] = sn
            e = GraphEdge(
                id=self._edge_id(u_node_id, sn.id, "user_owns_session"),
                source=u_node_id,
                target=sn.id,
                relationship="user_owns_session",
                label="Logged In",
                edge_type="direct_database",
                provenance={"source_table": "sessions", "fk": "linux_user_id"},
            )
            edges[e.id] = e

        # Recent processes
        processes = db.scalars(
            select(Process)
            .where(Process.host_id == user.host_id, Process.linux_user_id == user.id)
            .order_by(Process.started_at.desc())
            .limit(6)
        ).all()
        for p in processes:
            if len(nodes) >= max_nodes:
                break
            pn = self._process_to_node(p)
            nodes[pn.id] = pn
            e = GraphEdge(
                id=self._edge_id(u_node_id, pn.id, "user_owns_process"),
                source=u_node_id,
                target=pn.id,
                relationship="user_owns_process",
                label="Executed Process",
                edge_type="direct_database",
                provenance={"source_table": "processes", "fk": "linux_user_id"},
            )
            edges[e.id] = e

    def _expand_event(
        self,
        db: Session,
        evt: Event,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        max_nodes: int,
    ) -> None:
        evt_node_id = f"event:{evt.id}"

        # Host
        if evt.host_id:
            h = db.get(Host, evt.host_id)
            if h and f"host:{h.id}" not in nodes and len(nodes) < max_nodes:
                hn = self._host_to_node(h)
                nodes[hn.id] = hn
            if h:
                e = GraphEdge(
                    id=self._edge_id(evt_node_id, f"host:{h.id}", "event_on_host"),
                    source=evt_node_id,
                    target=f"host:{h.id}",
                    relationship="event_on_host",
                    label="Telemetry On Host",
                    edge_type="direct_database",
                    provenance={"source_table": "events", "fk": "host_id"},
                )
                edges[e.id] = e

        # Referenced Process
        if evt.process_id:
            p = db.get(Process, evt.process_id)
            if p and p.host_id == evt.host_id:
                pn_id = f"process:{p.id}"
                if pn_id not in nodes and len(nodes) < max_nodes:
                    pn = self._process_to_node(p)
                    nodes[pn.id] = pn
                e = GraphEdge(
                    id=self._edge_id(evt_node_id, pn_id, "event_references_process"),
                    source=evt_node_id,
                    target=pn_id,
                    relationship="event_references_process",
                    label="Associated Process",
                    edge_type="direct_database",
                    provenance={"source_table": "events", "fk": "process_id"},
                )
                edges[e.id] = e

    def _expand_file(
        self,
        db: Session,
        file_obj: File,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        max_nodes: int,
    ) -> None:
        file_node_id = f"file:{file_obj.id}"

        # Host
        if file_obj.host_id:
            h = db.get(Host, file_obj.host_id)
            if h and f"host:{h.id}" not in nodes and len(nodes) < max_nodes:
                hn = self._host_to_node(h)
                nodes[hn.id] = hn
            if h:
                e = GraphEdge(
                    id=self._edge_id(file_node_id, f"host:{h.id}", "file_on_host"),
                    source=file_node_id,
                    target=f"host:{h.id}",
                    relationship="file_on_host",
                    label="File On Host",
                    edge_type="direct_database",
                    provenance={"source_table": "files", "fk": "host_id"},
                )
                edges[e.id] = e

        # FIM Deviations on this path
        deviations = db.scalars(
            select(FimDeviation).where(
                FimDeviation.host_id == file_obj.host_id,
                FimDeviation.file_path == file_obj.path,
            )
        ).all()
        for dev in deviations:
            if len(nodes) >= max_nodes:
                break
            dn = self._fim_deviation_to_node(dev)
            nodes[dn.id] = dn
            e = GraphEdge(
                id=self._edge_id(dn.id, file_node_id, "fim_deviation_on_file"),
                source=dn.id,
                target=file_node_id,
                relationship="fim_deviation_on_file",
                label="Integrity Deviation",
                edge_type="direct_database",
                provenance={"source_table": "fim_deviations", "path": file_obj.path},
            )
            edges[e.id] = e

    # ── Cross-Entity Pivoting ────────────────────────────────────────────────

    def get_entity_pivots(
        self,
        db: Session,
        entity_type: str,
        entity_id: str,
    ) -> EntityPivotResponse:
        """Collect direct pivoting links across related forensic entities."""
        clean_type = entity_type.strip().lower()
        clean_id = str(entity_id).strip()

        parsed_uuid = None
        try:
            parsed_uuid = uuid.UUID(clean_id)
        except (ValueError, TypeError):
            pass

        node = self._resolve_node(db, clean_type, clean_id, parsed_uuid)
        if node is None:
            return EntityPivotResponse(
                entity_type=clean_type,
                entity_id=clean_id,
                label=f"{clean_type}:{clean_id}",
                related_entities={},
                breadcrumbs=[],
            )

        related: dict[str, list[dict[str, Any]]] = {}

        if clean_type == "host" and parsed_uuid:
            host = db.get(Host, parsed_uuid)
            if host:
                procs = db.scalars(
                    select(Process)
                    .where(Process.host_id == host.id)
                    .order_by(Process.started_at.desc())
                    .limit(10)
                ).all()
                if procs:
                    related["processes"] = [
                        {"id": str(p.id), "title": p.command, "pid": p.pid} for p in procs
                    ]
                sessions = db.scalars(
                    select(UserSession)
                    .where(UserSession.host_id == host.id)
                    .order_by(UserSession.started_at.desc())
                    .limit(10)
                ).all()
                if sessions:
                    related["sessions"] = [
                        {"id": str(s.id), "title": f"Session ({s.session_type.upper()}) on {s.terminal or 'console'}"}
                        for s in sessions
                    ]
                events = db.scalars(
                    select(Event)
                    .where(Event.host_id == host.id)
                    .order_by(Event.timestamp.desc())
                    .limit(10)
                ).all()
                if events:
                    related["events"] = [
                        {"id": str(e.id), "title": e.event_type, "timestamp": e.timestamp.isoformat()}
                        for e in events
                    ]
                detections = db.scalars(
                    select(Detection)
                    .where(Detection.host_id == host.id)
                    .order_by(Detection.timestamp.desc())
                    .limit(10)
                ).all()
                if detections:
                    related["detections"] = [
                        {"id": str(d.id), "title": d.title, "severity": d.severity}
                        for d in detections
                    ]
                incidents = db.scalars(
                    select(Incident)
                    .where(Incident.host_id == host.id)
                    .order_by(Incident.created_at.desc())
                    .limit(10)
                ).all()
                if incidents:
                    related["incidents"] = [
                        {"id": str(i.id), "title": i.title, "status": i.status, "severity": i.severity}
                        for i in incidents
                    ]
                snapshots = db.scalars(
                    select(Snapshot)
                    .where(Snapshot.host_id == host.id)
                    .order_by(Snapshot.timestamp.desc())
                    .limit(5)
                ).all()
                if snapshots:
                    related["snapshots"] = [
                        {"id": str(sn.id), "title": f"{sn.snapshot_type.capitalize()} Snapshot", "timestamp": sn.timestamp.isoformat() if sn.timestamp else ""}
                        for sn in snapshots
                    ]

        elif clean_type == "process" and parsed_uuid:
            proc = db.get(Process, parsed_uuid)
            if proc:
                if proc.host_id:
                    related["host"] = [{"id": str(proc.host_id)}]
                if proc.linux_user_id:
                    u = db.get(LinuxUser, proc.linux_user_id)
                    if u:
                        related["user"] = [{"id": str(u.id), "title": u.username, "uid": u.uid}]

                # Parent
                if proc.ppid and proc.ppid > 1:
                    parent = db.scalars(
                        select(Process)
                        .where(
                            Process.host_id == proc.host_id,
                            Process.pid == proc.ppid,
                            Process.started_at <= proc.started_at,
                            or_(Process.ended_at.is_(None), Process.ended_at >= proc.started_at),
                        )
                        .order_by(Process.started_at.desc())
                    ).first()
                    if parent:
                        related["parent_process"] = [
                            {"id": str(parent.id), "title": parent.command, "pid": parent.pid}
                        ]

                # Children
                child_stmt = (
                    select(Process)
                    .where(
                        Process.host_id == proc.host_id,
                        Process.ppid == proc.pid,
                        Process.started_at >= proc.started_at,
                    )
                    .order_by(Process.started_at.asc())
                )
                if proc.ended_at is not None:
                    child_stmt = child_stmt.where(Process.started_at <= proc.ended_at)
                children = db.scalars(child_stmt.limit(10)).all()
                if children:
                    related["child_processes"] = [
                        {"id": str(c.id), "title": c.command, "pid": c.pid} for c in children
                    ]

                # Events
                events = db.scalars(
                    select(Event)
                    .where(Event.process_id == proc.id, Event.host_id == proc.host_id)
                    .order_by(Event.timestamp.desc())
                    .limit(10)
                ).all()
                if events:
                    related["events"] = [
                        {"id": str(e.id), "title": e.event_type, "timestamp": e.timestamp.isoformat()}
                        for e in events
                    ]

        elif clean_type == "user" and parsed_uuid:
            user = db.get(LinuxUser, parsed_uuid)
            if user:
                if user.host_id:
                    related["host"] = [{"id": str(user.host_id)}]
                sessions = db.scalars(
                    select(UserSession)
                    .where(UserSession.host_id == user.host_id, UserSession.linux_user_id == user.id)
                    .limit(10)
                ).all()
                if sessions:
                    related["sessions"] = [
                        {"id": str(s.id), "title": f"Session ({s.session_type})"} for s in sessions
                    ]
                procs = db.scalars(
                    select(Process)
                    .where(Process.host_id == user.host_id, Process.linux_user_id == user.id)
                    .limit(10)
                ).all()
                if procs:
                    related["processes"] = [
                        {"id": str(p.id), "title": p.command, "pid": p.pid} for p in procs
                    ]
                events = db.scalars(
                    select(Event).where(Event.uid == user.uid, Event.host_id == user.host_id).limit(10)
                ).all()
                if events:
                    related["events"] = [
                        {"id": str(e.id), "title": e.event_type, "timestamp": e.timestamp.isoformat()}
                        for e in events
                    ]

        elif clean_type == "session" and parsed_uuid:
            sess = db.get(UserSession, parsed_uuid)
            if sess:
                if sess.host_id:
                    related["host"] = [{"id": str(sess.host_id)}]
                if sess.linux_user_id:
                    u = db.get(LinuxUser, sess.linux_user_id)
                    if u:
                        related["user"] = [{"id": str(u.id), "title": u.username, "uid": u.uid}]
                procs = db.scalars(
                    select(Process)
                    .where(
                        Process.host_id == sess.host_id,
                        Process.started_at >= sess.started_at,
                        or_(sess.ended_at.is_(None), Process.started_at <= sess.ended_at),
                    )
                    .limit(10)
                ).all()
                if procs:
                    related["processes"] = [
                        {"id": str(p.id), "title": p.command, "pid": p.pid} for p in procs
                    ]

        elif clean_type == "detection" and parsed_uuid:
            det = db.get(Detection, parsed_uuid)
            if det:
                if det.host_id:
                    related["host"] = [{"id": str(det.host_id)}]
                if det.fim_deviation_id:
                    related["fim_deviation"] = [{"id": str(det.fim_deviation_id)}]
                inc_ev = db.scalars(
                    select(IncidentEvidence).where(IncidentEvidence.detection_id == det.id)
                ).all()
                if inc_ev:
                    related["incidents"] = [
                        {"incident_id": str(ie.incident_id), "title": ie.title} for ie in inc_ev
                    ]
                trig_events = db.scalars(
                    select(Event)
                    .where(Event.host_id == det.host_id, Event.timestamp <= det.timestamp)
                    .order_by(Event.timestamp.desc())
                    .limit(5)
                ).all()
                if trig_events:
                    related["triggering_events"] = [
                        {"id": str(e.id), "title": e.event_type, "timestamp": e.timestamp.isoformat()}
                        for e in trig_events
                    ]

        elif clean_type == "fim_deviation" and parsed_uuid:
            dev = db.get(FimDeviation, parsed_uuid)
            if dev:
                if dev.host_id:
                    related["host"] = [{"id": str(dev.host_id)}]
                file_obj = db.scalars(
                    select(File).where(File.host_id == dev.host_id, File.path == dev.file_path)
                ).first()
                if file_obj:
                    related["file"] = [{"id": str(file_obj.id), "title": file_obj.path}]
                dets = db.scalars(
                    select(Detection).where(Detection.fim_deviation_id == dev.id)
                ).all()
                if dets:
                    related["detections"] = [
                        {"id": str(d.id), "title": d.title, "severity": d.severity} for d in dets
                    ]
                inc_ev = db.scalars(
                    select(IncidentEvidence).where(
                        IncidentEvidence.evidence_type == "fim_deviation",
                        IncidentEvidence.source_id == str(dev.id),
                    )
                ).all()
                if inc_ev:
                    related["incidents"] = [
                        {"incident_id": str(ie.incident_id), "title": ie.title} for ie in inc_ev
                    ]

        elif clean_type == "incident" and parsed_uuid:
            inc = db.get(Incident, parsed_uuid)
            if inc:
                if inc.host_id:
                    related["host"] = [{"id": str(inc.host_id)}]
                ev_items = db.scalars(
                    select(IncidentEvidence).where(IncidentEvidence.incident_id == inc.id)
                ).all()
                related["evidence"] = [
                    {"type": ev.evidence_type, "source_id": ev.source_id, "title": ev.title}
                    for ev in ev_items
                ]
                dets = [ev for ev in ev_items if ev.detection_id]
                if dets:
                    related["detections"] = [
                        {"id": str(d.detection_id), "title": d.title} for d in dets
                    ]

        elif clean_type == "snapshot" and parsed_uuid:
            snap = db.get(Snapshot, parsed_uuid)
            if snap:
                if snap.host_id:
                    related["host"] = [{"id": str(snap.host_id)}]
                if snap.timestamp:
                    procs = db.scalars(
                        select(Process)
                        .where(
                            Process.host_id == snap.host_id,
                            Process.started_at <= snap.timestamp,
                            or_(Process.ended_at.is_(None), Process.ended_at >= snap.timestamp),
                        )
                        .order_by(Process.started_at.desc())
                        .limit(10)
                    ).all()
                    if procs:
                        related["captured_processes"] = [
                            {"id": str(p.id), "title": p.command, "pid": p.pid} for p in procs
                        ]
                    events = db.scalars(
                        select(Event)
                        .where(Event.host_id == snap.host_id, Event.timestamp <= snap.timestamp)
                        .order_by(Event.timestamp.desc())
                        .limit(5)
                    ).all()
                    if events:
                        related["associated_events"] = [
                            {"id": str(e.id), "title": e.event_type, "timestamp": e.timestamp.isoformat()}
                            for e in events
                        ]

        elif clean_type == "event" and parsed_uuid:
            evt = db.get(Event, parsed_uuid)
            if evt:
                if evt.host_id:
                    related["host"] = [{"id": str(evt.host_id)}]
                if evt.process_id:
                    p = db.get(Process, evt.process_id)
                    if p:
                        related["process"] = [{"id": str(p.id), "title": p.command, "pid": p.pid}]
                if evt.uid is not None and evt.host_id:
                    u = db.scalars(
                        select(LinuxUser).where(LinuxUser.host_id == evt.host_id, LinuxUser.uid == evt.uid)
                    ).first()
                    if u:
                        related["user"] = [{"id": str(u.id), "title": u.username, "uid": u.uid}]

        elif clean_type == "file" and parsed_uuid:
            file_obj = db.get(File, parsed_uuid)
            if file_obj:
                if file_obj.host_id:
                    related["host"] = [{"id": str(file_obj.host_id)}]
                deviations = db.scalars(
                    select(FimDeviation).where(
                        FimDeviation.host_id == file_obj.host_id,
                        FimDeviation.file_path == file_obj.path,
                    )
                ).all()
                if deviations:
                    related["fim_deviations"] = [
                        {"id": str(d.id), "title": d.deviation_type, "severity": d.severity}
                        for d in deviations
                    ]
                events = db.scalars(
                    select(Event).where(
                        Event.host_id == file_obj.host_id,
                        Event.object_path == file_obj.path,
                    ).limit(10)
                ).all()
                if events:
                    related["events"] = [
                        {"id": str(e.id), "title": e.event_type, "timestamp": e.timestamp.isoformat()}
                        for e in events
                    ]

        breadcrumbs = []
        if node.host_id and clean_type != "host":
            breadcrumbs.append({"type": "host", "id": str(node.host_id), "label": f"Host {node.host_id}"})
        breadcrumbs.append({"type": clean_type, "id": clean_id, "label": node.label})

        return EntityPivotResponse(
            entity_type=clean_type,
            entity_id=clean_id,
            label=node.label,
            host_id=node.host_id,
            related_entities=related,
            breadcrumbs=breadcrumbs,
        )
