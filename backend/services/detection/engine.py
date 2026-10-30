"""Core OSIRIS Detection Evaluation Engine.

Evaluates normalized events against active declarative single-event and sequence rules.
Guarantees:
- Deterministic UTC timestamps.
- Explainable condition matching.
- Strict host-scoped isolation.
- Alert deduplication / idempotency with SHA-256 fingerprints.
- Forensic linkage to source events, processes, and sessions.
"""
from __future__ import annotations

import collections
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Sequence
import uuid

from backend.services.detection.matcher import evaluate_condition_node, extract_field_value
from backend.services.detection.models import DetectionMatch, RuleDefinition
from backend.services.detection.sequence import SequenceMatcher, _get_event_id, _get_event_timestamp

logger = logging.getLogger("osiris.services.detection.engine")


def compute_dedup_hash(rule_id: str, host_id: uuid.UUID, event_ids: Sequence[uuid.UUID]) -> str:
    """Compute deterministic SHA-256 deduplication fingerprint for a detection."""
    sorted_eids = sorted(str(eid) for eid in event_ids)
    raw = f"{rule_id}:{host_id}:{','.join(sorted_eids)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class DetectionEngine:
    """Authoritative OSIRIS detection evaluation engine."""

    def __init__(self, rules: Sequence[RuleDefinition] | None = None) -> None:
        self._rules: dict[str, RuleDefinition] = {}
        self._single_event_rules: list[RuleDefinition] = []
        self._sequence_matchers: list[SequenceMatcher] = []

        if rules:
            for r in rules:
                self.add_rule(r)

    def add_rule(self, rule: RuleDefinition) -> None:
        """Register a validated rule with the engine (idempotent)."""
        if rule.rule_id in self._rules:
            self._single_event_rules = [r for r in self._single_event_rules if r.rule_id != rule.rule_id]
            self._sequence_matchers = [m for m in self._sequence_matchers if m.rule.rule_id != rule.rule_id]

        self._rules[rule.rule_id] = rule
        if not rule.enabled:
            return

        if rule.rule_type == "single_event":
            self._single_event_rules.append(rule)
        elif rule.rule_type == "sequence":
            self._sequence_matchers.append(SequenceMatcher(rule))

    def clear_rules(self) -> None:
        """Clear all registered rules."""
        self._rules.clear()
        self._single_event_rules.clear()
        self._sequence_matchers.clear()

    @property
    def rules(self) -> list[RuleDefinition]:
        return list(self._rules.values())

    def evaluate_event(self, event: Any) -> list[DetectionMatch]:
        """Evaluate a single observation against all enabled single-event rules.

        Returns a list of DetectionMatch objects for any matched rules.
        """
        if not self._single_event_rules:
            return []

        host_id_raw = extract_field_value(event, "host_id")
        if not host_id_raw:
            return []

        host_id = host_id_raw if isinstance(host_id_raw, uuid.UUID) else uuid.UUID(str(host_id_raw))
        event_id = _get_event_id(event)
        event_ts = _get_event_timestamp(event)
        process_id = extract_field_value(event, "process_id")
        if process_id and not isinstance(process_id, uuid.UUID):
            try:
                process_id = uuid.UUID(str(process_id))
            except ValueError:
                process_id = None

        session_id = extract_field_value(event, "session_id")
        if session_id and not isinstance(session_id, uuid.UUID):
            try:
                session_id = uuid.UUID(str(session_id))
            except ValueError:
                session_id = None

        matches: list[DetectionMatch] = []

        for rule in self._single_event_rules:
            assert rule.conditions is not None
            res = evaluate_condition_node(rule.conditions, event)
            if res.matched:
                dedup = compute_dedup_hash(rule.rule_id, host_id, [event_id])
                evidence = {
                    "rule_id": rule.rule_id,
                    "event_type": extract_field_value(event, "event_type"),
                    "action": extract_field_value(event, "action"),
                    "source": extract_field_value(event, "source"),
                    "uid": extract_field_value(event, "uid"),
                    "username": extract_field_value(event, "username"),
                    "command": extract_field_value(event, "command"),
                    "object_path": extract_field_value(event, "object_path"),
                    "triggering_event_id": str(event_id),
                    "matched_at": event_ts.isoformat(),
                }

                match = DetectionMatch(
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    host_id=host_id,
                    timestamp=event_ts,
                    severity=rule.severity,
                    title=rule.name,
                    description=rule.description or rule.explanation,
                    category=rule.category,
                    explanation=rule.explanation,
                    matched_conditions={"conditions": res.details},
                    evidence=evidence,
                    triggering_event_ids=[event_id],
                    primary_event_id=event_id,
                    process_id=process_id,
                    session_id=session_id,
                    dedup_hash=dedup,
                )
                matches.append(match)

        return matches

    def evaluate_batch(self, events: Sequence[Any]) -> list[DetectionMatch]:
        """Evaluate a batch of observations against all enabled rules.

        Handles both single-event detection and multi-event sequence correlation.
        Guarantees cross-host isolation and eliminates duplicate matches within the batch.
        """
        if not events:
            return []

        all_matches: list[DetectionMatch] = []
        seen_dedup_hashes: set[str] = set()

        # 1. Single-event evaluation
        for ev in events:
            single_matches = self.evaluate_event(ev)
            for m in single_matches:
                if m.dedup_hash not in seen_dedup_hashes:
                    seen_dedup_hashes.add(m.dedup_hash)
                    all_matches.append(m)

        # 2. Sequence evaluation with host isolation
        if self._sequence_matchers:
            events_by_host: dict[uuid.UUID, list[Any]] = collections.defaultdict(list)
            for ev in events:
                hid_raw = extract_field_value(ev, "host_id")
                if hid_raw:
                    hid = hid_raw if isinstance(hid_raw, uuid.UUID) else uuid.UUID(str(hid_raw))
                    events_by_host[hid].append(ev)

            for host_id, host_events in events_by_host.items():
                for seq_matcher in self._sequence_matchers:
                    seq_results = seq_matcher.evaluate_host_events(host_id, host_events)
                    for res in seq_results:
                        rule = seq_matcher.rule
                        triggering_ids = res["triggering_event_ids"]
                        dedup = compute_dedup_hash(rule.rule_id, host_id, triggering_ids)

                        if dedup in seen_dedup_hashes:
                            continue
                        seen_dedup_hashes.add(dedup)

                        primary_ev = res["primary_event"]
                        primary_eid = _get_event_id(primary_ev)
                        pid = extract_field_value(primary_ev, "process_id")
                        if pid and not isinstance(pid, uuid.UUID):
                            try:
                                pid = uuid.UUID(str(pid))
                            except ValueError:
                                pid = None
                        sid = extract_field_value(primary_ev, "session_id")
                        if sid and not isinstance(sid, uuid.UUID):
                            try:
                                sid = uuid.UUID(str(sid))
                            except ValueError:
                                sid = None

                        match = DetectionMatch(
                            rule_id=rule.rule_id,
                            rule_version=rule.version,
                            host_id=host_id,
                            timestamp=res["timestamp"],
                            severity=rule.severity,
                            title=rule.name,
                            description=rule.description or rule.explanation,
                            category=rule.category,
                            explanation=rule.explanation,
                            matched_conditions=res["matched_conditions"],
                            evidence=res["evidence"],
                            triggering_event_ids=triggering_ids,
                            primary_event_id=primary_eid,
                            process_id=pid,
                            session_id=sid,
                            dedup_hash=dedup,
                        )
                        all_matches.append(match)

        return all_matches
