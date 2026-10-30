"""Sequence evaluation engine for multi-event correlated security detection.

Evaluates sequences across ordered observations with:
- Strict host isolation.
- Bounded sliding time windows.
- In-order stage satisfaction without event reuse across stages.
- Match-field correlation (e.g., matching username across failed and successful attempts).
- Forensic evidence explainability.
"""
from __future__ import annotations

import collections
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence
import uuid

from backend.services.detection.matcher import evaluate_condition_node, extract_field_value
from backend.services.detection.models import RuleDefinition, SequenceDefinition, SequenceStage


def _get_event_timestamp(obs: Any) -> datetime:
    """Extract UTC timezone-aware timestamp from observation."""
    raw_ts = extract_field_value(obs, "timestamp")
    if isinstance(raw_ts, datetime):
        if raw_ts.tzinfo is None:
            return raw_ts.replace(tzinfo=timezone.utc)
        return raw_ts.astimezone(timezone.utc)
    if isinstance(raw_ts, str):
        try:
            dt = datetime.fromisoformat(raw_ts)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _get_event_id(obs: Any) -> uuid.UUID:
    """Extract UUID identifier from observation."""
    eid = extract_field_value(obs, "id")
    if isinstance(eid, uuid.UUID):
        return eid
    if isinstance(eid, str):
        try:
            return uuid.UUID(eid)
        except ValueError:
            pass
    return uuid.uuid4()


class SequenceMatcher:
    """Stateful or batch sequence evaluator for declarative sequence rules."""

    def __init__(self, rule: RuleDefinition) -> None:
        if rule.rule_type != "sequence" or rule.sequence is None:
            raise ValueError(f"Rule '{rule.rule_id}' is not a sequence rule.")
        self.rule = rule
        self.seq_def: SequenceDefinition = rule.sequence
        self.stages = self.seq_def.stages
        self.window_seconds = self.seq_def.time_window_seconds
        self.min_total_events = sum(s.min_count for s in self.stages)

    def evaluate_host_events(
        self,
        host_id: uuid.UUID,
        events: list[Any],
    ) -> list[dict[str, Any]]:
        """Evaluate a sequence against an ordered collection of events for a specific host.

        Events MUST belong to the same host_id.
        Returns a list of match payloads for any detected sequences.
        """
        if len(events) < self.min_total_events:
            return []

        # Ensure events are stably sorted by UTC timestamp, preserving input arrival order
        sorted_events = sorted(events, key=_get_event_timestamp)

        n_stages = len(self.stages)

        # Pre-classify events by which stages they satisfy
        stage_matches: list[list[int]] = [[] for _ in range(n_stages)]
        stage_explanations: dict[tuple[int, int], list[dict[str, Any]]] = {}

        for e_idx, event in enumerate(sorted_events):
            for s_idx, stage in enumerate(self.stages):
                res = evaluate_condition_node(stage.conditions, event)
                if res.matched:
                    stage_matches[s_idx].append(e_idx)
                    stage_explanations[(s_idx, e_idx)] = res.details

        # If any stage has fewer matching events than min_count, sequence cannot be satisfied
        for s_idx, stage in enumerate(self.stages):
            if len(stage_matches[s_idx]) < stage.min_count:
                return []

        matches: list[dict[str, Any]] = []
        seen_event_id_tuples: set[tuple[uuid.UUID, ...]] = set()

        final_stage_idx = n_stages - 1

        # Scan candidate events completing the final stage
        for final_event_idx in stage_matches[final_stage_idx]:
            final_event = sorted_events[final_event_idx]
            final_ts = _get_event_timestamp(final_event)
            window_start_ts = final_ts - timedelta(seconds=self.window_seconds)

            candidate = self._resolve_stages_backward(
                stage_idx=final_stage_idx,
                upper_bound_idx=final_event_idx + 1,
                anchor_event_idx=final_event_idx,
                window_start_ts=window_start_ts,
                sorted_events=sorted_events,
                stage_matches=stage_matches,
                stage_explanations=stage_explanations,
                collected_stage_events=[],
                match_field_values={},
            )

            if candidate:
                eids_key = tuple(sorted(candidate["triggering_event_ids"]))
                if eids_key not in seen_event_id_tuples:
                    seen_event_id_tuples.add(eids_key)
                    matches.append(candidate)

        return matches

    def _resolve_stages_backward(
        self,
        stage_idx: int,
        upper_bound_idx: int,
        anchor_event_idx: int | None,
        window_start_ts: datetime,
        sorted_events: list[Any],
        stage_matches: list[list[int]],
        stage_explanations: dict[tuple[int, int], list[dict[str, Any]]],
        collected_stage_events: list[list[int]],
        match_field_values: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Recursively assemble sequence stages backwards from final stage to stage 0.

        Enforces:
        - Strict index ordering: max(events in stage s) < min(events in stage s+1).
        - Sliding time window: events must have timestamp >= window_start_ts.
        - Intra-stage and inter-stage match_fields consistency.
        - Zero event reuse across stages.
        """
        if stage_idx < 0:
            # All stages assembled in reverse order [Stage K-1, Stage K-2, ... Stage 0]
            # Restore forward chronological order
            ordered_stages = list(reversed(collected_stage_events))
            return self._build_sequence_match_payload(
                sorted_events=sorted_events,
                collected_stage_events=ordered_stages,
                stage_explanations=stage_explanations,
                match_fields=match_field_values,
            )

        stage = self.stages[stage_idx]
        is_final_stage = (stage_idx == len(self.stages) - 1)

        # 1. Candidate events for this stage must have index < upper_bound_idx and timestamp >= window_start_ts
        matching_indices = [
            i for i in stage_matches[stage_idx]
            if i < upper_bound_idx and _get_event_timestamp(sorted_events[i]) >= window_start_ts
        ]

        # For final stage, anchor_event_idx must be the last event in this stage
        if is_final_stage and anchor_event_idx is not None:
            if anchor_event_idx not in matching_indices:
                return None
            anchor_ev = sorted_events[anchor_event_idx]

            # Bind match_fields from anchor event
            new_mf = dict(match_field_values)
            for mf in stage.match_fields:
                val = extract_field_value(anchor_ev, mf)
                if val is None:
                    return None  # Cannot satisfy correlation without field value
                new_mf[mf] = val

            if stage.min_count == 1:
                chosen = [anchor_event_idx]
                return self._resolve_stages_backward(
                    stage_idx=stage_idx - 1,
                    upper_bound_idx=chosen[0],
                    anchor_event_idx=None,
                    window_start_ts=window_start_ts,
                    sorted_events=sorted_events,
                    stage_matches=stage_matches,
                    stage_explanations=stage_explanations,
                    collected_stage_events=collected_stage_events + [chosen],
                    match_field_values=new_mf,
                )
            else:
                # Prior events in final stage must match new_mf and precede anchor_event_idx
                prior = [
                    i for i in matching_indices
                    if i < anchor_event_idx and all(
                        extract_field_value(sorted_events[i], mf) == new_mf[mf]
                        for mf in stage.match_fields
                    )
                ]
                needed = stage.min_count - 1
                if len(prior) < needed:
                    return None
                chosen = prior[-needed:] + [anchor_event_idx]
                return self._resolve_stages_backward(
                    stage_idx=stage_idx - 1,
                    upper_bound_idx=chosen[0],
                    anchor_event_idx=None,
                    window_start_ts=window_start_ts,
                    sorted_events=sorted_events,
                    stage_matches=stage_matches,
                    stage_explanations=stage_explanations,
                    collected_stage_events=collected_stage_events + [chosen],
                    match_field_values=new_mf,
                )

        # Non-final stages: filter candidates by already-bound match_fields
        valid_candidates = []
        for i in matching_indices:
            ev = sorted_events[i]
            consistent = True
            for mf in stage.match_fields:
                if mf in match_field_values:
                    if extract_field_value(ev, mf) != match_field_values[mf]:
                        consistent = False
                        break
            if consistent:
                valid_candidates.append(i)

        if len(valid_candidates) < stage.min_count:
            return None

        # Check if this stage introduces match_fields that are not yet bound
        unbound_mf = [mf for mf in stage.match_fields if mf not in match_field_values]
        if unbound_mf:
            # Group valid_candidates by unbound field values
            groups: dict[tuple[Any, ...], list[int]] = collections.defaultdict(list)
            for i in valid_candidates:
                ev = sorted_events[i]
                vals = tuple(extract_field_value(ev, mf) for mf in unbound_mf)
                if any(v is None for v in vals):
                    continue
                groups[vals].append(i)

            # Order groups by the timestamp of their latest event descending
            sorted_groups = sorted(
                groups.items(),
                key=lambda item: _get_event_timestamp(sorted_events[item[1][-1]]),
                reverse=True,
            )

            for vals, group_indices in sorted_groups:
                if len(group_indices) < stage.min_count:
                    continue
                chosen = group_indices[-stage.min_count:]
                new_mf = dict(match_field_values)
                for mf, v in zip(unbound_mf, vals):
                    new_mf[mf] = v

                res = self._resolve_stages_backward(
                    stage_idx=stage_idx - 1,
                    upper_bound_idx=chosen[0],
                    anchor_event_idx=None,
                    window_start_ts=window_start_ts,
                    sorted_events=sorted_events,
                    stage_matches=stage_matches,
                    stage_explanations=stage_explanations,
                    collected_stage_events=collected_stage_events + [chosen],
                    match_field_values=new_mf,
                )
                if res is not None:
                    return res
            return None

        # All match_fields already bound (or stage has no match_fields)
        # Take the most immediate min_count candidates (closest to upper_bound_idx)
        chosen = valid_candidates[-stage.min_count:]
        return self._resolve_stages_backward(
            stage_idx=stage_idx - 1,
            upper_bound_idx=chosen[0],
            anchor_event_idx=None,
            window_start_ts=window_start_ts,
            sorted_events=sorted_events,
            stage_matches=stage_matches,
            stage_explanations=stage_explanations,
            collected_stage_events=collected_stage_events + [chosen],
            match_field_values=dict(match_field_values),
        )

    def _build_sequence_match_payload(
        self,
        sorted_events: list[Any],
        collected_stage_events: list[list[int]],
        stage_explanations: dict[tuple[int, int], list[dict[str, Any]]],
        match_fields: dict[str, Any],
    ) -> dict[str, Any]:
        """Construct structured forensic match payload from chosen sequence events."""
        all_event_ids: list[uuid.UUID] = []
        stages_evidence = []
        all_matched_conditions: list[dict[str, Any]] = []

        first_event = sorted_events[collected_stage_events[0][0]]
        last_event = sorted_events[collected_stage_events[-1][-1]]
        first_ts = _get_event_timestamp(first_event)
        last_ts = _get_event_timestamp(last_event)

        for s_idx, event_indices in enumerate(collected_stage_events):
            stage = self.stages[s_idx]
            stage_eids = [_get_event_id(sorted_events[i]) for i in event_indices]
            all_event_ids.extend(stage_eids)

            stage_details = []
            for i in event_indices:
                stage_details.extend(stage_explanations.get((s_idx, i), []))
                all_matched_conditions.extend(stage_explanations.get((s_idx, i), []))

            stages_evidence.append({
                "stage_id": stage.stage_id,
                "event_count": len(event_indices),
                "event_ids": [str(eid) for eid in stage_eids],
                "matched_conditions": stage_details,
            })

        evidence = {
            "sequence_rule_id": self.rule.rule_id,
            "window_seconds": self.window_seconds,
            "actual_duration_seconds": max(0.0, (last_ts - first_ts).total_seconds()),
            "first_observed_at": first_ts.isoformat(),
            "last_observed_at": last_ts.isoformat(),
            "correlated_fields": match_fields,
            "stages": stages_evidence,
        }

        # Deduplicate matched condition entries for concise explainability
        seen_conds = set()
        dedup_conditions = []
        for c in all_matched_conditions:
            key = (c.get("field"), c.get("operator"), str(c.get("actual")), str(c.get("expected")))
            if key not in seen_conds:
                seen_conds.add(key)
                dedup_conditions.append(c)

        return {
            "rule_id": self.rule.rule_id,
            "rule_version": self.rule.version,
            "primary_event": last_event,
            "all_events": [sorted_events[i] for stage_idxs in collected_stage_events for i in stage_idxs],
            "triggering_event_ids": all_event_ids,
            "matched_conditions": {"conditions": dedup_conditions},
            "evidence": evidence,
            "timestamp": last_ts,
        }
