"""OSIRIS Detection Engine & Security Rules Foundation (Phase 2 Milestone 2.4)."""

from backend.services.detection.engine import DetectionEngine, compute_dedup_hash
from backend.services.detection.matcher import evaluate_condition_node, extract_field_value
from backend.services.detection.models import (
    ConditionNode,
    DetectionMatch,
    RuleDefinition,
    RuleValidationError,
    SequenceDefinition,
    SequenceStage,
)
from backend.services.detection.rules_loader import load_rules_from_directory
from backend.services.detection.sequence import SequenceMatcher
from backend.services.detection.service import DetectionService
from backend.services.detection.validator import validate_rule_dict, validate_rule_yaml

__all__ = [
    "ConditionNode",
    "DetectionEngine",
    "DetectionMatch",
    "DetectionService",
    "RuleDefinition",
    "RuleValidationError",
    "SequenceDefinition",
    "SequenceMatcher",
    "SequenceStage",
    "compute_dedup_hash",
    "evaluate_condition_node",
    "extract_field_value",
    "load_rules_from_directory",
    "validate_rule_dict",
    "validate_rule_yaml",
]
