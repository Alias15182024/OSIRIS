"""Declarative detection rules file loader and registry.

Safely loads YAML rule definitions from disk and validates schema constraints.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Sequence

from backend.services.detection.models import RuleDefinition, RuleValidationError
from backend.services.detection.validator import validate_rule_yaml

logger = logging.getLogger("osiris.services.detection.loader")

RULES_DIR = Path(__file__).resolve().parent / "rules"


def load_rules_from_directory(directory: Path | str | None = None) -> list[RuleDefinition]:
    """Load and validate all YAML rules from the specified directory.

    If directory is None, defaults to `backend/services/detection/rules/`.
    Returns list of validated RuleDefinition objects.
    """
    rule_dir = Path(directory) if directory is not None else RULES_DIR
    if not rule_dir.exists() or not rule_dir.is_dir():
        logger.warning(f"Detection rules directory not found: {rule_dir}")
        return []

    rules: list[RuleDefinition] = []
    seen_ids: dict[str, Path] = {}

    # Sort files for deterministic loading order
    rule_files = sorted(list(rule_dir.glob("*.yaml")) + list(rule_dir.glob("*.yml")))

    for fpath in rule_files:
        try:
            content = fpath.read_text(encoding="utf-8")
            rule = validate_rule_yaml(content)

            if rule.rule_id in seen_ids:
                raise RuleValidationError(
                    f"Duplicate rule_id '{rule.rule_id}' found in '{fpath.name}' (already defined in '{seen_ids[rule.rule_id].name}')."
                )

            seen_ids[rule.rule_id] = fpath
            rules.append(rule)
            logger.debug(f"Loaded detection rule '{rule.rule_id}' from {fpath.name}")
        except Exception as exc:
            logger.error(f"Failed to load rule from {fpath.name}: {exc}")
            raise RuleValidationError(f"Error loading rule file '{fpath.name}': {exc}") from exc

    return rules
