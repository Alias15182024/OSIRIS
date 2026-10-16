"""OSIRIS desktop UI package."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from desktop.ui import design_tokens


def get_token_replacements() -> dict[str, str]:
    """Build token dictionary mapping placeholder keys to design token values."""
    replacements: dict[str, str] = {}
    for name in dir(design_tokens):
        if name.isupper():
            val = getattr(design_tokens, name)
            if isinstance(val, (str, int, float)):
                str_val = str(val)
                replacements[name] = str_val
                replacements[name.lower()] = str_val
                no_underscores = name.replace("_", "")
                replacements[no_underscores] = str_val
                replacements[no_underscores.lower()] = str_val

    # Also register structured aliases from token containers
    alias_mappings = (
        design_tokens.SURFACES,
        design_tokens.TEXT,
        design_tokens.ACCENTS,
        design_tokens.SEVERITY,
        design_tokens.STATUS,
        design_tokens.METRICS,
        design_tokens.RADII,
        design_tokens.SPACING,
    )
    for container in alias_mappings:
        for key in container:
            try:
                val = container[key]
                if isinstance(val, (str, int, float)):
                    str_val = str(val)
                    k_str = str(key)
                    replacements[k_str] = str_val
                    replacements[k_str.upper()] = str_val
                    replacements[k_str.lower()] = str_val
            except Exception:
                continue

    return replacements


def substitute_tokens(
    template: str,
    replacements: Mapping[str, Any] | None = None,
) -> str:
    """Substitute {{TOKEN}} and @TOKEN@ placeholders with design token values.

    Args:
        template: QSS template string containing placeholders.
        replacements: Optional mapping of token names to string values. If not
            provided, all uppercase constants from desktop.ui.design_tokens are used.

    Returns:
        Deterministic stylesheet string with all placeholders replaced.

    Raises:
        TypeError: If template is not a string.
    """
    if not isinstance(template, str):
        raise TypeError(f"Template must be a string, got {type(template).__name__}")

    token_map = replacements if replacements is not None else get_token_replacements()

    def replace_token(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        if key in token_map:
            return str(token_map[key])
        key_upper = key.upper()
        if key_upper in token_map:
            return str(token_map[key_upper])
        key_lower = key.lower()
        if key_lower in token_map:
            return str(token_map[key_lower])
        norm = key.replace("-", "_")
        if norm in token_map:
            return str(token_map[norm])
        if norm.upper() in token_map:
            return str(token_map[norm.upper()])
        if norm.lower() in token_map:
            return str(token_map[norm.lower()])
        return match.group(0)

    # Match {{ TOKEN }} or {{TOKEN}} or {{TOKEN-NAME}}
    result = re.sub(r"\{\{\s*([A-Za-z0-9_-]+)\s*\}\}", replace_token, template)
    # Match @TOKEN@ or @TOKEN-NAME@
    result = re.sub(r"@([A-Za-z0-9_-]+)@", replace_token, result)
    return result


def get_stylesheet_path() -> Path:
    """Locate desktop/assets/style.qss reliably using package-relative resolution.

    Returns:
        Path to desktop/assets/style.qss.

    Raises:
        FileNotFoundError: If desktop/assets/style.qss does not exist.
    """
    style_path = Path(__file__).resolve().parent.parent / "assets" / "style.qss"
    if not style_path.is_file():
        raise FileNotFoundError(
            f"OSIRIS desktop stylesheet asset not found at expected path: {style_path}"
        )
    return style_path


def load_stylesheet(token_overrides: Mapping[str, Any] | None = None) -> str:
    """Load, substitute design tokens, and return the OSIRIS desktop stylesheet.

    Locates desktop/assets/style.qss reliably from the package location,
    injects centralized tokens from desktop.ui.design_tokens (with optional
    token overrides), and returns the deterministic QSS stylesheet string.

    Args:
        token_overrides: Optional mapping of token names to override values.

    Returns:
        The fully-rendered OSIRIS QSS stylesheet string.

    Raises:
        FileNotFoundError: If desktop/assets/style.qss cannot be located.
    """
    style_path = get_stylesheet_path()
    raw_content = style_path.read_text(encoding="utf-8")
    tokens = get_token_replacements()
    if token_overrides:
        for k, v in token_overrides.items():
            str_val = str(v)
            k_raw = str(k).strip()
            tokens[k_raw] = str_val
            tokens[k_raw.upper()] = str_val
            tokens[k_raw.lower()] = str_val
            k_underscores = k_raw.replace("-", "_")
            tokens[k_underscores] = str_val
            tokens[k_underscores.upper()] = str_val
            tokens[k_underscores.lower()] = str_val
            k_no_underscores = k_underscores.replace("_", "")
            tokens[k_no_underscores] = str_val
            tokens[k_no_underscores.upper()] = str_val
            tokens[k_no_underscores.lower()] = str_val
    return substitute_tokens(raw_content, tokens)


get_stylesheet = load_stylesheet

__all__ = [
    "get_stylesheet",
    "get_stylesheet_path",
    "get_token_replacements",
    "load_stylesheet",
    "substitute_tokens",
]
