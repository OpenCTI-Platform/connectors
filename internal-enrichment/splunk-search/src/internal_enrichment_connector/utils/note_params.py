"""Parse and validate per-indicator parameters from OpenCTI Note content fields.

Note.content is expected to contain a YAML mapping.  The schema below lists
every recognised field; unknown fields are warned about (likely typos) and
silently dropped so that callers always receive a clean, type-safe dict.

Usage::

    from internal_enrichment_connector.utils.note_params import load_note_params

    params = load_note_params(note["content"])
    earliest = params.get("earliest", "-30d@d")
"""

from __future__ import annotations

import logging
import re

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

NOTE_SCHEMA: dict[str, dict] = {
    "earliest": {
        "type": str,
        "description": "Splunk earliest_time (e.g., -30d@d, -24h@h, 2024-01-01T00:00:00)",
    },
    "latest": {
        "type": str,
        "description": "Splunk latest_time (e.g., now, -1h@h)",
    },
    "max_results": {
        "type": int,
        "description": "Maximum rows to return from Splunk",
    },
    "fields": {
        "type": list,
        "description": "List of CIM fields to extract",
    },
    "index": {
        "type": str,
        "description": "Splunk index override",
    },
    "sourcetype": {
        "type": str,
        "description": "Splunk sourcetype filter",
    },
    "timeout": {
        "type": int,
        "description": "Search timeout in seconds",
    },
    # Internal / legacy fields that SplunkIndicator.render() reads directly
    "search": {
        "type": str,
        "description": "Raw SPL override — replaces the template-based search entirely",
    },
    "index_scope": {
        "type": str,
        "description": "Full index expression used verbatim in the SPL query (e.g., index=security)",
    },
    "observable_field": {
        "type": str,
        "description": "Override the field name used to match the observable value",
    },
    "observable_type": {
        "type": str,
        "description": "Override the observable type label",
    },
    "wait_seconds": {
        "type": int,
        "description": "Seconds to wait between Splunk job status polls",
    },
    # Backwards-compat aliases (normalised in _build_search_plan before validation)
    "earliest_time": {
        "type": str,
        "description": "Alias for 'earliest' (deprecated — use 'earliest')",
    },
    "latest_time": {
        "type": str,
        "description": "Alias for 'latest' (deprecated — use 'latest')",
    },
}

KNOWN_NOTE_FIELDS: frozenset[str] = frozenset(NOTE_SCHEMA.keys())


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_note_params(content: str) -> dict:
    """Parse YAML parameters from a Note content field.

    Returns an empty dict when *content* is blank or not a YAML mapping.
    Never raises — parsing errors are logged as warnings.
    """
    if not content or not content.strip():
        return {}
    try:
        # Strip HTML tags (e.g. content wrapped by the OpenCTI rich-text editor)
        cleaned = re.sub(r"<[^>]+>", "\n", content)
        # Strip Markdown code fences (```yaml, ```json, ``` …)
        cleaned = re.sub(r"^```[\w]*\s*", "", cleaned.strip(), flags=re.MULTILINE)
        cleaned = re.sub(r"^```\s*$", "", cleaned, flags=re.MULTILINE)
        cleaned = cleaned.strip()
        parsed = yaml.safe_load(cleaned)
        if not isinstance(parsed, dict):
            logger.warning(
                "[NOTE] Note content is not a YAML mapping, ignoring: %s",
                type(parsed).__name__,
            )
            return {}
        return parsed
    except yaml.YAMLError as exc:
        logger.warning(
            "[NOTE] Failed to parse Note content as YAML: %s — raw content preview: %r",
            exc,
            content[:200],
        )
        return {}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_note_params(params: dict) -> dict:
    """Validate Note params against the schema.

    Unknown fields and fields with wrong types are warned about and dropped.
    Only fields listed in *NOTE_SCHEMA* are returned.
    """
    validated: dict = {}

    unknown = set(params.keys()) - KNOWN_NOTE_FIELDS
    if unknown:
        logger.warning(
            "[NOTE] Unknown fields in Note params (ignored): %s — " "Valid fields: %s",
            sorted(unknown),
            sorted(KNOWN_NOTE_FIELDS),
        )

    for key in KNOWN_NOTE_FIELDS:
        if key not in params:
            continue
        expected_type = NOTE_SCHEMA[key]["type"]
        value = params[key]
        if not isinstance(value, expected_type):
            logger.warning(
                "[NOTE] Field '%s' expected %s, got %s (%r) — ignoring",
                key,
                expected_type.__name__,
                type(value).__name__,
                value,
            )
            continue
        validated[key] = value

    return validated


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------


def load_note_params(content: str) -> dict:
    """Parse YAML from Note content and validate against the schema.

    This is the single function all enrichment paths should call.
    Returns a clean dict of validated params (possibly empty).
    """
    raw = parse_note_params(content)
    if not raw:
        logger.debug("[NOTE] No params found in Note, using connector defaults")
        return {}
    validated = validate_note_params(raw)
    if validated:
        logger.debug("[NOTE] Parsed params from Note: %s", sorted(validated.keys()))
    return validated
