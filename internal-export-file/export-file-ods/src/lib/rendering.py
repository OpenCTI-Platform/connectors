"""Cell rendering helpers for list-of-dict OpenCTI fields.

This module is intentionally dependency-free (no ``unogenerator`` / no
``pycti``) so the rendering of list-of-dict cells can be unit-tested
without LibreOffice being available on the CI runner.
"""

import json
from typing import Any, Tuple

from lib.sanitization import sanitize_cell

# Order-sensitive list of strategies used by :func:`render_dict_item` to
# extract a human-readable string from a list-of-dict cell. Each entry is a
# tuple of keys; the first strategy whose key set is a subset of the dict
# (and whose values are non-empty) is used.
#
# Order matters: more specific composites (``source_name``+``url``,
# ``kill_chain_name``+``phase_name``) come first so they render the
# information operators expect (``MITRE ATT&CK: https://...``,
# ``mitre-attack:execution``) instead of falling back to a less informative
# single field.
DICT_ITEM_STRATEGIES: Tuple[Tuple[str, ...], ...] = (
    ("source_name", "url"),
    ("kill_chain_name", "phase_name"),
    ("name",),
    ("definition",),
    ("value",),
    ("observable_value",),
    ("url",),
    ("source_name",),
)


def render_dict_item(item: Any) -> str:
    """Render a single dict from a list-of-dict cell.

    Tries :data:`DICT_ITEM_STRATEGIES` in order. Composite strategies
    (more than one key) are joined with ``": "`` except for kill-chain
    phases which use ``":"`` to keep the canonical ``mitre-attack:execution``
    form. Falls back to a stable ``json.dumps`` rendering of the dict so
    unsupported shapes (custom enrichment payloads, dicts without any of
    the recognised keys) are still exported instead of silently producing
    an empty cell.
    """
    if not isinstance(item, dict):
        return sanitize_cell(item)
    for strategy in DICT_ITEM_STRATEGIES:
        present = [k for k in strategy if item.get(k) not in (None, "")]
        if not present:
            continue
        if len(present) == 1:
            return sanitize_cell(item[present[0]])
        if strategy == ("kill_chain_name", "phase_name"):
            return sanitize_cell(f"{item['kill_chain_name']}:{item['phase_name']}")
        return sanitize_cell(": ".join(str(item[k]) for k in present))
    try:
        return sanitize_cell(
            json.dumps(item, sort_keys=True, default=str, ensure_ascii=False)
        )
    except (TypeError, ValueError):
        return sanitize_cell(str(item))


def render_dict_list(items: Any) -> str:
    """Render a list of dicts as a comma-separated cell.

    Empty rendered values are skipped to avoid trailing / repeated commas
    when an item produces no output.
    """
    if not isinstance(items, list) or not items:
        return ""
    rendered = [render_dict_item(item) for item in items]
    return ",".join(part for part in rendered if part)


__all__ = ("DICT_ITEM_STRATEGIES", "render_dict_item", "render_dict_list")
