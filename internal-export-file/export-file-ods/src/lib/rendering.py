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
# tuple of keys.
#
# * **Composite** strategies (more than one key) only match when **every**
#   key in the tuple is populated on the dict. A partial match falls
#   through to the next strategy so a dict that only carries a lone
#   ``source_name`` (no ``url``) does not collapse to that one field
#   while a more specific complete shape further down the table would
#   have produced a richer rendering.
# * **Single-key** strategies match when the one key is populated.
#
# Order matters: more specific composites (``source_name``+``url``,
# ``kill_chain_name``+``phase_name``) come first so they render the
# information operators expect (``MITRE ATT&CK: https://...``,
# ``mitre-attack:execution``) when both keys are present. Partial
# composites then fall through to the single-key fallbacks
# (``("url",)`` / ``("source_name",)``) at the bottom of the table so
# the dict still produces a non-empty cell.
DICT_ITEM_STRATEGIES: Tuple[Tuple[str, ...], ...] = (
    ("source_name", "url"),
    ("kill_chain_name", "phase_name"),
    ("name",),
    ("definition",),
    ("value",),
    ("observable_value",),
    ("url",),
    ("source_name",),
    ("phase_name",),
    ("kill_chain_name",),
)


def render_dict_item(item: Any) -> str:
    """Render a single dict from a list-of-dict cell.

    Tries :data:`DICT_ITEM_STRATEGIES` in order. Composite strategies
    require **every** key in the tuple to be populated on the dict — a
    partial match falls through to the next strategy. Composite values
    are joined with ``": "`` except for kill-chain phases which use
    ``":"`` to keep the canonical ``mitre-attack:execution`` form.
    Single-key strategies match when their one key is populated.

    Falls back to a stable ``json.dumps`` rendering of the dict so
    unsupported shapes (custom enrichment payloads, dicts without any of
    the recognised keys) are still exported instead of silently producing
    an empty cell.
    """
    if not isinstance(item, dict):
        return sanitize_cell(item)
    for strategy in DICT_ITEM_STRATEGIES:
        present = [k for k in strategy if item.get(k) not in (None, "")]
        if len(present) != len(strategy):
            # Composite strategies require **all** keys; partial matches
            # fall through to the next (more specific) strategy in the
            # table so we never collapse a richer dict to a partial
            # composite.
            continue
        if len(strategy) == 1:
            return sanitize_cell(item[strategy[0]])
        if strategy == ("kill_chain_name", "phase_name"):
            return sanitize_cell(f"{item['kill_chain_name']}:{item['phase_name']}")
        return sanitize_cell(": ".join(str(item[k]) for k in strategy))
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
