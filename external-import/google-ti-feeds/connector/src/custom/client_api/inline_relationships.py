"""Predict empty sub-entity calls from inline relationship descriptors.

The collection list call is made with ``relationships=associations,attack_techniques``.
GTI then returns, for each collection, up to 20 relationship descriptors
(``{"type": "collection", "id": "..."}``) at no extra quota cost. Reading them
tells whether a sub-entity call (``/collections/{id}/{type}``) would come back
empty, so that call can be skipped.

Reading rules, checked against the API in November 2026:

- An id prefix gives the collection type: ``threat-actor--``, ``campaign--``,
  ``vulnerability--``, ``report--``.
- ``malware--`` is used for malware families AND software toolkits.
- Ids without a prefix (community sources such as ``malpedia_...``) can be a
  malware family or a software toolkit.
- Descriptors stop at 20: when a cursor is present, the list is incomplete and
  the call is always made.
- When the descriptors are missing (no ``relationships`` in the response), the
  call is always made.
"""

from typing import Any

INLINE_RELATIONSHIPS_PARAM = "associations,attack_techniques"

UNPREFIXED = ""

ASSOCIATION_PREFIXES: dict[str, set[str]] = {
    "malware_families": {"malware", UNPREFIXED},
    "software_toolkits": {"malware", "software-toolkit", UNPREFIXED},
    "threat_actors": {"threat-actor"},
    "vulnerabilities": {"vulnerability"},
    "campaigns": {"campaign"},
    "reports": {"report"},
}


def _get_relationship(relationships: Any, name: str) -> Any:
    """Return one relationship block, from a dict or an object."""
    if isinstance(relationships, dict):
        return relationships.get(name)
    return getattr(relationships, name, None)


def _block_items(block: Any) -> tuple[list[Any], bool]:
    """Return the descriptors of a relationship block and whether it is complete.

    A block whose ``data`` is missing, null or not a list proves nothing, so it
    is reported as incomplete and the call is kept. GTI sends ``"data": []``
    for a relationship that is really empty.
    """
    if isinstance(block, dict):
        data = block.get("data")
        meta = block.get("meta") or {}
    else:
        data = getattr(block, "data", None)
        meta = getattr(block, "meta", None) or {}
    if not isinstance(data, list):
        return [], False
    cursor = meta.get("cursor") if isinstance(meta, dict) else None
    return list(data), not cursor


def _descriptor_prefix(descriptor: Any) -> str:
    """Return the type prefix of a descriptor id (empty when there is none)."""
    descriptor_id = descriptor.get("id") if isinstance(descriptor, dict) else descriptor
    if not isinstance(descriptor_id, str) or "--" not in descriptor_id:
        return UNPREFIXED
    return descriptor_id.split("--", 1)[0]


def is_subentity_call_needed(subentity_type: str, relationships: Any) -> bool:
    """Tell whether a sub-entity call can return data, from inline descriptors.

    Args:
        subentity_type: Sub-entity type of the call (``malware_families``...).
        relationships: The ``relationships`` object of the collection, or None.

    Returns:
        False only when the descriptors prove the call would return nothing.

    """
    if not relationships:
        return True

    if subentity_type == "attack_techniques":
        block = _get_relationship(relationships, "attack_techniques")
        if block is None:
            return True
        items, complete = _block_items(block)
        return bool(items) or not complete

    expected_prefixes = ASSOCIATION_PREFIXES.get(subentity_type)
    if expected_prefixes is None:
        return True

    block = _get_relationship(relationships, "associations")
    if block is None:
        return True
    items, complete = _block_items(block)
    if not complete:
        return True
    return any(_descriptor_prefix(item) in expected_prefixes for item in items)
