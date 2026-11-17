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
- Ids without a prefix (community sources such as ``malpedia_...``) were only
  seen on malware families and software toolkits, but the API does not promise
  it: their type is unknown, so every association call is made.
- Descriptors stop at 20: when a cursor is present or the block holds 20
  descriptors, the list may be incomplete and the call is always made.
- When the descriptors are missing (no ``relationships`` in the response), the
  call is always made.
- The list call only asks for the relationships that the configured
  sub-entity types can use.
"""

from typing import Any

ATTACK_TECHNIQUES = "attack_techniques"
ASSOCIATIONS = "associations"
INLINE_DESCRIPTOR_LIMIT = 20

UNPREFIXED = ""

ASSOCIATION_PREFIXES: dict[str, set[str]] = {
    "malware_families": {"malware"},
    "software_toolkits": {"malware", "software-toolkit"},
    "threat_actors": {"threat-actor"},
    "vulnerabilities": {"vulnerability"},
    "campaigns": {"campaign"},
    "reports": {"report"},
}


def inline_relationships_param(subentity_types: list[str] | None) -> str | None:
    """Return the ``relationships`` value for a list call, or None to omit it.

    Args:
        subentity_types: Sub-entity types configured for the collection type, or
            None when unknown (then both relationships are asked for).

    Returns:
        The comma-separated relationships that can predict a configured
        sub-entity call, or None when no configured call can be predicted.

    """
    if subentity_types is None:
        return f"{ASSOCIATIONS},{ATTACK_TECHNIQUES}"
    needed = []
    if any(t in ASSOCIATION_PREFIXES for t in subentity_types):
        needed.append(ASSOCIATIONS)
    if ATTACK_TECHNIQUES in subentity_types:
        needed.append(ATTACK_TECHNIQUES)
    return ",".join(needed) or None


def _get_relationship(relationships: Any, name: str) -> Any:
    """Return one relationship block, from a dict or an object."""
    if isinstance(relationships, dict):
        return relationships.get(name)
    return getattr(relationships, name, None)


def _block_items(block: Any) -> tuple[list[Any], bool]:
    """Return the descriptors of a relationship block and whether it is complete.

    A block whose ``data`` is missing, null or not a list proves nothing, so it
    is reported as incomplete and the call is kept. GTI sends ``"data": []``
    for a relationship that is really empty. A block with a cursor or with
    ``INLINE_DESCRIPTOR_LIMIT`` descriptors may be truncated, so it is reported
    as incomplete too.
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
    return list(data), not cursor and len(data) < INLINE_DESCRIPTOR_LIMIT


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

    if subentity_type == ATTACK_TECHNIQUES:
        block = _get_relationship(relationships, ATTACK_TECHNIQUES)
        if block is None:
            return True
        items, complete = _block_items(block)
        return bool(items) or not complete

    expected_prefixes = ASSOCIATION_PREFIXES.get(subentity_type)
    if expected_prefixes is None:
        return True

    block = _get_relationship(relationships, ASSOCIATIONS)
    if block is None:
        return True
    items, complete = _block_items(block)
    if not complete:
        return True
    prefixes = {_descriptor_prefix(item) for item in items}
    if UNPREFIXED in prefixes:
        return True
    return not prefixes.isdisjoint(expected_prefixes)
