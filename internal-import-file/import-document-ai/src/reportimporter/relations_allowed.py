"""Helpers for validating STIX relationships against the OpenCTI schema.

These utilities are used to:
- Fetch and normalize the OpenCTI relation type matrix.
- Normalize STIX object types into the keys OpenCTI expects.
- Check if a given relation is allowed between two STIX object types.
"""

from __future__ import annotations

from pycti import OpenCTIConnectorHelper


def load_allowed_relations(
    helper: OpenCTIConnectorHelper,
) -> dict[tuple[str, str], set[str]]:
    """Fetch and normalize the allowed relations matrix from OpenCTI.

    Returns a mapping of (FROM_TYPE, TO_TYPE) -> set of ALLOWED_RELATION_TYPES,
    all uppercased for case-insensitive lookup.
    """
    query = """
    query LoadRelationMapping {
      schemaRelationsTypesMapping {
        key
        values
      }
    }
    """
    data = (
        helper.api.query(query).get("data", {}).get("schemaRelationsTypesMapping", [])
    )
    mapping: dict[tuple[str, str], set[str]] = {}
    for entry in data:
        key = str(entry.get("key", ""))
        if "_" not in key:
            continue
        from_type, to_type = key.split("_", 1)
        values = entry.get("values") or []
        mapping[(from_type.upper(), to_type.upper())] = {str(v).upper() for v in values}
    return mapping


def stix_lookup_type(obj: dict[str, object] | None) -> str:
    """Return the normalized OpenCTI type key for a STIX object.

    Special cases:
    - Identity → returns its x_opencti_identity_type or identity_class
    - Location → returns its x_opencti_location_type
    - Others   → returns the STIX `type` field

    Returns an empty string if obj is None or type is missing.
    """
    if not obj:
        return ""
    stix_type = str(obj.get("type", "")).upper()
    if stix_type == "IDENTITY":
        identity_type = obj.get("x_opencti_identity_type") or obj.get("identity_class")
        return str(identity_type or "").upper()
    if stix_type == "LOCATION":
        return str(obj.get("x_opencti_location_type", "")).upper()
    if stix_type == "THREAT-ACTOR":
        actor_type = obj.get("x_opencti_identity_type")
        if actor_type:
            return f"THREAT-ACTOR-{actor_type.upper()}"
        return "THREAT-ACTOR-GROUP"
    return stix_type


def is_relation_allowed(
    allowed_relations: dict[tuple[str, str], set[str]],
    from_type: str,
    to_type: str,
    rel_type: str,
) -> bool:
    """Check whether a STIX relation is allowed between two object types.

    Args:
        allowed_relations: Pre-fetched relation mapping from load_allowed_relations().
        from_type: Source object type (case-insensitive).
        to_type: Target object type (case-insensitive).
        rel_type: Relation type to check (case-insensitive).

    Returns:
        True if rel_type is allowed for (from_type, to_type), else False.
    """
    if not rel_type:
        return False
    key = (str(from_type).upper(), str(to_type).upper())
    return str(rel_type).upper() in allowed_relations.get(key, set())
