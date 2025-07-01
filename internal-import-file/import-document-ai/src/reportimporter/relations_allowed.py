from pycti import OpenCTIConnectorHelper

_ALLOWED: dict[tuple[str, str], set[str]] = {}


def load_allowed_relations(helper: OpenCTIConnectorHelper) -> None:
    """Loads allowed relationship mappings into global cache.

    Loads allowed relationship mappings from the OpenCTI GraphQL API
    into the global _ALLOWED dictionary.

    Each key in _ALLOWED is a tuple of (from_type, to_type), and the value
    is a set of allowed relationship types (all uppercased).

    Args:
        helper (OpenCTIConnectorHelper): The connector helper to query OpenCTI.
    """
    q = """
    query LoadRelationMapping {
      schemaRelationsTypesMapping {
        key
        values
      }
    }
    """
    data = helper.api.query(q)["data"]["schemaRelationsTypesMapping"]
    for entry in data:
        # key comes as "FromType_ToType"
        key = entry["key"].upper()
        from_type, to_type = key.split("_", 1)
        _ALLOWED[(from_type, to_type)] = {v.upper() for v in entry["values"]}


def stix_lookup_type(obj: dict[str, object] | None) -> str:
    """Given a STIX object dict from pycti, return the key used
    in OpenCTI’s schemaRelationsTypesMapping.

    - For identity objects, prefer x_opencti_identity_type over identity_class.
    - For location objects, use x_opencti_location_type.
    - Otherwise, use the upper-cased STIX type.

    Args:
        obj (dict[str, object] | None): STIX object dict or None

    Returns:
        str: A normalized type name used for relationship validation.
    """
    if not obj:
        return ""
    t = str(obj.get("type", "")).upper()
    if t == "IDENTITY":
        return str(
            obj.get("x_opencti_identity_type") or obj.get("identity_class") or ""
        ).upper()
    if t == "LOCATION":
        return str(obj.get("x_opencti_location_type", "")).upper()
    return t


def is_relation_allowed(from_type: str, to_type: str, rel_type: str) -> bool:
    """Determines whether a given STIX relationship type is allowed between two object types.

    Args:
        from_type (str): The source object's normalized STIX/OpenCTI type.
        to_type (str): The target object's normalized STIX/OpenCTI type.
        rel_type (str): The STIX relationship type.

    Returns:
        bool: True if the relationship is allowed, False otherwise.
    """
    return rel_type.upper() in _ALLOWED.get((from_type.upper(), to_type.upper()), set())
