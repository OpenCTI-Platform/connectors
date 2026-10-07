"""
Conversion of container markings and report types to MISP event tags.
"""

from typing import Dict, List, Optional, Set

# Container fields converted to MISP event tags
TAGGED_CONTAINER_FIELDS = ("object_marking_refs", "report_types")


def get_marking_tag(definition_type: str, name: str) -> Optional[str]:
    """
    Convert a marking definition to its MISP taxonomy tag.

    TLP markings are lowercased to match the MISP `tlp` taxonomy
    (e.g. "TLP:AMBER+STRICT" -> "tlp:amber+strict"). Other marking types
    (e.g. PAP) are expected to already be in "NAMESPACE:VALUE" format and
    are used as-is.

    :param definition_type: Marking definition type (e.g. "TLP", "PAP")
    :param name: Marking name / definition (e.g. "TLP:RED")
    :return: MISP tag or None
    """
    if not name:
        return None
    if (definition_type or "").upper() == "TLP":
        value = name.split(":", 1)[1] if ":" in name else name
        return f"tlp:{value.lower()}"
    return name


def build_marking_lookup(stix_bundle: Dict, allowlist: Set[str]) -> Dict[str, str]:
    """
    Map the marking definitions of a bundle to MISP tags.

    Marking definitions whose type is not in the allow-list are skipped.

    :param stix_bundle: STIX 2.1 bundle
    :param allowlist: Upper-cased marking definition types to convert
    :return: Dict of marking definition id -> MISP tag
    """
    lookup = {}
    for obj in stix_bundle.get("objects", []):
        if obj.get("type", "").lower() != "marking-definition":
            continue
        definition_type = obj.get("definition_type") or ""
        if definition_type.upper() not in allowlist:
            continue
        tag = get_marking_tag(definition_type, obj.get("name", ""))
        if tag:
            lookup[obj.get("id")] = tag
    return lookup


def get_previous_list_values(data: Dict, reverse_patch: List[Dict], key: str) -> List:
    """
    Rebuild the previous value of a list field of a STIX object by applying
    the reverse patch operations that target this field.

    Only the JSON Patch operations used by OpenCTI for list fields are
    supported: add, remove and replace, on the whole list or on an index.

    :param data: Current STIX object
    :param reverse_patch: Reverse JSON patch from the stream event context
    :param key: List field name (e.g. "object_marking_refs")
    :return: Previous list value
    """
    values = list(data.get(key) or [])
    field_path = f"/{key}"
    for operation in reverse_patch or []:
        path = operation.get("path", "")
        if path != field_path and not path.startswith(field_path + "/"):
            continue
        op = operation.get("op")
        index = path[len(field_path) + 1 :]
        if not index:
            if op in ("add", "replace"):
                values = list(operation.get("value") or [])
            elif op == "remove":
                values = []
            continue
        if op == "add" and index == "-":
            values.append(operation.get("value"))
            continue
        try:
            position = int(index)
        except ValueError:
            continue
        if op == "add":
            values.insert(position, operation.get("value"))
        elif op == "remove" and position < len(values):
            values.pop(position)
        elif op == "replace" and position < len(values):
            values[position] = operation.get("value")
    return values


def get_removed_container_values(data: Dict, context: Optional[Dict]) -> Dict:
    """
    Return the markings and report types removed from a container by an
    update event.

    :param data: Container STIX object of the update event
    :param context: Context of the update event (contains reverse_patch)
    :return: Dict of field name -> removed values (only non-empty fields)
    """
    reverse_patch = (context or {}).get("reverse_patch") or []
    removed = {}
    for key in TAGGED_CONTAINER_FIELDS:
        current = set(data.get(key) or [])
        previous = get_previous_list_values(data, reverse_patch, key)
        values = [
            value
            for value in previous
            if isinstance(value, str) and value not in current
        ]
        if values:
            removed[key] = values
    return removed
