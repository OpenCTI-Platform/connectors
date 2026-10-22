"""STIX conversion helpers shared by the connector base classes."""

import copy
import json
from typing import Any


def to_stix2_objects(objects: list[Any]) -> list[Any]:
    """Convert objects to stix2, calling ``to_stix2_object()`` when available.

    Connectors-sdk model instances are converted, while stix2 objects and
    plain STIX dicts are returned unchanged.

    Args:
        objects: A list of connectors-sdk model instances, stix2 objects or STIX dicts.

    Returns:
        A new list of stix2 objects or STIX dicts, in the same order.
    """
    return [
        obj.to_stix2_object() if hasattr(obj, "to_stix2_object") else obj
        for obj in objects
    ]


def to_stix_dict(obj: Any) -> dict[str, Any]:
    """Convert a connectors-sdk model, a stix2 object or a STIX dict to a new STIX dict.

    Args:
        obj: A connectors-sdk model instance, a stix2 object or a STIX dict.

    Returns:
        A STIX dict that does not share any mutable value with ``obj``.
    """
    if hasattr(obj, "to_stix2_object"):
        obj = obj.to_stix2_object()
    if hasattr(obj, "serialize"):
        stix_dict: dict[str, Any] = json.loads(obj.serialize())
        return stix_dict
    return copy.deepcopy(dict(obj))
