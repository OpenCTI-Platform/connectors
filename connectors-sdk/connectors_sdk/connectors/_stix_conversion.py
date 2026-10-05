"""STIX conversion helpers shared by the connector base classes."""

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
