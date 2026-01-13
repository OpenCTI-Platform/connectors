from __future__ import annotations

"""STIX bundle helpers.

`pycti` expects a STIX2 bundle as a JSON string/bytes. This module builds the
in-memory bundle object; callers may serialize to JSON as needed.

Notes:
- Object IDs should be deterministic (see `checkfirst_dataset.stix_ids`). Bundles
    themselves are transport containers, so their IDs can be random.
"""

import uuid
from typing import Any, Iterable


def dedupe_objects(objects: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate objects by STIX `id`, preserving the first occurrence."""
    dedup: dict[str, dict[str, Any]] = {}
    out: list[dict[str, Any]] = []
    for obj in objects:
        obj_id = obj.get("id")
        if isinstance(obj_id, str) and obj_id in dedup:
            continue
        if isinstance(obj_id, str):
            dedup[obj_id] = obj
        out.append(obj)
    return out


def make_bundle(objects: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Create a minimal STIX2 bundle dict for transport."""
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": list(objects),
    }
