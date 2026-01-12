from __future__ import annotations

import uuid
from typing import Any, Iterable


def dedupe_objects(objects: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
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
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": list(objects),
    }
