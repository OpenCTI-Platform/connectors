import re
from collections.abc import Mapping
from typing import Any, Literal

ActorEntityType = Literal[
    "Threat-Actor-Individual", "Threat-Actor-Group", "Intrusion-Set", "Malware"
]


def infer_actor_entity_type(actor: Mapping[str, Any]) -> ActorEntityType:
    name_candidate = actor.get("handle")
    if name_candidate in (None, ""):
        name_candidate = actor.get("name")
    if name_candidate in (None, ""):
        name_candidate = actor.get("uid")
    if name_candidate in (None, ""):
        name_candidate = ""
    name = str(name_candidate)
    normalized_name = name.lower().strip()

    hint_values: list[str] = []
    for key in (
        "entity_type",
        "entityType",
        "type",
        "actor_type",
        "actorType",
        "category",
        "classification",
    ):
        value = actor.get(key)
        if isinstance(value, str) and value.strip():
            hint_values.append(value.lower().strip())
    hints_blob = " ".join(hint_values + [normalized_name])

    if (
        "intrusion-set" in hints_blob
        or "intrusion set" in hints_blob
        or bool(re.search(r"\bapt(?:\d+)?\b", hints_blob))
        or normalized_name.startswith("apt")
    ):
        return "Intrusion-Set"

    if "malware" in hints_blob or "ransomware" in hints_blob:
        return "Malware"

    if (
        "threat-actor-group" in hints_blob
        or "threat actor group" in hints_blob
        or " actor group" in hints_blob
        or normalized_name.endswith(" group")
        or normalized_name.endswith(" gang")
        or normalized_name.endswith(" crew")
    ):
        return "Threat-Actor-Group"

    return "Threat-Actor-Individual"
