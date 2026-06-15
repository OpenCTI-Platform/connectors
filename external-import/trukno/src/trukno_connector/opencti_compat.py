import copy

ALLOWED_RELATIONSHIP_TYPES = {"uses", "targets", "indicates", "related-to"}


def cleanup_bundle_for_opencti(bundle: dict) -> dict:
    cleaned_bundle = copy.deepcopy(bundle)
    cleaned_objects = []
    for obj in cleaned_bundle.get("objects", []):
        if obj.get("type") == "relationship":
            if obj.get("relationship_type") not in ALLOWED_RELATIONSHIP_TYPES:
                continue
        for key in list(obj.keys()):
            if key.startswith("x_") and not key.startswith("x_opencti_"):
                obj.pop(key)
        cleaned_objects.append(obj)
    cleaned_bundle["objects"] = cleaned_objects
    return cleaned_bundle
