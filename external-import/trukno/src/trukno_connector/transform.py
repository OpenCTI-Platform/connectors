import uuid

from trukno_connector.opencti_compat import cleanup_bundle_for_opencti

STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def deterministic_stix_id(stix_type: str, key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(STIX_NAMESPACE, key)}"


def transform_breach_to_bundle(payload: dict) -> dict:
    published_at = payload["publishedAt"]
    report_id = deterministic_stix_id("report", payload["id"])
    object_refs = []
    objects = []

    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "name": payload["title"],
        "created": published_at,
        "modified": published_at,
        "published": published_at,
        "description": payload.get("summary", ""),
        "report_types": ["threat-report"],
        "object_refs": object_refs,
        "x_opencti_source": "trukno",
    }
    objects.append(report)

    for ttp in payload.get("relatedTTPs", []):
        attack_pattern_id = deterministic_stix_id("attack-pattern", ttp["id"])
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": attack_pattern_id,
                "name": ttp["title"],
            }
        )
        object_refs.append(attack_pattern_id)

    for malware in payload.get("relatedMalwares", []):
        malware_id = deterministic_stix_id("malware", malware["id"])
        objects.append(
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": malware_id,
                "name": malware["title"],
                "is_family": False,
            }
        )
        object_refs.append(malware_id)

    bundle = {
        "type": "bundle",
        "id": deterministic_stix_id("bundle", payload["id"]),
        "objects": objects,
    }
    return cleanup_bundle_for_opencti(bundle)
