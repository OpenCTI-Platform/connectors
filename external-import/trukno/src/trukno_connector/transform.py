import uuid

from trukno_connector.opencti_compat import cleanup_bundle_for_opencti

STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# attack-pattern / malware objects are shared reference entities keyed by their
# own stable id, so the same TTP/malware can be referenced by many breaches. Their
# created/modified must therefore be stable too: deriving them from each enclosing
# breach's publishedAt would emit the same STIX id with different timestamps,
# making OpenCTI flip-flop the object on every ingest. Use a fixed reference
# timestamp so a given id always produces an identical object.
REFERENCE_OBJECT_TIMESTAMP = "1970-01-01T00:00:00Z"


def deterministic_stix_id(stix_type: str, key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(STIX_NAMESPACE, key)}"


def transform_breach_to_bundle(payload: dict) -> dict:
    object_refs = []
    objects = []

    for ttp in payload.get("relatedTTPs", []):
        attack_pattern_id = deterministic_stix_id("attack-pattern", ttp["id"])
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": attack_pattern_id,
                "created": REFERENCE_OBJECT_TIMESTAMP,
                "modified": REFERENCE_OBJECT_TIMESTAMP,
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
                "created": REFERENCE_OBJECT_TIMESTAMP,
                "modified": REFERENCE_OBJECT_TIMESTAMP,
                "name": malware["title"],
                "is_family": False,
                "malware_types": ["unknown"],
            }
        )
        object_refs.append(malware_id)

    # STIX 2.1 requires report.object_refs to reference at least one object, so
    # only emit the report when the breach has at least one linkable
    # attack-pattern/malware. Breaches with neither carry no graph value in this
    # connector's current scope; the caller skips the resulting empty bundle.
    if object_refs:
        published_at = payload["publishedAt"]
        report = {
            "type": "report",
            "spec_version": "2.1",
            "id": deterministic_stix_id("report", payload["id"]),
            "name": payload["title"],
            "created": published_at,
            "modified": published_at,
            "published": published_at,
            "description": payload.get("summary", ""),
            "report_types": ["threat-report"],
            "object_refs": object_refs,
        }
        objects.insert(0, report)

    bundle = {
        "type": "bundle",
        "id": deterministic_stix_id("bundle", payload["id"]),
        "objects": objects,
    }
    return cleanup_bundle_for_opencti(bundle)
