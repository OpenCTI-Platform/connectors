MARKING = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
IDENTITY = "identity--17c7205f-adda-5b65-b038-d95eb68940d5"
IP_INDICATOR = "indicator--000b80fb-4813-518e-98bd-2004c4699f80"
URL_INDICATOR = "indicator--117be4a2-9aba-58e4-b949-98d2b173278d"
ATTACK_PATTERN = "attack-pattern--01f100ef-db56-55e4-93a6-465b12b58e64"
CVE = "vulnerability--11ef6fe7-8e3b-588d-9c44-3bd3020915ad"

COMMON = {
    "spec_version": "2.1",
    "created_by_ref": IDENTITY,
    "object_marking_refs": [MARKING],
    "modified": "2026-11-14T02:48:13.000Z",
}


def bundle(bundle_id: str = "bundle--c9ea85c4-9fbf-59af-968e-0789e17cf429") -> dict:
    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": [
            {"type": "identity", "id": IDENTITY, "name": "OffSeq"},
            {
                **COMMON,
                "type": "indicator",
                "id": IP_INDICATOR,
                "name": "Mirage attacker 192.0.2.10",
                "description": "Attacked 3 Mirage honeypots in 3 networks; services: ssh.",
                "pattern": "[ipv4-addr:value = '192.0.2.10']",
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "labels": ["ssh", "ssh-bruteforce"],
                "confidence": 46,
                "created": "2026-10-28T22:00:00.000Z",
                "valid_from": "2026-10-28T22:00:00.000Z",
                "valid_until": "2026-11-18T23:00:00.000Z",
            },
            {
                **COMMON,
                "type": "indicator",
                "id": URL_INDICATOR,
                "name": "Mirage download URL",
                "pattern": "[url:value = 'http://198.51.100.7:8001/x.sh']",
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "created": "2026-11-07T19:00:00.000Z",
                "valid_from": "2026-11-07T19:00:00.000Z",
            },
            {
                **COMMON,
                "type": "attack-pattern",
                "id": ATTACK_PATTERN,
                "name": "Exploit Public-Facing Application",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1190",
                        "url": "https://attack.mitre.org/techniques/T1190/",
                    }
                ],
            },
            {
                **COMMON,
                "type": "vulnerability",
                "id": CVE,
                "name": "CVE-2024-4577",
                "labels": ["cisa-kev"],
            },
            {
                **COMMON,
                "type": "relationship",
                "id": "relationship--000f0f27-c60e-5fab-ba1e-c84549fc860e",
                "relationship_type": "indicates",
                "source_ref": IP_INDICATOR,
                "target_ref": ATTACK_PATTERN,
            },
            {
                **COMMON,
                "type": "relationship",
                "id": "relationship--100f0f27-c60e-5fab-ba1e-c84549fc860e",
                "relationship_type": "related-to",
                "source_ref": IP_INDICATOR,
                "target_ref": CVE,
            },
        ],
    }
