from unittest.mock import MagicMock

import pycti
from threatmatch.converter import Converter


def _build_converter(threat_actor_to_intrusion_set: bool = False) -> Converter:
    return Converter(
        helper=MagicMock(),
        author_name="ThreatMatch",
        author_description="ThreatMatch Description",
        tlp_level="amber",
        threat_actor_to_intrusion_set=threat_actor_to_intrusion_set,
    )


INDICATOR_ID = "indicator--01234567-89ab-cdef-0123-456789abcdef"


def test_converter_keeps_source_labels_and_extracts_external_references() -> None:
    converter = _build_converter()
    stix_object = {
        "type": "threat-actor",
        "id": "threat-actor--01234567-89ab-cdef-0123-456789abcdef",
        "created": "2025-05-27T15:29:48.000Z",
        "modified": "2026-07-30T13:12:12.000Z",
        "name": "Void Blizzard",
        "description": (
            "<h2>Overview</h2>"
            '<p>Report <a href="https://example.org/report">Source</a>.</p>'
        ),
        # ThreatMatch already ships countries/sectors/motivations as labels.
        "labels": [
            "Espionage",
            "Russia",
            "Aerospace, defence & security",
            " ",
            "Russia",
        ],
    }

    converted = list(converter.process(stix_object))
    assert len(converted) == 1
    main_object = converted[0]

    assert "first_seen" not in main_object
    assert "<a href" not in main_object["description"]
    assert "## Overview" in main_object["description"]
    assert "[Source](https://example.org/report)" in main_object["description"]
    assert main_object["external_references"] == [
        {"source_name": "example.org", "url": "https://example.org/report"}
    ]
    # Deduplicated, blank-stripped, and compound sector names left intact.
    assert main_object["labels"] == [
        "Espionage",
        "Russia",
        "Aerospace, defence & security",
    ]


def test_converter_links_indicators_for_threat_actor_profiles() -> None:
    converter = _build_converter()
    stix_object = {
        "type": "threat-actor",
        "id": "threat-actor--01234567-89ab-cdef-0123-456789abcdef",
        "created": "2025-05-27T15:29:48.000Z",
        "modified": "2026-07-30T13:12:12.000Z",
        "name": "Void Blizzard",
        "object_refs": [INDICATOR_ID, "campaign--01234567-89ab-cdef-0123-456789abcdef"],
    }

    converted = list(converter.process(stix_object))
    assert len(converted) == 2
    assert "object_refs" not in converted[0]

    relationship = converted[1]
    # STIX/OpenCTI direction is indicator --indicates--> entity.
    assert relationship["relationship_type"] == "indicates"
    assert relationship["source_ref"] == INDICATOR_ID
    assert relationship["target_ref"] == stix_object["id"]
    assert relationship["id"] == pycti.StixCoreRelationship.generate_id(
        "indicates", INDICATOR_ID, stix_object["id"]
    )


def test_converter_links_indicators_for_malware_profiles() -> None:
    """Malware profiles also carry their IOCs in object_refs."""
    converter = _build_converter()
    stix_object = {
        "type": "malware",
        "id": "malware--01234567-89ab-cdef-0123-456789abcdef",
        "created": "2025-09-09T12:31:32.000Z",
        "modified": "2025-09-10T12:31:32.000Z",
        "name": "CastleLoader",
        "is_family": True,
        "object_refs": [INDICATOR_ID],
    }

    converted = list(converter.process(stix_object))
    assert len(converted) == 2
    assert converted[1]["relationship_type"] == "indicates"
    assert converted[1]["source_ref"] == INDICATOR_ID
    assert converted[1]["target_ref"] == stix_object["id"]


def test_converter_keeps_object_refs_on_containers() -> None:
    converter = _build_converter()
    stix_object = {
        "type": "report",
        "id": "report--01234567-89ab-cdef-0123-456789abcdef",
        "name": "Alert",
        "published": "2025-06-11T10:28:06.000Z",
        "object_refs": [INDICATOR_ID],
    }

    converted = list(converter.process(stix_object))
    assert len(converted) == 1
    assert converted[0]["object_refs"] == [INDICATOR_ID]
    assert "first_seen" not in converted[0]


def test_converter_maps_associated_content_to_related_to() -> None:
    converter = _build_converter(threat_actor_to_intrusion_set=True)
    actor_id = "threat-actor--01234567-89ab-cdef-0123-456789abcdef"
    campaign_id = "campaign--01234567-89ab-cdef-0123-456789abcdef"
    stix_object = {
        "type": "relationship",
        "id": "relationship--01234567-89ab-cdef-0123-456789abcdef",
        "relationship_type": "associated-content",
        "source_ref": actor_id,
        "target_ref": campaign_id,
    }

    converted = list(converter.process(stix_object))
    assert len(converted) == 1
    relationship = converted[0]
    assert relationship["relationship_type"] == "related-to"
    assert relationship["id"] == stix_object["id"]
    assert relationship["source_ref"] == actor_id.replace(
        "threat-actor", "intrusion-set"
    )
    assert relationship["target_ref"] == campaign_id


def test_converter_converts_attck_labels_to_attack_patterns() -> None:
    converter = _build_converter(threat_actor_to_intrusion_set=True)
    stix_object = {
        "type": "threat-actor",
        "id": "threat-actor--01234567-89ab-cdef-0123-456789abcdef",
        "name": "BlackFile",
        "labels": [
            "Organised Crime Group (OCG)",
            "T1566.004 - Spearphishing Voice",
            "T1078 - Valid Accounts",
            "T1078 - Valid Accounts",
        ],
    }

    converted = list(converter.process(stix_object))
    main_object = converted[0]
    intrusion_set_id = main_object["id"]
    assert main_object["type"] == "intrusion-set"
    assert main_object["labels"] == ["Organised Crime Group (OCG)"]

    attack_patterns = [o for o in converted if o["type"] == "attack-pattern"]
    relationships = [o for o in converted if o["type"] == "relationship"]
    assert [ap["x_mitre_id"] for ap in attack_patterns] == ["T1566.004", "T1078"]
    assert attack_patterns[0]["name"] == "Spearphishing Voice"
    assert attack_patterns[0]["id"] == pycti.AttackPattern.generate_id(
        name="Spearphishing Voice", x_mitre_id="T1566.004"
    )
    assert attack_patterns[0]["external_references"] == [
        {
            "source_name": "mitre-attack",
            "external_id": "T1566.004",
            "url": "https://attack.mitre.org/techniques/T1566/004",
        }
    ]
    assert all(ap["object_marking_refs"] for ap in attack_patterns)
    assert all(ap["created_by_ref"] == converter.author.id for ap in attack_patterns)

    assert len(relationships) == 2
    for relationship, attack_pattern in zip(relationships, attack_patterns):
        assert relationship["relationship_type"] == "uses"
        assert relationship["source_ref"] == intrusion_set_id
        assert relationship["target_ref"] == attack_pattern["id"]


def test_converter_converts_attck_labels_on_malware_and_campaigns() -> None:
    converter = _build_converter()
    for stix_type in ["malware", "campaign"]:
        stix_object = {
            "type": stix_type,
            "id": f"{stix_type}--01234567-89ab-cdef-0123-456789abcdef",
            "name": "LokiBot",
            "labels": ["T1027.002 - Software Packing"],
        }
        converted = list(converter.process(stix_object))
        assert converted[0]["labels"] == []
        assert converted[1]["type"] == "attack-pattern"
        assert converted[2]["source_ref"] == stix_object["id"]


def test_converter_converts_attck_labels_on_indicators_via_indicates() -> None:
    converter = _build_converter()
    stix_object = {
        "type": "indicator",
        "id": INDICATOR_ID,
        "name": "MirrorBlast [profiles - 2342]",
        "pattern": "[file:hashes.'SHA-256'='b593add117782fee1816d31afd95355533f926653b140291445543d9e3aca246']",
        "pattern_type": "stix",
        "labels": [
            "Downloader",
            "United States of America (USA)",
            "T1036 - Masquerading",
            "T1036.004 - Masquerade Task or Service",
        ],
    }

    converted = list(converter.process(stix_object))
    main_object = converted[0]
    assert main_object["type"] == "indicator"
    assert main_object["labels"] == ["Downloader", "United States of America (USA)"]

    attack_patterns = [o for o in converted if o["type"] == "attack-pattern"]
    relationships = [o for o in converted if o["type"] == "relationship"]
    assert [ap["x_mitre_id"] for ap in attack_patterns] == ["T1036", "T1036.004"]
    assert len(relationships) == 2
    for relationship, attack_pattern in zip(relationships, attack_patterns):
        assert relationship["relationship_type"] == "indicates"
        assert relationship["source_ref"] == INDICATOR_ID
        assert relationship["target_ref"] == attack_pattern["id"]
        assert relationship["id"] == pycti.StixCoreRelationship.generate_id(
            "indicates", INDICATOR_ID, attack_pattern["id"]
        )


def test_converter_does_not_create_attack_patterns_for_reports() -> None:
    converter = _build_converter()
    stix_object = {
        "type": "report",
        "id": "report--01234567-89ab-cdef-0123-456789abcdef",
        "name": "Alert",
        "published": "2025-06-11T10:28:06.000Z",
        "labels": ["T1027 - Obfuscated Files or Information"],
    }

    converted = list(converter.process(stix_object))
    assert len(converted) == 1
    assert converted[0]["labels"] == ["T1027 - Obfuscated Files or Information"]


def test_converter_cleans_names_and_aliases() -> None:
    converter = _build_converter()
    stix_object = {
        "type": "threat-actor",
        "id": "threat-actor--01234567-89ab-cdef-0123-456789abcdef",
        "name": "Lazarus Group\n\n",
        "aliases": [
            "Reconnaissance General Bureau (RGB)",
            "Unit 121; Subgroup 1: Diamond Sleet (ZINC)",
            "UNC577; Subgroup 2 (likely disbanded): APT38",
            "Lazarus Group",
            "APT38",
            " ",
        ],
    }

    main_object = list(converter.process(stix_object))[0]
    assert main_object["name"] == "Lazarus Group"
    assert main_object["aliases"] == [
        "Reconnaissance General Bureau (RGB)",
        "Unit 121; Subgroup 1: Diamond Sleet (ZINC)",
        "UNC577; Subgroup 2 (likely disbanded): APT38",
        "APT38",
    ]


def test_converter_maps_threat_actor_to_intrusion_set_in_indicator_links() -> None:
    converter = _build_converter(threat_actor_to_intrusion_set=True)
    stix_object = {
        "type": "threat-actor",
        "id": "threat-actor--01234567-89ab-cdef-0123-456789abcdef",
        "created": "2025-05-27T15:29:48.000Z",
        "name": "Void Blizzard",
        "object_refs": [INDICATOR_ID],
    }

    converted = list(converter.process(stix_object))
    assert converted[0]["type"] == "intrusion-set"
    assert converted[1]["target_ref"].startswith("intrusion-set--")


def test_converter_keeps_labels_not_explicitly_in_structured_goals() -> None:
    converter = _build_converter()
    stix_object = {
        "type": "threat-actor",
        "id": "threat-actor--01234567-89ab-cdef-0123-456789abcdef",
        "name": "Example Actor",
        "goals": ["Exposure of data"],
        "labels": ["Exposure of data", "Extortion"],
    }

    converted = list(converter.process(stix_object))
    assert converted[0]["labels"] == ["Extortion"]


def test_converter_inherits_source_marking_on_derived_objects() -> None:
    converter = _build_converter()
    stix_object = {
        "type": "malware",
        "id": "malware--01234567-89ab-cdef-0123-456789abcdef",
        "name": "Example Malware",
        "created_by_ref": "identity--11111111-1111-4111-8111-111111111111",
        "object_marking_refs": [
            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
        ],
        "labels": ["T1027.002 - Software Packing"],
        "object_refs": [INDICATOR_ID],
    }

    converted = list(converter.process(stix_object))
    derived_objects = [o for o in converted if o["id"] != stix_object["id"]]
    assert len(derived_objects) == 3
    assert all(
        obj["created_by_ref"] == stix_object["created_by_ref"]
        for obj in derived_objects
    )
    assert all(
        obj["object_marking_refs"] == stix_object["object_marking_refs"]
        for obj in derived_objects
    )
