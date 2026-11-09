"""Every code path must send a technique with the same name and x_mitre_id.

The actor, malware and indicator importers each used their own spelling of a technique
(the technique ID as name, the CrowdStrike API name, the label name, a lower-case ID).
Every alternation renamed the Attack Pattern on the platform.
"""

from unittest.mock import MagicMock, patch

import pytest
from crowdstrike_feeds_connector.actor.importer import ActorImporter
from crowdstrike_feeds_connector.malware.importer import MalwareImporter
from crowdstrike_feeds_services.utils import create_attack_pattern, create_organization
from crowdstrike_feeds_services.utils.attack_lookup import (
    AttackTechniqueLookup,
    normalize_mitre_id,
)
from stix2 import TLP_AMBER

ATTACK_DATASET = {
    "type": "bundle",
    "objects": [
        {
            "type": "attack-pattern",
            "name": "Endpoint Denial of Service",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1499"}
            ],
        },
        {
            "type": "attack-pattern",
            "name": "Malicious File",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1204.002"}
            ],
        },
        {
            "type": "attack-pattern",
            "name": "Cloud Accounts",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1078.004"}
            ],
        },
        {
            "type": "attack-pattern",
            "name": "Cloud Accounts",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1136.003"}
            ],
        },
        {
            "type": "attack-pattern",
            "name": "PowerShell",
            "revoked": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1086"}
            ],
        },
    ],
}

AUTHOR = create_organization("CrowdStrike")


@pytest.fixture
def attack_lookup() -> AttackTechniqueLookup:
    with patch.object(
        AttackTechniqueLookup,
        "_load_enterprise_attack_techniques",
        lambda self: self._parse_attack_json(ATTACK_DATASET),
    ):
        return AttackTechniqueLookup(attack_version="17.1")


def _importer(importer_class, attack_lookup):
    importer = importer_class.__new__(importer_class)
    importer.helper = MagicMock()
    importer.author = AUTHOR
    importer.tlp_marking = TLP_AMBER
    importer.attack_lookup = attack_lookup
    return importer


def test_normalize_mitre_id():
    assert normalize_mitre_id(" t1204.002 ") == "T1204.002"  # noqa: S101
    assert normalize_mitre_id(None) is None  # noqa: S101
    assert normalize_mitre_id("  ") is None  # noqa: S101


def test_lookup_by_mitre_id_ignores_case(attack_lookup):
    technique = attack_lookup.lookup_technique_by_mitre_id("t1499")
    assert technique is not None  # noqa: S101
    assert technique.name == "Endpoint Denial of Service"  # noqa: S101
    assert technique.mitre_id == "T1499"  # noqa: S101


@pytest.mark.parametrize(
    "name, mitre_id",
    [
        ("T1499", "T1499"),
        ("Endpoint Denial Of Service", "t1499"),
        ("Endpoint Denial of Service", "T1499"),
    ],
)
def test_every_spelling_gives_the_mitre_name_and_id(attack_lookup, name, mitre_id):
    attack_pattern = create_attack_pattern(
        name=name, mitre_id=mitre_id, attack_lookup=attack_lookup
    )
    assert attack_pattern.name == "Endpoint Denial of Service"  # noqa: S101
    assert attack_pattern.x_mitre_id == "T1499"  # noqa: S101


def test_unknown_technique_keeps_its_name_with_an_upper_case_id(attack_lookup):
    attack_pattern = create_attack_pattern(
        name="Some Technique", mitre_id="t9999", attack_lookup=attack_lookup
    )
    assert attack_pattern.name == "Some Technique"  # noqa: S101
    assert attack_pattern.x_mitre_id == "T9999"  # noqa: S101


def test_without_lookup_the_id_is_upper_case():
    attack_pattern = create_attack_pattern(name="T1499", mitre_id="t1499")
    assert attack_pattern.name == "T1499"  # noqa: S101
    assert attack_pattern.x_mitre_id == "T1499"  # noqa: S101


def test_actor_and_malware_importers_send_the_same_technique(attack_lookup):
    actor_importer = _importer(ActorImporter, attack_lookup)
    actor_importer.actors_api_cs = MagicMock()
    actor_importer.actors_api_cs.query_mitre_attacks.return_value = {
        "resources": ["actor_tactic_T1499"]
    }
    malware_importer = _importer(MalwareImporter, attack_lookup)

    [from_actor] = actor_importer._get_and_create_attack_patterns(
        {"id": 1, "name": "FANCY BEAR"}
    )
    [from_malware] = malware_importer._get_and_create_attack_patterns(
        {
            "id": 2,
            "name": "Some Malware",
            "mitre": [
                {
                    "technique_id": "t1499",
                    "technique_name": "Endpoint Denial Of Service",
                }
            ],
        }
    )

    for attack_pattern in (from_actor, from_malware):
        assert attack_pattern.name == "Endpoint Denial of Service"  # noqa: S101
        assert attack_pattern.x_mitre_id == "T1499"  # noqa: S101
    assert from_actor.id == from_malware.id  # noqa: S101


def test_label_name_resolves_to_the_mitre_name(attack_lookup):
    technique = attack_lookup.lookup_technique_by_name("Endpoint Denial Of Service")
    assert technique is not None  # noqa: S101
    assert technique.name == "Endpoint Denial of Service"  # noqa: S101
    assert technique.mitre_id == "T1499"  # noqa: S101


def test_techniques_sharing_a_name_are_all_found_by_mitre_id(attack_lookup):
    for mitre_id in ("T1078.004", "T1136.003"):
        technique = attack_lookup.lookup_technique_by_mitre_id(mitre_id)
        assert technique is not None  # noqa: S101
        assert technique.name == "Cloud Accounts"  # noqa: S101
        assert technique.mitre_id == mitre_id  # noqa: S101


def test_revoked_technique_is_left_out(attack_lookup):
    assert attack_lookup.lookup_technique_by_mitre_id("T1086") is None  # noqa: S101
    assert attack_lookup.lookup_technique_by_name("PowerShell") is None  # noqa: S101
    attack_pattern = create_attack_pattern(
        name="T1086", mitre_id="t1086", attack_lookup=attack_lookup
    )
    assert attack_pattern.name == "T1086"  # noqa: S101
    assert attack_pattern.x_mitre_id == "T1086"  # noqa: S101


def test_empty_name_or_id_is_not_resolved(attack_lookup):
    assert attack_lookup.lookup_technique_by_name("") is None  # noqa: S101
    assert attack_lookup.lookup_technique_by_mitre_id(None) is None  # noqa: S101
    assert attack_lookup.lookup_mitre_id("Unknown Technique") is None  # noqa: S101
