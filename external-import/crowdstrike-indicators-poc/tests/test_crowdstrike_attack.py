"""Tests for resolving CrowdStrike ATT&CK labels to MITRE AttackPatterns.

``fixtures/attack_extract.json`` holds AttackPatterns copied unchanged from
MITRE ATT&CK Enterprise 17.1 (© The MITRE Corporation, reproduced under the
ATT&CK terms of use).
"""

import json
from datetime import UTC, datetime
from typing import Any
from unittest import mock

import pytest
import stix2
from conftest import FIXTURES_DIR, load_fixture, make_indicator
from crowdstrike_indicators import attack as attack_module
from crowdstrike_indicators.attack import (
    AttackPatternCatalog,
    CrowdStrikeAddAttackPatterns,
    match_key,
)
from crowdstrike_indicators.errors import IndicatorConversionError
from crowdstrike_indicators.ids import indicates_id
from crowdstrike_indicators.malware import CrowdStrikeAddMalware
from crowdstrike_indicators.models import CrowdStrikeIndicator
from crowdstrike_indicators.stix import CrowdStrikeIndicatorBundle
from crowdstrike_indicators.transformer import CrowdStrikeIndicatorTransformer
from stix2.exceptions import InvalidValueError
from stix2.v21 import Relationship

ATTACK_DATA = load_fixture("attack_extract.json")
ATTACK_FILE = FIXTURES_DIR / "attack_extract.json"


@pytest.fixture(scope="module")
def catalog() -> AttackPatternCatalog:
    return AttackPatternCatalog(ATTACK_DATA)


def mitre_id(pattern) -> str:
    return next(
        ref.external_id
        for ref in pattern.external_references
        if ref.source_name == "mitre-attack"
    )


# --- Loading -----------------------------------------------------------------


def test_catalog_from_file_keeps_only_live_techniques():
    catalog = AttackPatternCatalog.from_file(ATTACK_FILE)

    assert len(catalog) == len(ATTACK_DATA["objects"]) - 1  # the revoked T1022


def test_revoked_technique_is_ignored(catalog):
    assert any(
        obj["name"] == "Data Encrypted" and obj["revoked"]
        for obj in ATTACK_DATA["objects"]
    )
    assert catalog.resolve("Exfiltration", "DataEncrypted") is None


@pytest.mark.parametrize("content", ["[]", '{"type": "identity"}', "{not json"])
def test_file_that_is_not_a_bundle_is_rejected(tmp_path, content):
    path = tmp_path / "not-a-bundle.json"
    path.write_text(content)

    with pytest.raises(ValueError, match="not-a-bundle.json"):
        AttackPatternCatalog.from_file(path)


def test_bundle_without_object_list_is_rejected():
    with pytest.raises(ValueError, match="'objects' is not a list"):
        AttackPatternCatalog({"type": "bundle", "objects": None})


# --- Name matching -----------------------------------------------------------


def test_match_key_keeps_letters_and_digits():
    assert match_key("Registry Run Keys / Startup Folder") == match_key(
        "RegistryRunKeysStartupFolder"
    )
    assert match_key("Non-Standard Port") == "nonstandardport"


def test_camelcase_name_matches(catalog):
    assert mitre_id(catalog.resolve("Execution", "PowerShell")) == "T1059.001"


def test_punctuation_in_mitre_name_matches(catalog):
    pattern = catalog.resolve("Persistence", "RegistryRunKeysStartupFolder")

    assert pattern.name == "Registry Run Keys / Startup Folder"
    assert mitre_id(pattern) == "T1547.001"


def test_unique_match_ignores_the_tactic(catalog):
    assert mitre_id(catalog.resolve("SomeOtherTactic", "PowerShell")) == "T1059.001"


# --- Tactic ------------------------------------------------------------------


def test_tactic_chooses_between_techniques_sharing_a_name(catalog):
    command_and_control = catalog.resolve("CommandAndControl", "Steganography")
    defense_evasion = catalog.resolve("DefenseEvasion", "Steganography")

    assert mitre_id(command_and_control) == "T1001.002"
    assert mitre_id(defense_evasion) == "T1027.003"


@pytest.mark.parametrize("technique", ["Botnet", "Malware", "Server"])
def test_name_ambiguous_within_its_tactic_resolves_to_none(catalog, technique):
    assert catalog.resolve("ResourceDevelopment", technique) is None


def test_unknown_name_resolves_to_none(catalog):
    assert catalog.resolve("CommandAndControl", "RemoteFileCopy") is None


def test_resolved_object_is_mitre_object_unchanged(catalog):
    pattern = catalog.resolve("Collection", "DataFromLocalSystem")
    original = next(o for o in ATTACK_DATA["objects"] if o["id"] == pattern.id)

    assert pattern.id == "attack-pattern--3c4a2599-71ee-4405-ba1e-0e28414b4bc5"
    assert json.loads(pattern.serialize()) == {
        key: value
        for key, value in original.items()
        if not (key == "revoked" and value is False)
    }


# --- The bundle step ---------------------------------------------------------

SAMPLE_ROWS = load_fixture("indicators_sample.json")["resources"]
SAMPLE_IDS = [f"{row['type']}-{i}" for i, row in enumerate(SAMPLE_ROWS)]
FIRST_ROW = SAMPLE_ROWS[0]
REPEATED_ROW = next(
    row
    for row in SAMPLE_ROWS
    if sum(
        label["name"].endswith("/ReplicationThroughRemovableMedia")
        for label in row["labels"]
    )
    == 2
)


def bundle_of(raw: dict[str, Any]) -> CrowdStrikeIndicatorBundle:
    indicator = CrowdStrikeIndicatorTransformer().convert(
        CrowdStrikeIndicator.model_validate(raw)
    )
    return CrowdStrikeAddMalware().convert(indicator)


def with_labels(*names: str) -> CrowdStrikeIndicatorBundle:
    return bundle_of(make_indicator(1, labels=[{"name": name} for name in names]))


def add_attack_patterns(
    bundle: CrowdStrikeIndicatorBundle, catalog: AttackPatternCatalog
) -> CrowdStrikeIndicatorBundle:
    return CrowdStrikeAddAttackPatterns(catalog).convert(bundle)


def test_resolved_techniques_in_label_order(catalog):
    result = add_attack_patterns(bundle_of(FIRST_ROW), catalog)

    assert [mitre_id(p) for p in result.attack_patterns] == [
        "T1005",
        "T1555",
        "T1056",
        "T1078",
        "T1589.001",
    ]
    assert result.attack_patterns[0].id == (
        "attack-pattern--3c4a2599-71ee-4405-ba1e-0e28414b4bc5"
    )


def test_attack_patterns_are_the_catalog_objects(catalog):
    result = add_attack_patterns(bundle_of(FIRST_ROW), catalog)

    assert result.attack_patterns[0] is catalog.resolve(
        "Collection", "DataFromLocalSystem"
    )


def test_same_technique_under_two_tactics_is_added_once(catalog):
    result = add_attack_patterns(bundle_of(REPEATED_ROW), catalog)

    ids = [mitre_id(p) for p in result.attack_patterns]
    assert ids.count("T1091") == 1
    assert len(ids) == len(set(ids))


def test_earlier_objects_are_kept(catalog):
    before = bundle_of(FIRST_ROW)
    assert before.malware

    result = add_attack_patterns(before, catalog)

    assert result.indicator is before.indicator
    assert result.malware == before.malware
    assert result.relationships[: len(before.relationships)] == before.relationships
    assert len(result.relationships) == len(before.relationships) + len(
        result.attack_patterns
    )


def test_unresolved_labels_add_nothing(catalog):
    before = with_labels(
        "MitreATTCK/CommandAndControl/RemoteFileCopy",
        "MitreATTCK/ResourceDevelopment/Botnet",
        "Malware/ExampleFamily1",
        "MitreATTCK/OnlyTwoParts",
    )

    result = add_attack_patterns(before, catalog)

    assert result.attack_patterns == []
    assert result.relationships == before.relationships
    assert "MitreATTCK/CommandAndControl/RemoteFileCopy" in result.indicator.labels


def test_indicator_without_labels(catalog):
    result = add_attack_patterns(bundle_of(make_indicator(1)), catalog)

    assert result.attack_patterns == []


def test_relationship_to_a_technique(catalog):
    result = add_attack_patterns(bundle_of(FIRST_ROW), catalog)

    relationship = result.relationships[len(result.malware)]
    indicator = result.indicator
    assert indicator.id == "indicator--1455db42-6c02-5136-aa8f-149a7c58270c"
    assert relationship.relationship_type == "indicates"
    assert relationship.source_ref == indicator.id
    assert relationship.target_ref == (
        "attack-pattern--3c4a2599-71ee-4405-ba1e-0e28414b4bc5"
    )
    assert relationship.id == indicates_id(indicator.id, relationship.target_ref)
    assert relationship.created == indicator.created
    assert relationship.modified == indicator.modified


def _serialized(bundle: CrowdStrikeIndicatorBundle) -> list[str]:
    objects = [
        bundle.indicator,
        *bundle.malware,
        *bundle.attack_patterns,
        *bundle.relationships,
    ]
    return [obj.serialize() for obj in objects]


def test_same_input_same_output_whatever_the_time(catalog):
    before = bundle_of(FIRST_ROW)
    first = add_attack_patterns(before, catalog)

    later = datetime(2099, 1, 1, tzinfo=UTC)
    with mock.patch("stix2.base.get_timestamp", return_value=later):
        second = add_attack_patterns(before, catalog)

    assert _serialized(first) == _serialized(second)


def test_stix2_failure_is_wrapped_with_its_cause(catalog):
    failure = InvalidValueError(Relationship, "source_ref", "forced")
    with mock.patch.object(attack_module, "Relationship", side_effect=failure):
        with pytest.raises(IndicatorConversionError) as caught:
            add_attack_patterns(bundle_of(FIRST_ROW), catalog)

    assert caught.value.indicator_id == FIRST_ROW["id"]
    assert caught.value.__cause__ is failure


@pytest.mark.parametrize("raw", SAMPLE_ROWS, ids=SAMPLE_IDS)
def test_three_step_chain_goes_into_a_stix_bundle(raw, catalog):
    result = add_attack_patterns(bundle_of(raw), catalog)

    stix_bundle = stix2.Bundle(
        objects=[
            result.indicator,
            *result.malware,
            *result.attack_patterns,
            *result.relationships,
        ],
        allow_custom=True,
    )
    targets = {r.target_ref for r in result.relationships}
    assert targets == {o.id for o in [*result.malware, *result.attack_patterns]}
    assert len(stix_bundle.objects) == 1 + 2 * len(targets)
