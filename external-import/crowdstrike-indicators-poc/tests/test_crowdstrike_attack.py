"""Tests for resolving CrowdStrike ATT&CK labels to MITRE AttackPatterns.

``fixtures/attack_extract.json`` holds AttackPatterns copied unchanged from
MITRE ATT&CK Enterprise 17.1 (© The MITRE Corporation, reproduced under the
ATT&CK terms of use).
"""

import json

import pytest
from conftest import FIXTURES_DIR, load_fixture
from crowdstrike_indicators.attack import AttackPatternCatalog, match_key

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
