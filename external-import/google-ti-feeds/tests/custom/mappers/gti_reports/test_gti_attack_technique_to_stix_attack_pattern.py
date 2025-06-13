"""Tests for the GTIAttackTechniqueToSTIXAttackPattern mapper."""

from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_reports.gti_attack_technique_to_stix_attack_pattern import (
    GTIAttackTechniqueToSTIXAttackPattern,
)
from connector.src.custom.models.gti_reports.gti_attack_technique_model import (
    AttackTechniqueModel,
    GTIAttackTechniqueData,
    Info,
)
from polyfactory.factories.pydantic_factory import ModelFactory
from polyfactory.fields import Use
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class InfoFactory(ModelFactory[Info]):
    """Factory for Info model."""

    __model__ = Info


class AttackTechniqueModelFactory(ModelFactory[AttackTechniqueModel]):
    """Factory for AttackTechniqueModel."""

    __model__ = AttackTechniqueModel


class GTIAttackTechniqueDataFactory(ModelFactory[GTIAttackTechniqueData]):
    """Factory for GTIAttackTechniqueData."""

    __model__ = GTIAttackTechniqueData

    type = "attack-technique"
    attributes = Use(AttackTechniqueModelFactory.build)


@pytest.fixture
def mock_organization() -> Identity:
    """Fixture for mock organization identity."""
    return Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization",
        identity_class="organization",
    )


@pytest.fixture
def mock_tlp_marking() -> MarkingDefinition:
    """Fixture for mock TLP marking definition."""
    return MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )


@pytest.fixture
def minimal_attack_technique_data() -> GTIAttackTechniqueData:
    """Fixture for minimal attack technique data."""
    return GTIAttackTechniqueDataFactory.build(
        attributes=AttackTechniqueModelFactory.build(
            info=None,
            link=None,
            stix_id=None,
        )
    )


@pytest.fixture
def attack_technique_with_external_refs() -> GTIAttackTechniqueData:
    """Fixture for attack technique data with external references."""
    return GTIAttackTechniqueDataFactory.build(
        attributes=AttackTechniqueModelFactory.build(
            link="https://attack.mitre.org/techniques/T1001/",
            stix_id="attack-pattern--abc123",
        )
    )


@pytest.fixture
def attack_technique_without_attributes() -> GTIAttackTechniqueData:
    """Fixture for attack technique without attributes."""
    return GTIAttackTechniqueDataFactory.build(attributes=None)


@pytest.fixture
def attack_technique_with_duplicate_link() -> GTIAttackTechniqueData:
    """Fixture for attack technique with duplicate link in external refs."""
    technique_id = "T1001"
    return GTIAttackTechniqueDataFactory.build(
        id=technique_id,
        attributes=AttackTechniqueModelFactory.build(
            link=f"https://attack.mitre.org/techniques/{technique_id}/",
        ),
    )


def test_gti_attack_technique_to_stix_minimal_data(
    minimal_attack_technique_data, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI attack technique with minimal data to STIX attack pattern."""
    # Given a GTI attack technique with minimal data
    mapper = _given_gti_attack_technique_mapper(
        minimal_attack_technique_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    attack_pattern = _when_convert_to_stix(mapper)

    # Then STIX attack pattern should be created successfully
    _then_stix_attack_pattern_created_successfully(attack_pattern)
    _then_stix_attack_pattern_has_correct_properties(
        attack_pattern, mock_organization, mock_tlp_marking
    )
    _then_stix_attack_pattern_has_mitre_id(
        attack_pattern, minimal_attack_technique_data.id
    )


def test_gti_attack_technique_to_stix_with_external_refs(
    attack_technique_with_external_refs, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI attack technique with external references to STIX attack pattern."""
    # Given a GTI attack technique with external references
    mapper = _given_gti_attack_technique_mapper(
        attack_technique_with_external_refs, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    attack_pattern = _when_convert_to_stix(mapper)

    # Then STIX attack pattern should include external references
    _then_stix_attack_pattern_created_successfully(attack_pattern)
    _then_stix_attack_pattern_has_external_references(attack_pattern)


def test_gti_attack_technique_to_stix_without_attributes(
    attack_technique_without_attributes, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI attack technique without attributes raises ValueError."""
    # Given a GTI attack technique without attributes
    mapper = _given_gti_attack_technique_mapper(
        attack_technique_without_attributes, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    # Then should raise ValueError
    _when_convert_to_stix_raises_error(
        mapper, ValueError, "Attack technique attributes are missing"
    )


def test_gti_attack_technique_to_stix_with_duplicate_link(
    attack_technique_with_duplicate_link, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI attack technique with duplicate link in external refs."""
    # Given a GTI attack technique with duplicate link
    mapper = _given_gti_attack_technique_mapper(
        attack_technique_with_duplicate_link, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    attack_pattern = _when_convert_to_stix(mapper)

    # Then STIX attack pattern should have unique external references
    _then_stix_attack_pattern_created_successfully(attack_pattern)
    _then_stix_attack_pattern_has_unique_external_references(attack_pattern)


def test_extract_aliases_method():
    """Test _extract_aliases static method."""
    # Given attack technique attributes
    attributes = AttackTechniqueModelFactory.build()

    # When extracting aliases
    aliases = GTIAttackTechniqueToSTIXAttackPattern._extract_aliases(attributes)

    # Then aliases should be None (simplified implementation)
    assert aliases is None  # noqa: S101


def test_extract_aliases_with_none_attributes():
    """Test _extract_aliases static method with None attributes."""
    # Given None attributes
    # When extracting aliases
    aliases = GTIAttackTechniqueToSTIXAttackPattern._extract_aliases(None)

    # Then aliases should be None
    assert aliases is None  # noqa: S101


def test_extract_kill_chain_phases_method():
    """Test _extract_kill_chain_phases static method."""
    # Given attack technique attributes
    attributes = AttackTechniqueModelFactory.build()

    # When extracting kill chain phases
    phases = GTIAttackTechniqueToSTIXAttackPattern._extract_kill_chain_phases(
        attributes
    )

    # Then phases should be None (simplified implementation)
    assert phases is None  # noqa: S101


def test_extract_kill_chain_phases_with_none_attributes():
    """Test _extract_kill_chain_phases static method with None attributes."""
    # Given None attributes
    # When extracting kill chain phases
    phases = GTIAttackTechniqueToSTIXAttackPattern._extract_kill_chain_phases(None)

    # Then phases should be None
    assert phases is None  # noqa: S101


def test_normalize_tactic_name_method():
    """Test _normalize_tactic_name static method."""
    # Given test cases for tactic name normalization
    test_cases = [
        ("Initial Access", "initial-access"),
        ("Privilege Escalation", "privilege-escalation"),
        ("Defense Evasion", "defense-evasion"),
        ("Credential Access", "credential-access"),
    ]

    # When normalizing tactic names
    # Then names should be normalized correctly
    for input_name, expected_output in test_cases:
        result = GTIAttackTechniqueToSTIXAttackPattern._normalize_tactic_name(
            input_name
        )
        assert result == expected_output  # noqa: S101


def test_create_external_references_with_all_data(mock_organization, mock_tlp_marking):
    """Test _create_external_references method with all external reference data."""
    # Given a GTI attack technique with all external reference data
    technique_id = "T1001"
    attack_technique = GTIAttackTechniqueDataFactory.build(
        id=technique_id,
        attributes=AttackTechniqueModelFactory.build(
            link="https://attack.mitre.org/techniques/T1001/custom",
            stix_id="attack-pattern--abc123",
        ),
    )
    mapper = _given_gti_attack_technique_mapper(
        attack_technique, mock_organization, mock_tlp_marking
    )

    # When creating external references
    external_refs = mapper._create_external_references(attack_technique.attributes)

    # Then external references should contain all expected data
    assert external_refs is not None  # noqa: S101
    assert len(external_refs) >= 2  # noqa: S101

    mitre_ref = next(
        (ref for ref in external_refs if ref.get("external_id") == technique_id),
        None,
    )
    assert mitre_ref is not None  # noqa: S101
    assert mitre_ref["source_name"] == "mitre-attack"  # noqa: S101
    assert (  # noqa: S101
        mitre_ref["url"] == f"https://attack.mitre.org/techniques/{technique_id}/"
    )

    stix_ref = next(
        (ref for ref in external_refs if ref.get("source_name") == "stix"),
        None,
    )
    assert stix_ref is not None  # noqa: S101
    assert stix_ref["external_id"] == "attack-pattern--abc123"  # noqa: S101


def test_create_external_references_minimal_data(mock_organization, mock_tlp_marking):
    """Test _create_external_references method with minimal data."""
    # Given a GTI attack technique with minimal data
    technique_id = "T1002"
    attack_technique = GTIAttackTechniqueDataFactory.build(
        id=technique_id,
        attributes=AttackTechniqueModelFactory.build(
            link=None,
            stix_id=None,
        ),
    )
    mapper = _given_gti_attack_technique_mapper(
        attack_technique, mock_organization, mock_tlp_marking
    )

    # When creating external references
    external_refs = mapper._create_external_references(attack_technique.attributes)

    # Then external references should contain only MITRE reference
    assert external_refs is not None  # noqa: S101
    assert len(external_refs) == 1  # noqa: S101

    mitre_ref = external_refs[0]
    assert mitre_ref["source_name"] == "mitre-attack"  # noqa: S101
    assert mitre_ref["external_id"] == technique_id  # noqa: S101
    assert (  # noqa: S101
        mitre_ref["url"] == f"https://attack.mitre.org/techniques/{technique_id}/"
    )


def test_create_external_references_with_none_attributes(
    mock_organization, mock_tlp_marking
):
    """Test _create_external_references method with None attributes."""
    # Given a GTI attack technique
    attack_technique = GTIAttackTechniqueDataFactory.build()
    mapper = _given_gti_attack_technique_mapper(
        attack_technique, mock_organization, mock_tlp_marking
    )

    # When creating external references with None attributes
    external_refs = mapper._create_external_references(None)

    # Then external references should be None
    assert external_refs is None  # noqa: S101


def _given_gti_attack_technique_mapper(
    attack_technique: GTIAttackTechniqueData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> GTIAttackTechniqueToSTIXAttackPattern:
    """Create a GTIAttackTechniqueToSTIXAttackPattern mapper instance."""
    return GTIAttackTechniqueToSTIXAttackPattern(
        attack_technique=attack_technique,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTIAttackTechniqueToSTIXAttackPattern):
    """Convert GTI attack technique to STIX attack pattern."""
    return mapper.to_stix()


def _when_convert_to_stix_raises_error(
    mapper: GTIAttackTechniqueToSTIXAttackPattern, error_type: type, error_message: str
):
    """Test that conversion raises expected error."""
    with pytest.raises(error_type, match=error_message):
        mapper.to_stix()


def _then_stix_attack_pattern_created_successfully(attack_pattern):
    """Assert that STIX attack pattern was created successfully."""
    assert attack_pattern is not None  # noqa: S101
    assert hasattr(attack_pattern, "name")  # noqa: S101
    assert hasattr(attack_pattern, "spec_version")  # noqa: S101
    assert hasattr(attack_pattern, "created")  # noqa: S101
    assert hasattr(attack_pattern, "modified")  # noqa: S101


def _then_stix_attack_pattern_has_correct_properties(
    attack_pattern, organization: Identity, tlp_marking: MarkingDefinition
):
    """Assert that STIX attack pattern has correct properties."""
    assert attack_pattern.created_by_ref == organization.id  # noqa: S101
    assert tlp_marking.id in attack_pattern.object_marking_refs  # noqa: S101


def _then_stix_attack_pattern_has_mitre_id(attack_pattern, expected_mitre_id: str):
    """Assert that STIX attack pattern has correct MITRE ID."""
    # Check if mitre_id is available as a property or custom property
    if hasattr(attack_pattern, "mitre_id"):
        assert attack_pattern.mitre_id == expected_mitre_id  # noqa: S101
    elif hasattr(attack_pattern, "custom_properties"):
        assert (  # noqa: S101
            attack_pattern.custom_properties.get("x_mitre_id") == expected_mitre_id
        )
    else:
        # Check external references for MITRE ID
        assert attack_pattern.external_references is not None  # noqa: S101
        mitre_ref = next(
            (
                ref
                for ref in attack_pattern.external_references
                if (isinstance(ref, dict) and ref.get("source_name") == "mitre-attack")
                or (hasattr(ref, "source_name") and ref.source_name == "mitre-attack")
            ),
            None,
        )
        assert mitre_ref is not None  # noqa: S101


def _then_stix_attack_pattern_has_external_references(attack_pattern):
    """Assert that STIX attack pattern has external references."""
    assert attack_pattern.external_references is not None  # noqa: S101
    assert len(attack_pattern.external_references) > 0  # noqa: S101


def _then_stix_attack_pattern_has_unique_external_references(attack_pattern):
    """Assert that STIX attack pattern has unique external references."""
    assert attack_pattern.external_references is not None  # noqa: S101
    urls = []
    for ref in attack_pattern.external_references:
        url = ref.get("url") if isinstance(ref, dict) else getattr(ref, "url", None)
        if url:
            urls.append(url)
    assert len(urls) == len(set(urls))  # noqa: S101
