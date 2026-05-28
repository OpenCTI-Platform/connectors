"""Tests that GTIAttackTechniqueIDsToSTIXAttackPatterns produces AttackPatterns with description=None."""

from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_attack_techniques.gti_attack_technique_ids_to_stix_attack_patterns import (
    GTIAttackTechniqueIDsToSTIXAttackPatterns,
)
from connector.src.custom.models.gti.gti_attack_technique_id_model import (
    GTIAttackTechniqueIDData,
)
from stix2.v21 import Identity, MarkingDefinition  # type: ignore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_organization():
    """Mock organization Identity object."""
    return Identity(  # pylint: disable=W9101
        name="Test Organization",
        identity_class="organization",
    )


@pytest.fixture
def mock_tlp_marking():
    """Mock TLP marking definition object."""
    return MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )


@pytest.fixture
def attack_technique_ids() -> GTIAttackTechniqueIDData:
    """Attack technique ID data with two technique IDs."""
    return GTIAttackTechniqueIDData.from_id_list(["T1055", "T1078"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _given_attack_technique_ids_mapper(
    attack_technique_ids: GTIAttackTechniqueIDData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> GTIAttackTechniqueIDsToSTIXAttackPatterns:
    return GTIAttackTechniqueIDsToSTIXAttackPatterns(
        attack_technique_ids=attack_technique_ids,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTIAttackTechniqueIDsToSTIXAttackPatterns) -> list:
    return mapper.to_stix()


def _then_attack_pattern_has_no_description(attack_pattern) -> None:  # noqa: ANN001
    assert attack_pattern.name is not None  # noqa: S101
    assert attack_pattern.description is None  # noqa: S101


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.order(1)
def test_attack_patterns_have_no_description(
    attack_technique_ids,
    mock_organization,
    mock_tlp_marking,
):
    """Minimal AttackPatterns from technique IDs must have description=None."""
    # GIVEN
    mapper = _given_attack_technique_ids_mapper(
        attack_technique_ids,
        mock_organization,
        mock_tlp_marking,
    )

    # WHEN
    attack_patterns = _when_convert_to_stix(mapper)

    # THEN
    assert len(attack_patterns) == 2  # noqa: S101
    for ap in attack_patterns:
        _then_attack_pattern_has_no_description(ap)


@pytest.mark.order(1)
def test_single_attack_pattern_has_no_description(
    mock_organization,
    mock_tlp_marking,
):
    """A single minimal AttackPattern from a technique ID must have description=None."""
    # GIVEN
    ids_data = GTIAttackTechniqueIDData.from_id_list(["T1059"])
    mapper = _given_attack_technique_ids_mapper(
        ids_data,
        mock_organization,
        mock_tlp_marking,
    )

    # WHEN
    attack_patterns = _when_convert_to_stix(mapper)

    # THEN
    assert len(attack_patterns) == 1  # noqa: S101
    _then_attack_pattern_has_no_description(attack_patterns[0])
