"""Tests that GTIAttackTechniqueIDsToSTIXAttackPatterns uses the technique name, not the ID.

The attack pattern ID only depends on the MITRE ID, so an attack pattern named after
its own ID would overwrite the name of the MITRE technique on the platform (#8012).
"""

from uuid import uuid4

import pycti
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _given_mapper(
    ids: list[str],
    names: dict[str, str] | None,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> GTIAttackTechniqueIDsToSTIXAttackPatterns:
    return GTIAttackTechniqueIDsToSTIXAttackPatterns(
        attack_technique_ids=GTIAttackTechniqueIDData.from_id_list(ids, names=names),
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTIAttackTechniqueIDsToSTIXAttackPatterns) -> list:
    return mapper.to_stix()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.order(1)
def test_attack_pattern_uses_technique_name_not_id(mock_organization, mock_tlp_marking):
    """The attack pattern is named after the technique, never after its ID."""
    # GIVEN
    mapper = _given_mapper(
        ["T1046"],
        {"T1046": "Network Service Discovery"},
        mock_organization,
        mock_tlp_marking,
    )

    # WHEN
    attack_patterns = _when_convert_to_stix(mapper)

    # THEN
    assert len(attack_patterns) == 1  # noqa: S101
    assert attack_patterns[0].name == "Network Service Discovery"  # noqa: S101
    assert attack_patterns[0].name != "T1046"  # noqa: S101


@pytest.mark.order(1)
def test_attack_pattern_id_is_unchanged_by_the_name(
    mock_organization, mock_tlp_marking
):
    """The ID is derived from the MITRE ID alone, so it merges with MITRE ATT&CK."""
    # GIVEN
    mapper = _given_mapper(
        ["T1046"],
        {"T1046": "Network Service Discovery"},
        mock_organization,
        mock_tlp_marking,
    )

    # WHEN
    attack_patterns = _when_convert_to_stix(mapper)

    # THEN
    expected_id = pycti.AttackPattern.generate_id(name="T1046", x_mitre_id="T1046")
    assert attack_patterns[0].id == expected_id  # noqa: S101


@pytest.mark.order(1)
def test_attack_pattern_keeps_mitre_id_author_and_marking(
    mock_organization, mock_tlp_marking
):
    """x_mitre_id, author and marking are not affected by the name."""
    # GIVEN
    mapper = _given_mapper(
        ["T1046"],
        {"T1046": "Network Service Discovery"},
        mock_organization,
        mock_tlp_marking,
    )

    # WHEN
    attack_patterns = _when_convert_to_stix(mapper)

    # THEN
    attack_pattern = attack_patterns[0]
    assert attack_pattern.custom_properties["x_mitre_id"] == "T1046"  # noqa: S101
    assert attack_pattern.created_by_ref == mock_organization.id  # noqa: S101
    assert attack_pattern.object_marking_refs == [mock_tlp_marking.id]  # noqa: S101


@pytest.mark.order(1)
@pytest.mark.parametrize(
    "names",
    [
        pytest.param({"T1055": "Process Injection"}, id="missing"),
        pytest.param({"T1055": "Process Injection", "T1046": ""}, id="empty"),
        pytest.param({"T1055": "Process Injection", "T1046": "   "}, id="blank"),
    ],
)
def test_technique_without_name_is_skipped(mock_organization, mock_tlp_marking, names):
    """A technique without a usable name is skipped, the others are still emitted."""
    # GIVEN
    mapper = _given_mapper(
        ["T1046", "T1055"], names, mock_organization, mock_tlp_marking
    )

    # WHEN
    attack_patterns = _when_convert_to_stix(mapper)

    # THEN
    emitted_ids = [ap.custom_properties["x_mitre_id"] for ap in attack_patterns]
    assert emitted_ids == ["T1055"]  # noqa: S101
    assert attack_patterns[0].name == "Process Injection"  # noqa: S101
