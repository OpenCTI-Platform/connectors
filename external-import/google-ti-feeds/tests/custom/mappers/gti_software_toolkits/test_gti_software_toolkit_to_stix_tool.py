"""Tests for the GTISoftwareToolkitToSTIXTool mapper."""

from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_software_toolkits.gti_software_toolkit_to_stix_tool import (
    GTISoftwareToolkitToSTIXTool,
)
from connector.src.custom.models.gti.gti_software_toolkit_model import (
    AltNameDetail,
    GTISoftwareToolkitData,
    SoftwareToolkitModel,
)
from polyfactory.factories.pydantic_factory import ModelFactory
from polyfactory.fields import Use
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class AltNameDetailFactory(ModelFactory[AltNameDetail]):
    """Factory for AltNameDetail model."""

    __model__ = AltNameDetail


class SoftwareToolkitModelFactory(ModelFactory[SoftwareToolkitModel]):
    """Factory for SoftwareToolkitModel."""

    __model__ = SoftwareToolkitModel
    creation_date = 1000000000
    last_modification_date = 1100000000


class GTISoftwareToolkitDataFactory(ModelFactory[GTISoftwareToolkitData]):
    """Factory for GTISoftwareToolkitData."""

    __model__ = GTISoftwareToolkitData

    type = "collection"
    attributes = Use(SoftwareToolkitModelFactory.build)


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
def minimal_software_toolkit_data() -> GTISoftwareToolkitData:
    """Fixture for minimal software toolkit data."""
    return GTISoftwareToolkitDataFactory.build(
        attributes=SoftwareToolkitModelFactory.build(
            description=None,
            tags=None,
            alt_names_details=None,
            tool_version=None,
        )
    )


@pytest.fixture
def software_toolkit_with_aliases() -> GTISoftwareToolkitData:
    """Fixture for software toolkit data with aliases."""
    return GTISoftwareToolkitDataFactory.build(
        attributes=SoftwareToolkitModelFactory.build(
            alt_names_details=[
                AltNameDetailFactory.build(value="AliasA"),
                AltNameDetailFactory.build(value="AliasB"),
            ]
        )
    )


@pytest.fixture
def software_toolkit_without_attributes() -> GTISoftwareToolkitData:
    """Fixture for software toolkit without attributes."""
    return GTISoftwareToolkitDataFactory.build(attributes=None)


@pytest.mark.order(1)
def test_gti_software_toolkit_to_stix_minimal_data(
    minimal_software_toolkit_data, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI software toolkit with minimal data to STIX Tool."""
    # Given a GTI software toolkit with minimal data
    mapper = _given_gti_software_toolkit_mapper(
        minimal_software_toolkit_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    tool = _when_convert_to_stix(mapper)

    # Then STIX tool should be created successfully
    _then_stix_tool_created_successfully(tool)
    _then_stix_tool_has_correct_properties(tool, mock_organization, mock_tlp_marking)


@pytest.mark.order(1)
def test_gti_software_toolkit_to_stix_with_aliases(
    software_toolkit_with_aliases, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI software toolkit with aliases to STIX Tool."""
    # Given a GTI software toolkit with aliases
    mapper = _given_gti_software_toolkit_mapper(
        software_toolkit_with_aliases, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    tool = _when_convert_to_stix(mapper)

    # Then STIX tool should include aliases
    _then_stix_tool_created_successfully(tool)
    _then_stix_tool_has_aliases(tool, ["AliasA", "AliasB"])


@pytest.mark.order(1)
def test_gti_software_toolkit_to_stix_without_attributes(
    software_toolkit_without_attributes, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI software toolkit without attributes raises ValueError."""
    # Given a GTI software toolkit without attributes
    mapper = _given_gti_software_toolkit_mapper(
        software_toolkit_without_attributes, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    # Then should raise ValueError
    _when_convert_to_stix_raises_error(
        mapper, ValueError, "Software toolkit attributes are missing"
    )


@pytest.mark.order(1)
def test_gti_software_toolkit_external_reference(
    minimal_software_toolkit_data, mock_organization, mock_tlp_marking
):
    """Test that external reference to VirusTotal is created correctly."""
    # Given a GTI software toolkit
    toolkit_id = minimal_software_toolkit_data.id
    mapper = _given_gti_software_toolkit_mapper(
        minimal_software_toolkit_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    tool = _when_convert_to_stix(mapper)

    # Then external references should point to VirusTotal
    assert tool.external_references is not None  # noqa: S101
    ext_ref = tool.external_references[0]
    assert ext_ref["source_name"] == "Google Threat Intelligence"  # noqa: S101
    assert ext_ref["external_id"] == toolkit_id  # noqa: S101
    assert (  # noqa: S101
        ext_ref["url"] == f"https://www.virustotal.com/gui/collection/{toolkit_id}"
    )


@pytest.mark.order(1)
def test_extract_aliases_with_alt_names():
    """Test _extract_aliases with alternative names."""
    # Given attributes with alt_names_details
    attributes = SoftwareToolkitModelFactory.build(
        alt_names_details=[
            AltNameDetailFactory.build(value="ToolAlias1"),
            AltNameDetailFactory.build(value="ToolAlias2"),
        ]
    )

    # When extracting aliases
    aliases = GTISoftwareToolkitToSTIXTool._extract_aliases(attributes)

    # Then aliases should be returned
    assert aliases is not None  # noqa: S101
    assert "ToolAlias1" in aliases  # noqa: S101
    assert "ToolAlias2" in aliases  # noqa: S101


@pytest.mark.order(1)
def test_extract_aliases_with_no_alt_names():
    """Test _extract_aliases with no alternative names."""
    # Given attributes without alt_names_details
    attributes = SoftwareToolkitModelFactory.build(alt_names_details=None)

    # When extracting aliases
    aliases = GTISoftwareToolkitToSTIXTool._extract_aliases(attributes)

    # Then aliases should be None
    assert aliases is None  # noqa: S101


@pytest.mark.order(1)
def test_stix_tool_has_deterministic_id(mock_organization, mock_tlp_marking):
    """Test that two toolkits with the same name produce the same STIX ID."""
    # Given two software toolkits with the same name
    name = "SameName"
    toolkit_a = GTISoftwareToolkitDataFactory.build(
        attributes=SoftwareToolkitModelFactory.build(name=name)
    )
    toolkit_b = GTISoftwareToolkitDataFactory.build(
        attributes=SoftwareToolkitModelFactory.build(name=name)
    )

    mapper_a = _given_gti_software_toolkit_mapper(
        toolkit_a, mock_organization, mock_tlp_marking
    )
    mapper_b = _given_gti_software_toolkit_mapper(
        toolkit_b, mock_organization, mock_tlp_marking
    )

    # When converting both to STIX
    tool_a = _when_convert_to_stix(mapper_a)
    tool_b = _when_convert_to_stix(mapper_b)

    # Then both should share the same deterministic ID
    assert tool_a.id == tool_b.id  # noqa: S101


def _given_gti_software_toolkit_mapper(
    software_toolkit: GTISoftwareToolkitData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> GTISoftwareToolkitToSTIXTool:
    """Create a GTISoftwareToolkitToSTIXTool mapper instance."""
    return GTISoftwareToolkitToSTIXTool(
        software_toolkit=software_toolkit,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTISoftwareToolkitToSTIXTool):
    """Convert GTI software toolkit to STIX Tool."""
    return mapper.to_stix()


def _when_convert_to_stix_raises_error(
    mapper: GTISoftwareToolkitToSTIXTool, error_type: type, error_message: str
):
    """Test that conversion raises expected error."""
    with pytest.raises(error_type, match=error_message):
        mapper.to_stix()


def _then_stix_tool_created_successfully(tool):
    """Assert that STIX Tool was created successfully."""
    assert tool is not None  # noqa: S101
    assert hasattr(tool, "name")  # noqa: S101
    assert hasattr(tool, "spec_version")  # noqa: S101
    assert hasattr(tool, "created")  # noqa: S101
    assert hasattr(tool, "modified")  # noqa: S101


def _then_stix_tool_has_correct_properties(
    tool, organization: Identity, tlp_marking: MarkingDefinition
):
    """Assert that STIX Tool has correct creator and marking properties."""
    assert tool.created_by_ref == organization.id  # noqa: S101
    assert tlp_marking.id in tool.object_marking_refs  # noqa: S101


def _then_stix_tool_has_aliases(tool, expected_aliases: list[str]):
    """Assert that STIX Tool has the expected aliases."""
    assert tool.aliases is not None  # noqa: S101
    for alias in expected_aliases:
        assert alias in tool.aliases  # noqa: S101
