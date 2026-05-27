import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import ToolType
from connectors_sdk.models.tool import Tool
from pydantic import ValidationError
from stix2.v21 import Tool as Stix2Tool


def test_tool_is_a_base_identified_entity():
    """Test that Tool is a BaseIdentifiedEntity."""
    # Given the Tool class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Tool, BaseIdentifiedEntity)


def test_tool_class_should_not_accept_invalid_input():
    """Test that Tool class should not accept invalid input."""
    # Given: An invalid input data for Tool
    input_data = {
        "name": "Test Tool",
        "tool_types": ["remote-access"],
        "invalid_key": "invalid_value",
    }
    # When validating the tool
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        Tool.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_tool_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that Tool to_stix2_object method returns a valid STIX2.1 Tool."""
    # Given: A valid Tool instance
    tool = Tool(
        name="Test Tool",
        description="Test description",
        tool_types=[ToolType.REMOTE_ACCESS],
        aliases=["alias_1", "alias_2"],
        kill_chain_phases=[{"chain_name": "test", "phase_name": "pre-attack"}],
        tool_version="1.0.0",
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = tool.to_stix2_object()
    # Then: A valid STIX2.1 Tool is returned
    assert isinstance(stix2_obj, Stix2Tool)


def test_tool_to_stix2_object_with_minimal_fields(
    fake_valid_organization_author,
    fake_valid_tlp_markings,
):
    """Test that Tool to_stix2_object works with only required fields."""
    # Given: A Tool instance with only required fields
    tool = Tool(
        name="Minimal Tool",
        tool_types=[ToolType.EXPLOITATION],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
    )
    # When: calling to_stix2_object method
    stix2_obj = tool.to_stix2_object()
    # Then: A valid STIX2.1 Tool is returned
    assert isinstance(stix2_obj, Stix2Tool)
