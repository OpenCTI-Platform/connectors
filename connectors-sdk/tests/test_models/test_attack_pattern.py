import pytest
from connectors_sdk.models.attack_pattern import AttackPattern
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from pydantic import ValidationError
from stix2.v21 import AttackPattern as Stix2AttackPattern


def test_attack_pattern_is_a_base_identified_entity():
    """Test that AttackPattern is a BaseIdentifiedEntity."""
    # Given the AttackPattern class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(AttackPattern, BaseIdentifiedEntity)


def test_attack_pattern_class_should_not_accept_invalid_input():
    """Test that AttackPattern class should not accept invalid input."""
    # Given: An invalid input data for AttackPattern
    input_data = {
        "name": "Test attack pattern",
        "invalid_key": "invalid_value",
    }
    # When validating the attack pattern
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        AttackPattern.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_attack_pattern_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that AttackPattern to_stix2_object method returns a valid STIX2.1 AttackPattern."""
    # Given: A valid AttackPattern instance
    attack_pattern = AttackPattern(
        name="Test attack pattern",
        description="Test description",
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = attack_pattern.to_stix2_object()
    # Then: A valid STIX2.1 AttackPattern is returned
    assert isinstance(stix2_obj, Stix2AttackPattern)
