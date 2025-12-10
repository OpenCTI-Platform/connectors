import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import Reliability
from connectors_sdk.models.individual import Individual
from pydantic import ValidationError
from stix2.v21 import Identity as Stix2Identity


def test_individual_is_a_base_identified_entity():
    """Test that Individual is a BaseIdentifiedEntity."""
    # Given the Individual class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Individual, BaseIdentifiedEntity)


def test_individual_class_should_not_accept_invalid_input():
    """Test that Individual class should not accept invalid input."""
    # Given: An invalid input data for Individual
    input_data = {
        "name": "Test individual",
        "invalid_key": "invalid_value",
    }
    # When validating the individual
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        Individual.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_individual_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that Individual to_stix2_object method returns a valid STIX2.1 Individual."""
    # Given: A valid Individual instance
    individual = Individual(
        name="John Doe",
        description="Test description",
        contact_information="contact@test.com",
        reliability=Reliability.A,
        aliases=["Test alias"],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = individual.to_stix2_object()
    # Then: A valid STIX2.1 Identity is returned
    assert isinstance(stix2_obj, Stix2Identity)
