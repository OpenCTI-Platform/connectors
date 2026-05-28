import pytest
from connectors_sdk.models import ExternalReference, OrganizationAuthor, TLPMarking
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.hostname import Hostname
from pycti import CustomObservableHostname
from pydantic import ValidationError


def test_hostname_is_a_base_identified_entity() -> None:
    """Test that Hostname is a BaseIdentifiedEntity."""
    # Given the Hostname class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Hostname, BaseIdentifiedEntity)


def test_hostname_class_should_not_accept_invalid_input() -> None:
    """Test that Hostname class should not accept invalid input."""
    # Given: An invalid input data for Hostname
    input_data = {
        "name": "Test hostname",
        "invalid_key": "invalid_value",
    }
    # When validating the hostname
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        Hostname.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_hostname_to_stix2_object(
    fake_valid_organization_author: OrganizationAuthor,
    fake_valid_tlp_markings: list[TLPMarking],
    fake_valid_external_references: list[ExternalReference],
) -> None:
    """Test that Hostname to_stix2_object method returns correct STIX2.1 Location."""
    hostname = Hostname(
        value="Hostname value",
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    ).to_stix2_object()

    assert hostname == CustomObservableHostname(
        value="Hostname value",
        allow_custom=True,
        object_marking_refs=[
            marking.to_stix2_object().id for marking in fake_valid_tlp_markings
        ],
        x_opencti_created_by_ref=fake_valid_organization_author.id,
        x_opencti_external_references=[
            external_ref.to_stix2_object()
            for external_ref in fake_valid_external_references
        ],
    )
