import pytest
from connectors_sdk.models.domain_name import DomainName
from pydantic import ValidationError
from stix2.v21 import DomainName as Stix2DomainName


def test_domain_name_class_should_not_accept_invalid_input():
    """Test that DomainName class should not accept invalid input."""
    # Given: An invalid input data for DomainName
    input_data = {
        "value": "invalid_ip",
        "invalid_key": "invalid_value",
    }
    # When validating the domain name
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        DomainName.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_domain_name_to_stix2_object_returns_valid_stix_object():
    """Test that DomainName to_stix2_object method returns a valid STIX2.1 DomainName."""
    # Given: A valid DomainName instance
    domain_name = DomainName(value="test.com")
    # When: calling to_stix2_object method
    stix2_obj = domain_name.to_stix2_object()
    # Then: A valid STIX2.1 DomainName is returned
    assert isinstance(stix2_obj, Stix2DomainName)


def test_domain_name_to_stix2_object(
    fake_valid_organization_author,
    fake_valid_tlp_markings,
    fake_valid_external_references,
) -> None:
    domain_name = DomainName(
        value="example.com",
        score=85,
        description="Example domain name",
        labels=["test-label"],
        associated_files=[],
        create_indicator=True,
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    stix2_obj = domain_name.to_stix2_object()
    assert stix2_obj == Stix2DomainName(
        value="example.com",
        object_marking_refs=[marking.id for marking in fake_valid_tlp_markings],
        custom_properties=dict(
            x_opencti_score=85,
            x_opencti_description="Example domain name",
            x_opencti_labels=["test-label"],
            x_opencti_files=[],
            x_opencti_create_indicator=True,
            x_opencti_created_by_ref=fake_valid_organization_author.id,
            x_opencti_external_references=[
                external_ref.to_stix2_object()
                for external_ref in fake_valid_external_references
            ],
        ),
    )
