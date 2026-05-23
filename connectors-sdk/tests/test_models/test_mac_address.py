import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.mac_address import MACAddress
from pydantic import ValidationError
from stix2.v21 import MACAddress as Stix2MACAddress


def test_mac_address_is_a_base_identified_entity() -> None:
    """Test that MACAddress is a BaseIdentifiedEntity."""
    assert issubclass(MACAddress, BaseIdentifiedEntity)


def test_mac_address_class_should_not_accept_invalid_input() -> None:
    """Test that MACAddress class should not accept invalid input."""
    input_data = {
        "value": "00:11:22:33:44:55",
        "invalid_key": "invalid_value",
    }
    with pytest.raises(ValidationError) as error:
        MACAddress.model_validate(input_data)

    assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_mac_address_to_stix2_object_returns_valid_stix_object() -> None:
    """Test that MACAddress to_stix2_object method returns a valid STIX2.1 object."""
    mac_address = MACAddress(value="00:11:22:33:44:55")
    stix2_obj = mac_address.to_stix2_object()

    assert isinstance(stix2_obj, Stix2MACAddress)


def test_mac_address_to_stix2_object(
    fake_valid_organization_author,
    fake_valid_tlp_markings,
    fake_valid_external_references,
    fake_valid_associated_files,
) -> None:
    """Test that MACAddress to_stix2_object method returns correct STIX2.1 object."""
    mac_address = MACAddress(
        value="AA-BB-CC-DD-EE-FF",
        score=65,
        description="Observed suspicious endpoint identifier",
        labels=["network", "endpoint"],
        associated_files=fake_valid_associated_files,
        create_indicator=True,
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    stix_object = mac_address.to_stix2_object()

    assert stix_object == Stix2MACAddress(
        value="AA-BB-CC-DD-EE-FF",
        allow_custom=True,
        object_marking_refs=[marking.id for marking in fake_valid_tlp_markings],
        x_opencti_score=65,
        x_opencti_description="Observed suspicious endpoint identifier",
        x_opencti_labels=["network", "endpoint"],
        x_opencti_external_references=[
            external_ref.to_stix2_object()
            for external_ref in fake_valid_external_references
        ],
        x_opencti_created_by_ref=fake_valid_organization_author.id,
        x_opencti_files=[
            file.to_stix2_object() for file in fake_valid_associated_files
        ],
        x_opencti_create_indicator=True,
    )
