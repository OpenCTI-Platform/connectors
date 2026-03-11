import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.email_address import EmailAddress
from connectors_sdk.models.user_account import UserAccount
from pydantic import ValidationError
from stix2.v21 import EmailAddress as Stix2EmailAddress


def test_email_address_is_a_base_identified_entity() -> None:
    """Test that EmailAddress is a BaseIdentifiedEntity."""
    assert issubclass(EmailAddress, BaseIdentifiedEntity)


def test_email_address_class_should_not_accept_invalid_input():
    """Test that EmailAddress class should not accept invalid input."""
    input_data = {
        "value": "user@example.com",
        "invalid_key": "invalid_value",
    }
    with pytest.raises(ValidationError) as error:
        EmailAddress.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_email_address_to_stix2_object_returns_valid_stix_object():
    """Test that EmailAddress to_stix2_object method returns a valid STIX2.1 object."""
    email_address = EmailAddress(value="user@example.com")
    stix2_obj = email_address.to_stix2_object()
    assert isinstance(stix2_obj, Stix2EmailAddress)


def test_email_address_to_stix2_object(
    fake_valid_organization_author,
    fake_valid_tlp_markings,
    fake_valid_external_references,
    fake_valid_associated_files,
) -> None:
    user_account = UserAccount(
        user_id="john.doe@example.com",
        account_login="john.doe",
        display_name="John Doe",
    )

    email_address = EmailAddress(
        value="john.doe@example.com",
        display_name="John Doe",
        belongs_to=user_account,
        score=80,
        description="Suspicious phishing sender",
        labels=["phishing", "email"],
        associated_files=fake_valid_associated_files,
        create_indicator=True,
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    ).to_stix2_object()

    assert email_address == Stix2EmailAddress(
        value="john.doe@example.com",
        display_name="John Doe",
        belongs_to_ref=user_account.id,
        allow_custom=True,
        object_marking_refs=[marking.id for marking in fake_valid_tlp_markings],
        x_opencti_score=80,
        x_opencti_description="Suspicious phishing sender",
        x_opencti_labels=["phishing", "email"],
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
