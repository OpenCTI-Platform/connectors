from datetime import datetime, timezone

import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import AccountType
from connectors_sdk.models.user_account import UserAccount
from pydantic import ValidationError
from stix2.v21 import UserAccount as Stix2UserAccount


def test_user_account_is_a_base_identified_entity() -> None:
    """Test that UserAccount is a BaseIdentifiedEntity."""
    assert issubclass(UserAccount, BaseIdentifiedEntity)


def test_user_account_class_should_not_accept_invalid_input() -> None:
    """Test that UserAccount class should not accept invalid input."""
    input_data = {
        "user_id": "john.doe",
        "invalid_key": "invalid_value",
    }
    with pytest.raises(ValidationError) as error:
        UserAccount.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_user_account_to_stix2_object_returns_valid_stix_object() -> None:
    """Test that UserAccount to_stix2_object method returns a valid STIX2.1 object."""
    user_account = UserAccount(user_id="john.doe")
    stix2_obj = user_account.to_stix2_object()
    assert isinstance(stix2_obj, Stix2UserAccount)


def test_user_account_to_stix2_object(
    fake_valid_organization_author,
    fake_valid_tlp_markings,
    fake_valid_external_references,
    fake_valid_associated_files,
) -> None:
    """Test that UserAccount to_stix2_object method returns correct STIX2.1 object."""
    account_created = datetime(2025, 1, 1, 8, 30, 0, tzinfo=timezone.utc)
    account_expires = datetime(2026, 1, 1, 8, 30, 0, tzinfo=timezone.utc)
    credential_last_changed = datetime(2025, 2, 1, 9, 0, 0, tzinfo=timezone.utc)
    account_first_login = datetime(2025, 2, 2, 10, 0, 0, tzinfo=timezone.utc)
    account_last_login = datetime(2025, 3, 1, 11, 0, 0, tzinfo=timezone.utc)

    user_account = UserAccount(
        user_id="john.doe@example.com",
        account_login="john.doe",
        account_type=AccountType.WINDOWS_DOMAIN,
        display_name="John Doe",
        is_service_account=False,
        is_privileged=True,
        can_escalate_privs=True,
        is_disabled=False,
        account_created=account_created,
        account_expires=account_expires,
        credential_last_changed=credential_last_changed,
        account_first_login=account_first_login,
        account_last_login=account_last_login,
        score=90,
        description="Compromised domain account",
        labels=["credential-access", "active-directory"],
        associated_files=fake_valid_associated_files,
        create_indicator=True,
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    ).to_stix2_object()

    assert user_account == Stix2UserAccount(
        user_id="john.doe@example.com",
        account_login="john.doe",
        account_type="windows-domain",
        display_name="John Doe",
        is_service_account=False,
        is_privileged=True,
        can_escalate_privs=True,
        is_disabled=False,
        account_created=account_created,
        account_expires=account_expires,
        credential_last_changed=credential_last_changed,
        account_first_login=account_first_login,
        account_last_login=account_last_login,
        allow_custom=True,
        object_marking_refs=[marking.id for marking in fake_valid_tlp_markings],
        x_opencti_score=90,
        x_opencti_description="Compromised domain account",
        x_opencti_labels=["credential-access", "active-directory"],
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
