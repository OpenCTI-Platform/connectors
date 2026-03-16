"""UserAccount model."""

from datetime import datetime

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from connectors_sdk.models.enums import AccountType
from pydantic import Field
from stix2.v21 import UserAccount as Stix2UserAccount


class UserAccount(BaseObservableEntity):
    """Represent a user account observable on OpenCTI."""

    user_id: str | None = Field(
        description="Identifier of the account in the system (for example UID, GUID, account name, or email address).",
        default=None,
    )
    credential: str | None = Field(
        description="Cleartext credential for the account (intended for malware-analysis metadata, not for sharing PII).",
        default=None,
    )
    account_login: str | None = Field(
        description="Account login used by the user to sign in when different from user_id.",
        default=None,
    )
    account_type: AccountType | None = Field(
        description="Type of account (for example unix, windows-local, windows-domain, twitter).",
        default=None,
    )
    display_name: str | None = Field(
        description="Display name of the account shown in user interfaces.",
        default=None,
    )
    is_service_account: bool | None = Field(
        description="Whether the account is associated with a service or system process rather than an individual.",
        default=None,
    )
    is_privileged: bool | None = Field(
        description="Whether the account has elevated privileges.",
        default=None,
    )
    can_escalate_privs: bool | None = Field(
        description="Whether the account can escalate privileges.",
        default=None,
    )
    is_disabled: bool | None = Field(
        description="Whether the account is disabled.",
        default=None,
    )
    account_created: datetime | None = Field(
        description="When the account was created.",
        default=None,
    )
    account_expires: datetime | None = Field(
        description="When the account expires.",
        default=None,
    )
    credential_last_changed: datetime | None = Field(
        description="When the account credential was last changed.",
        default=None,
    )
    account_first_login: datetime | None = Field(
        description="When the account was first accessed.",
        default=None,
    )
    account_last_login: datetime | None = Field(
        description="When the account was last accessed.",
        default=None,
    )

    def to_stix2_object(self) -> Stix2UserAccount:
        """Make stix object."""
        return Stix2UserAccount(
            user_id=self.user_id,
            account_login=self.account_login,
            account_type=self.account_type.value if self.account_type else None,
            display_name=self.display_name,
            is_service_account=self.is_service_account,
            is_privileged=self.is_privileged,
            can_escalate_privs=self.can_escalate_privs,
            is_disabled=self.is_disabled,
            account_created=self.account_created,
            account_expires=self.account_expires,
            credential_last_changed=self.credential_last_changed,
            account_first_login=self.account_first_login,
            account_last_login=self.account_last_login,
            **self._common_stix2_properties(),
        )
