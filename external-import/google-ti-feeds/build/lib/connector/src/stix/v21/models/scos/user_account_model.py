"""The module provides a model for representing User Account objects in STIX 2.1 format."""

from datetime import datetime

from connector.src.stix.v21.models.ovs.account_type_ov_enums import AccountTypeOV
from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    UserAccount,
    _STIXBase21,
)


class UserAccountModel(BaseSCOModel):
    """Model representing a User Account in STIX 2.1 format."""

    extensions: dict[str, dict[str, str | int | bool]] | None = Field(
        default=None,
        description="dictionary of extensions. Keys are extension names like 'unix-account-ext', values are the corresponding content.",
    )

    user_id: str | None = Field(
        default=None,
        description="System-unique identifier for the user account (e.g., UID, GUID, email).",
    )
    credential: str | None = Field(
        default=None,
        description="Cleartext credential (ONLY for malware analysis use cases; avoid sharing PII).",
    )
    account_login: str | None = Field(
        default=None,
        description="Login string entered by the user (e.g., 'root').",
    )
    account_type: AccountTypeOV | None = Field(
        default=None,
        description="Open vocabulary value representing the account type. SHOULD come from account-type-ov.",
    )
    display_name: str | None = Field(
        default=None,
        description="Human-friendly display name (e.g., GECOS field on Unix).",
    )

    is_service_account: bool | None = Field(
        default=None,
        description="True if account is tied to a system service/daemon.",
    )
    is_privileged: bool | None = Field(
        default=None,
        description="True if account has elevated (e.g., admin/root) privileges.",
    )
    can_escalate_privs: bool | None = Field(
        default=None,
        description="True if account can escalate to elevated privileges (e.g., sudo access).",
    )
    is_disabled: bool | None = Field(
        default=None, description="True if the account is currently disabled."
    )

    account_created: datetime | None = Field(
        default=None, description="Timestamp when the account was created."
    )
    account_expires: datetime | None = Field(
        default=None, description="Timestamp when the account will expire."
    )
    credential_last_changed: datetime | None = Field(
        default=None,
        description="Timestamp when the account's credential was last changed.",
    )
    account_first_login: datetime | None = Field(
        default=None, description="Timestamp of the account's first login."
    )
    account_last_login: datetime | None = Field(
        default=None, description="Timestamp of the account's last login."
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return UserAccount(**self.model_dump(exclude_none=True))
