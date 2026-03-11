"""EmailAddress."""

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from connectors_sdk.models.reference import Reference
from connectors_sdk.models.user_account import UserAccount
from pydantic import Field
from stix2.v21 import EmailAddress as Stix2EmailAddress


class EmailAddress(BaseObservableEntity):
    """Represent an email address observable on OpenCTI."""

    value: str = Field(
        description="The email address value.",
        min_length=1,
    )
    display_name: str | None = Field(
        description="The display name of the email address.",
        default=None,
    )
    belongs_to: UserAccount | Reference | None = Field(
        description="The user account associated with the email address.",
        default=None,
    )

    def to_stix2_object(self) -> Stix2EmailAddress:
        """Make stix object."""
        return Stix2EmailAddress(
            value=self.value,
            display_name=self.display_name,
            belongs_to_ref=self.belongs_to.id if self.belongs_to else None,
            **self._common_stix2_properties(),
        )
