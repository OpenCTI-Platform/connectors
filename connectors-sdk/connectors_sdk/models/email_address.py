"""EmailAddress."""

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from pydantic import Field
from stix2.v21 import EmailAddress as Stix2EmailAddress


class EmailAddress(BaseObservableEntity):
    """Represent an email address observable."""

    value: str = Field(
        description="The email address value.",
        min_length=1,
    )

    def to_stix2_object(self) -> Stix2EmailAddress:
        """Make stix object."""
        return Stix2EmailAddress(
            value=self.value,
            **self._common_stix2_properties(),
        )
