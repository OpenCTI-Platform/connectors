# TODO To be removed once this model is added to SDK
"""Observables missing from connectors-sdk.

Follows the SDK's own Hostname model so the class can move to
connectors_sdk.models unchanged once the SDK ships it.
"""

from connectors_sdk.models import BaseObservableEntity
from pycti import CustomObservableCredential
from pydantic import Field


class Credential(BaseObservableEntity):
    """Define a Credential observable on OpenCTI.

    The value identifies the credential (an access key id), never the secret
    itself: Wiz does not expose secrets and they must not reach OpenCTI.
    """

    value: str = Field(
        description="The credential identifier.",
        min_length=1,
    )

    def to_stix2_object(self) -> CustomObservableCredential:
        """Make stix object."""
        return CustomObservableCredential(
            value=self.value,
            **self._common_stix2_properties(),
        )
