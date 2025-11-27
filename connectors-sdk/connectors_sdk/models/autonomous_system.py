"""Define the OpenCTI Observable."""

import stix2
from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from pydantic import Field


class AutonomousSystem(BaseObservableEntity):
    """Represent an autnomous system (AS) observable on OpenCTI."""

    number: int = Field(
        description="The number assigned to the autonomous system (AS).",
    )
    name: str | None = Field(
        description="The name of the autonomous system.",
        default=None,
    )
    rir: str | None = Field(
        description="The name of the Regional Internet Registry (RIR) that assigned the number to the autonomous system.",
        default=None,
    )

    def to_stix2_object(self) -> stix2.v21.AutonomousSystem:
        """Make the stix2 autonomous system object.

        Returns:
            (stix2.v21.AutonomousSystem): The stix2 autonomous system object.

        """
        return stix2.AutonomousSystem(
            number=self.number,
            name=self.name,
            rir=self.rir,
            **self._common_stix2_properties(),
        )
