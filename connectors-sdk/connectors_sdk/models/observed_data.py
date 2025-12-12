"""ObservedData."""

from typing import Any

from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from pycti import ObservedData as PyctiObservedData
from pydantic import AwareDatetime, Field
from stix2.v21 import ObservedData as Stix2ObservedData


class ObservedData(BaseIdentifiedEntity):
    """Base class for OpenCTI observed data."""

    first_observed: AwareDatetime = Field(
        description="The beginning of the time window during which the data was seen.",
    )
    last_observed: AwareDatetime = Field(
        description="The end of the time window during which the data was seen.",
    )
    number_observed: int = Field(
        gt=0,
        description="The number of times that each Cyber-observable object was observed.",
    )
    objects: list[BaseIdentifiedEntity] = Field(
        description="List of OpenCTI identified entities observed.",
    )

    def model_post_init(self, context__: Any) -> None:
        """Validate objects before calling id."""
        if not self.objects:
            raise ValueError("objects must contain at least one element")

        super().model_post_init(context__)

    def to_stix2_object(self) -> Stix2ObservedData:
        """Make stix object."""
        objects_refs = [obj.id for obj in self.objects]
        return Stix2ObservedData(
            id=PyctiObservedData.generate_id(objects_refs),
            first_observed=self.first_observed,
            last_observed=self.last_observed,
            number_observed=self.number_observed,
            object_refs=objects_refs,
            **self._common_stix2_properties()
        )
