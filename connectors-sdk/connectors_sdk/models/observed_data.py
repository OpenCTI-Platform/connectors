"""ObservedData."""

from connectors_sdk.models.associated_file import AssociatedFile
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
    entities: list[BaseIdentifiedEntity] = Field(
        min_length=1,
        description="List of OpenCTI identified entities observed.",
    )
    labels: list[str] | None = Field(
        default=None,
        description="Labels of the observed data",
    )
    associated_files: list[AssociatedFile] | None = Field(
        default=None,
        description="Files to upload with the observed data, e.g. observed data as a PDF.",
    )

    def to_stix2_object(self) -> Stix2ObservedData:
        """Make stix object."""
        object_refs = [obj.id for obj in self.entities]
        return Stix2ObservedData(
            id=PyctiObservedData.generate_id(object_refs),
            first_observed=self.first_observed,
            last_observed=self.last_observed,
            number_observed=self.number_observed,
            object_refs=object_refs,
            labels=self.labels,
            x_opencti_files=[
                file.to_stix2_object() for file in self.associated_files or []
            ],
            allow_custom=True,
            **self._common_stix2_properties()
        )
