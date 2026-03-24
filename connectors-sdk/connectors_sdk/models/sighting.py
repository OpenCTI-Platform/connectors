"""Sighting."""

from typing import TypeAlias

from connectors_sdk.models.administrative_area import AdministrativeArea
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.city import City
from connectors_sdk.models.country import Country
from connectors_sdk.models.individual import Individual
from connectors_sdk.models.observed_data import ObservedData
from connectors_sdk.models.organization import Organization
from connectors_sdk.models.reference import Reference
from connectors_sdk.models.region import Region
from pycti import StixSightingRelationship as PyctiStixSightingRelationship
from pydantic import AwareDatetime, Field
from stix2.v21 import Sighting as Stix2Sighting

IdentityOrLocation: TypeAlias = (
    Individual | Organization | AdministrativeArea | City | Country | Region
)


class Sighting(BaseIdentifiedEntity):
    """Represent a STIX Sighting relationship.

    Examples:
        >>> sighting = Sighting(
        ...     sighting_of=indicator,
        ...     where_sighted=[organization],
        ...     first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ...     last_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ... )
        >>> entity = sighting.to_stix2_object()
    """

    # TODO: This property MUST reference only an SDO or a Custom Object. We should create a parent class for SDO.
    sighting_of: BaseIdentifiedEntity | Reference = Field(
        description="The entity being sighted (e.g. an Indicator). MUST reference an SDO or Custom Object.",
    )
    where_sighted: list[IdentityOrLocation | Reference] = Field(
        description="The entities where the sighting occurred. MUST reference Identity or Location SDOs.",
        min_length=1,
    )
    observed_data: list[ObservedData | Reference] | None = Field(
        default=None,
        description="The observed data associated with this sighting.",
    )
    first_seen: AwareDatetime | None = Field(
        default=None,
        description="The beginning of the time window during which the sighting occurred.",
    )
    last_seen: AwareDatetime | None = Field(
        default=None,
        description="The end of the time window during which the sighting occurred.",
    )
    count: int | None = Field(
        default=None,
        description="Number of times the sighting was observed.",
        ge=0,
    )
    description: str | None = Field(
        default=None,
        description="Description of the sighting.",
    )
    qualification: bool | None = Field(
        default=None,
        description="Qualification of the sighting (false positive).",
    )

    def to_stix2_object(self) -> Stix2Sighting:
        """Make stix object."""
        where_sighted_ids = [ref.id for ref in self.where_sighted]
        observed_data_ids = (
            [ref.id for ref in self.observed_data]
            if self.observed_data is not None
            else None
        )

        return Stix2Sighting(
            id=PyctiStixSightingRelationship.generate_id(
                sighting_of_ref=self.sighting_of.id,
                where_sighted_refs=where_sighted_ids,
                first_seen=self.first_seen,
                last_seen=self.last_seen,
            ),
            sighting_of_ref=self.sighting_of.id,
            where_sighted_refs=where_sighted_ids,
            observed_data_refs=observed_data_ids,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            count=self.count,
            description=self.description,
            x_opencti_negative=self.qualification,
            **self._common_stix2_properties(),
            allow_custom=True,
        )
