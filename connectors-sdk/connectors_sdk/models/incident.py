"""Incident."""

from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import IncidentSeverity, IncidentType
from pycti import Incident as PyctiIncident
from pydantic import AwareDatetime, Field
from stix2.v21 import Incident as Stix2Incident


class Incident(BaseIdentifiedEntity):
    """Define an Incident on OpenCTI."""

    name: str = Field(
        description="A name used to identify this Incident.",
        min_length=1,
    )
    created: AwareDatetime = Field(
        description="The date and time at which the Incident was created, used for deterministic ID generation.",
    )
    description: str | None = Field(
        default=None,
        description="A description that provides more details and context about the Incident.",
    )
    incident_type: IncidentType | None = Field(
        default=None,
        description="The type of the Incident.",
    )
    severity: IncidentSeverity | None = Field(
        default=None,
        description="The severity of the Incident.",
    )
    source: str | None = Field(
        default=None,
        description="The source of the Incident.",
    )
    first_seen: AwareDatetime | None = Field(
        default=None,
        description="The time that this Incident was first seen.",
    )
    last_seen: AwareDatetime | None = Field(
        default=None,
        description="The time that this Incident was last seen.",
    )
    labels: list[str] | None = Field(
        default=None,
        description="Labels of the Incident.",
    )
    objective: str | None = Field(
        default=None,
        description="The objective of this Incident.",
    )

    def to_stix2_object(self) -> Stix2Incident:
        """Make stix object."""
        return Stix2Incident(
            id=PyctiIncident.generate_id(
                name=self.name,
                created=self.created,
            ),
            name=self.name,
            description=self.description,
            created=self.created,
            labels=self.labels,
            allow_custom=True,
            source=self.source,
            severity=self.severity,
            incident_type=self.incident_type,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            objective=self.objective,
            **self._common_stix2_properties(),
        )
