from datetime import datetime
from typing import Optional

import pycti
import stix2
from pydantic import Field
from spycloud_connector.models.opencti import Author, OCTIBaseModel, TLPMarking
from spycloud_connector.utils.types import OCTISeverityType


class Incident(OCTIBaseModel):  # TODO: complete description
    """
    Class representing an OpenCTI incident.
    Implements `to_stix2_ojbect` that returns a STIX2 Incident object.
    """

    name: str = Field(
        description="A name used to identify the incident.",
        min_length=1,
    )
    description: Optional[str] = Field(
        description="A description that provides more details and context about the incident, potentially including its purpose and its key characteristics.",
        min_length=1,
        default=None,
    )
    source: str = Field(description="", min_length=1)
    severity: OCTISeverityType = Field(description="")
    incident_type: str = Field(description="")
    author: Author = Field(description="The author reporting this incident.")
    created_at: datetime = Field(
        description="Represents the time at which the incident was originally reported."
    )
    updated_at: Optional[datetime] = Field(
        description="Must be set when creating a new version of an object if the created property was set.",
        default=None,
    )
    markings: list[TLPMarking] = Field(
        description="References for object markings.",
        min_length=1,
    )

    def to_stix2_object(self) -> stix2.Incident:
        return stix2.Incident(
            id=pycti.Incident.generate_id(self.name, self.created_at),
            name=self.name,
            description=self.description,
            created=self.created_at,
            created_by_ref=self.author.id,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_source": self.source,
                "x_opencti_severity": self.severity,
                "x_opencti_incident_type": self.incident_type,
                "x_opencti_first_seen": self.created_at,
                "x_opencti_last_seen": self.updated_at,
            },
        )
