"""CaseIncident."""

from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import (
    CaseIncidentResponseType,
    CasePriority,
    CaseSeverity,
)
from connectors_sdk.models.reference import Reference
from pycti import CaseIncident as PyctiCaseIncident
from pycti import CustomObjectCaseIncident
from pydantic import Field


class CaseIncident(BaseIdentifiedEntity):
    """Represents a case incident entity on OpenCTI.

    A Case Incident is a container used to group observables, indicators and
    other STIX objects related to the investigation of an incident.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/client-python/pycti/entities/opencti_case_incident.py
    """

    name: str = Field(
        description="Name of the case incident.",
        min_length=1,
    )
    description: str | None = Field(
        default=None,
        description="Description of the case incident.",
    )
    severity: CaseSeverity | None = Field(
        default=None,
        description="Severity of the case incident.",
    )
    priority: CasePriority | None = Field(
        default=None,
        description="Priority of the case incident.",
    )
    response_types: list[CaseIncidentResponseType] | None = Field(
        default=None,
        description="Response types of the case incident.",
    )
    objects: list[BaseIdentifiedEntity | Reference] | None = Field(
        default=None,
        description="OCTI objects contained in this case incident.",
    )

    def to_stix2_object(self) -> CustomObjectCaseIncident:
        """Make CaseIncident STIX2.1 object."""
        return CustomObjectCaseIncident(
            id=PyctiCaseIncident.generate_id(
                name=self.name,
                created=self.created,
            ),
            name=self.name,
            description=self.description,
            severity=self.severity,
            priority=self.priority,
            response_types=self.response_types,
            object_refs=[obj.id for obj in self.objects or []],
            allow_custom=True,
            **self._common_stix2_properties(),
        )
