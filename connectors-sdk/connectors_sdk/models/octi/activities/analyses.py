"""Offer analyses OpenCTI entities.


Notes:
    - ExternalReference is not defined here as it is a common entity used across different models.
    It is defined in the _common module.

"""

from collections import OrderedDict
from typing import Optional

import stix2.properties
from connectors_sdk.models.octi._common import (
    MODEL_REGISTRY,
    AssociatedFile,
    BaseIdentifiedEntity,
)
from connectors_sdk.models.octi.enums import Reliability, ReportType
from pycti import Report as PyctiReport
from pydantic import AwareDatetime, Field
from stix2 import Report as Stix2Report


class ReportStix(Stix2Report):  # type: ignore[misc]
    # As stix2 is untyped, subclassing one of its element is not handled by type checkers.
    """Override stix2 Report to not require any object_refs and so be compliant with OpenCTI Report entities."""

    # Copy the parent class properties
    _properties = OrderedDict(Stix2Report._properties)
    # Update properties definition to allow missing object_refs
    _properties["object_refs"] = stix2.properties.ListProperty(
        stix2.properties.ReferenceProperty(
            valid_types=["SCO", "SDO", "SRO"], spec_version="2.1"
        ),
        required=False,
    )


@MODEL_REGISTRY.register
class Report(BaseIdentifiedEntity):
    """Represent a report.

    Notes:
      - On OpenCTI reports without object_refs are still valid, unlike what STIX2.1 spec defines.
    """

    name: str = Field(
        description="Name of the report.",
        min_length=1,
    )
    publication_date: AwareDatetime = Field(
        description="Publication date of the report.",
    )
    description: Optional[str] = Field(
        description="Description of the report.",
        default=None,
    )
    report_types: Optional[list[ReportType]] = Field(
        description="Report types.",
        default=None,
    )
    reliability: Optional[Reliability] = Field(
        description="Reliability of the report.",
        default=None,
    )
    objects: Optional[list[BaseIdentifiedEntity]] = Field(
        description="Objects of the report.",
        default=None,
    )
    files: Optional[list[AssociatedFile]] = Field(
        description="Files to upload with the report, e.g. report as a PDF.",
        default=None,
    )

    def to_stix2_object(self) -> Stix2Report:
        """Make stix object."""
        return ReportStix(
            id=PyctiReport.generate_id(
                name=self.name,
                published=self.publication_date,
            ),
            name=self.name,
            published=self.publication_date,
            description=self.description,
            report_types=self.report_types,
            object_refs=[obj.id for obj in self.objects or []],
            created_by_ref=self.author.id if self.author else None,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking.id for marking in self.markings or []],
            allow_custom=True,
            x_opencti_reliability=self.reliability,
            x_opencti_files=[file.to_stix2_object() for file in self.files or []],
        )


MODEL_REGISTRY.rebuild_all()

if __name__ == "__main__":  # pragma: no cover  # Do not run coverage on doctest
    import doctest

    doctest.testmod()
