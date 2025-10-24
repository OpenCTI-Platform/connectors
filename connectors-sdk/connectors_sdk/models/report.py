"""Report."""

from __future__ import annotations

from collections import OrderedDict

import stix2.properties
from connectors_sdk.models.associated_file import AssociatedFile
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import Reliability, ReportType
from pycti import Report as PyctiReport
from pydantic import AwareDatetime, Field
from stix2.v21 import Report as Stix2Report


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
    description: str | None = Field(
        default=None,
        description="Description of the report.",
    )
    report_types: list[ReportType] | None = Field(
        default=None,
        description="Report types.",
    )
    labels: list[str] | None = Field(
        default=None,
        description="Labels of the report",
    )
    reliability: Reliability | None = Field(
        default=None,
        description="Reliability of the report.",
    )
    objects: list[BaseIdentifiedEntity] | None = Field(
        default=None,
        description="Objects of the report.",
    )
    files: list[AssociatedFile] | None = Field(
        default=None,
        description="Files to upload with the report, e.g. report as a PDF.",
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
            labels=self.labels,
            object_refs=[obj.id for obj in self.objects or []],
            allow_custom=True,
            x_opencti_reliability=self.reliability,
            x_opencti_files=[file.to_stix2_object() for file in self.files or []],
            **self._common_stix2_properties(),
        )
