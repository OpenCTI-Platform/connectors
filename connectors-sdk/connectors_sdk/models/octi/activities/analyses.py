"""Offer analyses OpenCTI entities.


Notes:
    - ExternalReference is not defined here as it is a common entity used across different models.
    It is defined in the _common module.

"""

from collections import OrderedDict

import stix2.properties
from connectors_sdk.models._model_registry import MODEL_REGISTRY
from connectors_sdk.models.octi._common import (
    AssociatedFile,
    BaseIdentifiedEntity,
)
from connectors_sdk.models.octi.enums import NoteType, Reliability, ReportType
from pycti import Note as PyctiNote
from pycti import Report as PyctiReport
from pydantic import AwareDatetime, Field
from stix2.v21 import Note as Stix2Note
from stix2.v21 import Report as Stix2Report


class NoteStix(Stix2Note):  # type: ignore[misc]
    # As stix2 is untyped, subclassing one of its element is not handled by type checkers.
    """Override stix2 Note to not require any object_refs and so be compliant with OpenCTI Note entities."""

    # Copy the parent class properties
    _properties = OrderedDict(Stix2Note._properties)
    # Update properties definition to allow missing object_refs
    _properties["object_refs"] = stix2.properties.ListProperty(
        stix2.properties.ReferenceProperty(
            valid_types=["SCO", "SDO", "SRO"], spec_version="2.1"
        ),
        required=False,
    )


@MODEL_REGISTRY.register
class Note(BaseIdentifiedEntity):
    """Represent a note."""

    content: str = Field(
        description="The main content of the note.",
    )
    publication_date: AwareDatetime = Field(
        description="Publication date of the note.",
    )
    abstract: str | None = Field(
        default=None,
        description="A brief summary of the note content.",
    )
    note_types: list[NoteType] | None = Field(
        default=None,
        description="Types of the note.",
    )
    labels: list[str] | None = Field(
        default=None,
        description="Labels of the note.",
    )
    authors: list[str] | None = Field(
        default=None,
        description="The name of the author(s) of this note (e.g., the analyst(s) that created it).",
    )
    objects: list[BaseIdentifiedEntity] | None = Field(
        default=None,
        description="OCTI objects this note applies to.",
    )

    def to_stix2_object(self) -> Stix2Note:
        """Make stix object."""
        return NoteStix(
            id=PyctiNote.generate_id(
                content=self.content,
                created=self.publication_date,
            ),
            abstract=self.abstract,
            content=self.content,
            labels=self.labels,
            authors=self.authors,
            object_refs=[obj.id for obj in self.objects or []],
            created_by_ref=self.author.id if self.author else None,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking.id for marking in self.markings or []],
            created=self.publication_date,  # usually set by stix2 lib but here it MUST be equal to the datetime used for note's id.
            allow_custom=True,
            note_types=self.note_types,
        )


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
