"""Note."""

from collections import OrderedDict

import stix2.properties
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import NoteType
from pycti import Note as PyctiNote
from pydantic import AwareDatetime, Field
from stix2.v21 import Note as Stix2Note


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
            created=self.publication_date,  # usually set by stix2 lib but here it MUST be equal to the datetime used for note's id.
            allow_custom=True,
            note_types=self.note_types,
            **self._common_stix2_properties()
        )
