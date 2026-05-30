"""Note."""

import warnings
from collections import OrderedDict
from typing import Any

import stix2.properties
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import NoteType
from connectors_sdk.models.reference import Reference
from pycti import Note as PyctiNote
from pydantic import AwareDatetime, Field, model_validator
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
    publication_date: AwareDatetime | None = Field(
        default=None,
        description="Deprecated: Use 'created' instead. Publication date of the note.",
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
    objects: list[BaseIdentifiedEntity | Reference] | None = Field(
        default=None,
        description="OCTI objects this note applies to.",
    )

    @model_validator(mode="before")
    @classmethod
    def _validate_publication_date_vs_created(cls, data: Any) -> Any:
        if isinstance(data, dict):
            pub_date = data.get("publication_date")
            created = data.get("created")
            if pub_date is not None and created is not None:
                raise ValueError(
                    "Cannot set both 'publication_date' and 'created'. "
                    "'publication_date' is deprecated, use 'created' instead."
                )
            if pub_date is not None:
                warnings.warn(
                    "'publication_date' is deprecated, use 'created' instead.",
                    DeprecationWarning,
                    stacklevel=2,
                )
                data["created"] = pub_date
                data["publication_date"] = None
        return data

    def to_stix2_object(self) -> Stix2Note:
        """Make stix object."""
        return NoteStix(
            id=PyctiNote.generate_id(
                content=self.content,
                created=self.created,
                abstract=self.abstract,
            ),
            abstract=self.abstract,
            content=self.content,
            labels=self.labels,
            authors=self.authors,
            object_refs=[obj.id for obj in self.objects or []],
            allow_custom=True,
            note_types=self.note_types,
            **self._common_stix2_properties()
        )
