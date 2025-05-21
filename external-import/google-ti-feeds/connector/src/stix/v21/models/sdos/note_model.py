"""The module defines the NoteModel class, which represents a STIX 2.1 Note object."""

from typing import List, Optional

from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field
from stix2.v21 import Note, _STIXBase21  # type: ignore


class NoteModel(BaseSDOModel):
    """Model representing a Note in STIX 2.1 format."""

    abstract: Optional[str] = Field(
        default=None, description="A brief summary of the note content."
    )
    content: str = Field(..., description="The main content of the note.")
    authors: Optional[List[str]] = Field(
        default=None,
        description="Names of the author(s) of this note (e.g., the analyst(s) who wrote it).",
    )
    object_refs: List[str] = Field(
        ..., description="STIX Object identifiers this note applies to."
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Note(**self.model_dump(exclude_none=True))
