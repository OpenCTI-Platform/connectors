"""The module defines the NoteModel class, which represents a STIX 2.1 Note object."""

from typing import Any, Dict, List, Optional

import pycti  # type: ignore  # Missing library stubs
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    Note,
    _STIXBase21,
)


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

    @model_validator(mode="before")
    @classmethod
    def generate_id(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ID regardless of whether one is provided."""
        data["id"] = NoteModel._generate_id(data=data)
        return data

    @classmethod
    def _generate_id(cls, data: Dict[str, Any]) -> Any:
        """Generate ID regardless of whether one is provided."""
        if isinstance(data, dict) and "created" in data:
            created = data.get("created", None)
            content = data.get("content", None)
            data["id"] = pycti.Note.generate_id(created=created, content=content)
        return data["id"]

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        data = self.model_dump(exclude={"id"}, exclude_none=True)
        pycti_id = NoteModel._generate_id(data=data)
        data.pop("id")

        return Note(id=pycti_id, **data)
