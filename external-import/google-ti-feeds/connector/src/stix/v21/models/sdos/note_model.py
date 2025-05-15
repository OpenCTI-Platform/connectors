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


def test_note_model() -> None:
    """Test function to demonstrate the usage of NoteModel."""
    from datetime import UTC, datetime
    from uuid import uuid4

    # === Minimal Note ===
    minimal = NoteModel(
        type="note",
        spec_version="2.1",
        id=f"note--{uuid4()}",
        created=datetime.now(UTC),
        modified=datetime.now(UTC),
        content="Suspicious activity observed but not confirmed malicious.",
        object_refs=[f"indicator--{uuid4()}"],
    )

    print("=== MINIMAL NOTE ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Note ===
    full = NoteModel(
        type="note",
        spec_version="2.1",
        id=f"note--{uuid4()}",
        created=datetime.now(UTC),
        modified=datetime.now(UTC),
        abstract="Analyst summary of campaign indicators",
        content="Indicators observed align with previous APT-29 infrastructure. Attribution with medium confidence.",
        authors=["Dr. Rei Hoshino", "D. Sato"],
        object_refs=[
            f"campaign--{uuid4()}",
            f"indicator--{uuid4()}",
            f"infrastructure--{uuid4()}",
        ],
        labels=["analyst-note", "attribution", "campaign"],
        confidence=75,
        lang="en",
        revoked=False,
        created_by_ref=f"identity--{uuid4()}",
        external_references=[],
        object_marking_refs=[f"marking-definition--{uuid4()}"],
        granular_markings=[
            {
                "selectors": ["content", "abstract"],
                "marking_ref": f"marking-definition--{uuid4()}",
            }
        ],
        extensions={
            f"extension-definition--{uuid4()}": {
                "extension_type": "new-sdo",
                "analyst_tier": "senior",
            }
        },
    )

    print("\n=== FULL NOTE ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_note_model()
