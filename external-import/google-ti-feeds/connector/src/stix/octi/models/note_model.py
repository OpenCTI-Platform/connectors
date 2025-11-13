"""The module contains the OctiNoteModel class, which represents an OpenCTI Note."""

from datetime import datetime
from typing import Any

from connector.src.stix.v21.models.sdos.note_model import NoteModel


class OctiNoteModel:
    """Model for creating OpenCTI Note objects."""

    @staticmethod
    def create(
        content: str,
        created: datetime,
        modified: datetime,
        organization_id: str,
        marking_ids: list[str],
        object_refs: list[str],
        abstract: str | None = None,
        authors: list[str] | None = None,
        labels: list[str] | None = None,
        external_references: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> NoteModel:
        """Create a Note model with OpenCTI custom properties.

        Args:
            content: The main content of the note
            created: When the note was created
            modified: When the note was last modified
            organization_id: The ID of the organization that created this note
            marking_ids: list of marking definition IDs to apply to the note
            object_refs: STIX Object identifiers this note applies to
            abstract: A brief summary of the note content
            authors: Names of the author(s) of this note
            labels: list of labels for this note
            external_references: list of external references
            **kwargs: Additional arguments to pass to NoteModel

        Returns:
            NoteModel: The created note model

        """
        if labels is None:
            labels = []

        custom_properties = kwargs.pop("custom_properties", {})

        data = {
            "type": "note",
            "spec_version": "2.1",
            "created": created,
            "modified": modified,
            "content": content,
            "object_refs": object_refs,
            "created_by_ref": organization_id,
            "object_marking_refs": marking_ids,
            "labels": labels,
            "external_references": external_references,
            "custom_properties": custom_properties,
            **kwargs,
        }

        if abstract:
            data["abstract"] = abstract
        if authors:
            data["authors"] = authors

        return NoteModel(**data)
