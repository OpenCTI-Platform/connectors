"""The module defines a FileModel class that represents a file in STIX 2.1 format."""

from datetime import datetime
from typing import Any

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    File,
    _STIXBase21,
)


class FileModel(BaseSCOModel):
    """FileModel class represents a file in STIX 2.1 format."""

    extensions: dict[str, dict[str, Any]] | None = Field(
        default=None,
        description="dictionary of file extensions (e.g., ntfs-ext, pdf-ext, archive-ext). Keys MUST be extension names.",
    )

    hashes: dict[str, str] | None = Field(
        default=None,
        description="dictionary of hash algorithm names and hash values. Keys MUST come from hash-algorithm-ov.",
    )

    size: int | None = Field(
        default=None,
        ge=0,
        description="Size of the file in bytes. MUST NOT be negative.",
    )
    name: str | None = Field(default=None, description="Name of the file as observed.")
    name_enc: str | None = Field(
        default=None,
        description="Character encoding used for the file name, per IANA character set registry.",
    )

    magic_number_hex: str | None = Field(
        default=None,
        description="Hexadecimal magic number associated with the file format.",
    )
    mime_type: str | None = Field(
        default=None,
        description="MIME type of the file. SHOULD follow IANA media type registry.",
    )

    ctime: datetime | None = Field(
        default=None, description="Timestamp when the file was created."
    )
    mtime: datetime | None = Field(
        default=None, description="Timestamp when the file was last modified."
    )
    atime: datetime | None = Field(
        default=None, description="Timestamp when the file was last accessed."
    )

    parent_directory_ref: str | None = Field(
        default=None,
        description="Reference to a directory SCO representing this file's parent. MUST be of type 'directory'.",
    )
    contains_refs: list[str] | None = Field(
        default=None,
        description="list of references to other SCOs contained within the file (e.g., embedded IPs, appended files).",
    )
    content_ref: str | None = Field(
        default=None,
        description="Reference to an Artifact object representing this file's content.",
    )

    @model_validator(mode="after")
    def validate_cross_refs(self) -> "FileModel":
        """Validate the cross-references in the FileModel instance."""
        if self.parent_directory_ref and not self.parent_directory_ref.startswith(
            "directory--"
        ):
            raise ValueError(
                "'parent_directory_ref' must reference an object of type 'directory'."
            )
        if self.content_ref and not self.content_ref.startswith("artifact--"):
            raise ValueError(
                "'content_ref' must reference an object of type 'artifact'."
            )
        return self

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return File(**self.model_dump(exclude_none=True))
