"""The module defines the DirectoryModel class, which represents a STIX 2.1 Directory object."""

from datetime import datetime
from typing import List, Optional

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    Directory,
    _STIXBase21,
)


class DirectoryModel(BaseSCOModel):
    """Model representing a Directory in STIX 2.1 format."""

    path: str = Field(
        ...,
        description="The observed path to the directory on the file system.",
    )
    path_enc: Optional[str] = Field(
        default=None,
        description="Character encoding of the path if it's non-Unicode. MUST use IANA character set registry name.",
    )
    ctime: Optional[datetime] = Field(
        default=None, description="Timestamp when the directory was created."
    )
    mtime: Optional[datetime] = Field(
        default=None,
        description="Timestamp when the directory was last modified.",
    )
    atime: Optional[datetime] = Field(
        default=None,
        description="Timestamp when the directory was last accessed.",
    )
    contains_refs: Optional[List[str]] = Field(
        default=None,
        description="List of identifiers referring to SCOs of type 'file' or 'directory' contained within this directory.",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Directory(**self.model_dump(exclude_none=True))
