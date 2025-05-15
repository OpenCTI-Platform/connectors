"""The module defines the DirectoryModel class, which represents a STIX 2.1 Directory object."""

from datetime import datetime
from typing import List, Optional

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import Directory, _STIXBase21  # type: ignore


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


def test_directory_model() -> None:
    """Test function to demonstrate the usage of DirectoryModel."""
    from datetime import UTC, datetime
    from uuid import uuid4

    now = datetime.now(UTC)

    # === Minimal Directory ===
    minimal = DirectoryModel(
        type="directory",
        spec_version="2.1",
        id=f"directory--{uuid4()}",
        path="C:\\Users\\Public\\Downloads",
    )

    print("=== MINIMAL DIRECTORY ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Directory ===
    full = DirectoryModel(
        type="directory",
        spec_version="2.1",
        id=f"directory--{uuid4()}",
        path="/opt/stealthdrop",
        path_enc="UTF-8",
        ctime=now.replace(microsecond=0),
        mtime=now.replace(microsecond=0),
        atime=now.replace(microsecond=0),
        contains_refs=[f"file--{uuid4()}", f"directory--{uuid4()}"],
    )

    print("\n=== FULL DIRECTORY ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_directory_model()
