"""The module defines the SoftwareModel class, which represents a STIX 2.1 Software object."""

from typing import List, Optional

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import Software, _STIXBase21  # type: ignore


class SoftwareModel(BaseSCOModel):
    """Model representing a Software in STIX 2.1 format."""

    name: str = Field(..., description="The name of the software.")
    cpe: Optional[str] = Field(
        default=None,
        description="CPE v2.3 entry for the software from the official NVD CPE Dictionary.",
    )
    languages: Optional[List[str]] = Field(
        default=None,
        description="List of supported languages (ISO 639-2 codes).",
    )
    vendor: Optional[str] = Field(
        default=None, description="The name of the software vendor."
    )
    version: Optional[str] = Field(
        default=None, description="Version of the software."
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Software(**self.model_dump(exclude_none=True))


def test_software_model() -> None:
    """Test function to demonstrate the usage of SoftwareModel."""
    from uuid import uuid4

    # === Minimal Software ===
    minimal = SoftwareModel(
        type="software",
        spec_version="2.1",
        id=f"software--{uuid4()}",
        name="OpenSSH",
    )

    print("=== MINIMAL SOFTWARE ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Software ===
    full = SoftwareModel(
        type="software",
        spec_version="2.1",
        id=f"software--{uuid4()}",
        name="Apache HTTP Server",
        vendor="Apache Software Foundation",
        version="2.4.57",
        cpe="cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*",
        languages=["eng", "jpn"],
    )

    print("\n=== FULL SOFTWARE ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_software_model()
