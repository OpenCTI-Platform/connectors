"""The module defines the SoftwareModel class, which represents a STIX 2.1 Software object."""

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    Software,
    _STIXBase21,
)


class SoftwareModel(BaseSCOModel):
    """Model representing a Software in STIX 2.1 format."""

    name: str = Field(..., description="The name of the software.")
    cpe: str | None = Field(
        default=None,
        description="CPE v2.3 entry for the software from the official NVD CPE dictionary.",
    )
    languages: list[str] | None = Field(
        default=None,
        description="list of supported languages (ISO 639-2 codes).",
    )
    vendor: str | None = Field(
        default=None, description="The name of the software vendor."
    )
    version: str | None = Field(default=None, description="Version of the software.")

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Software(**self.model_dump(exclude_none=True))
