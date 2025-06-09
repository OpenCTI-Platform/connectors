"""The module defines the URLModel class, which represents a STIX 2.1 URL object."""

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    URL,
    _STIXBase21,
)


class URLModel(BaseSCOModel):
    """Model representing a URL in STIX 2.1 format."""

    value: str = Field(
        ...,
        description="The URL value, which MUST conform to RFC3986 (Uniform Resource Locator).",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return URL(**self.model_dump(exclude_none=True))
