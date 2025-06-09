"""The module defines the DomainNameModel class, which represents a STIX 2.1 Domain Name object."""

from typing import List, Optional

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    DomainName,
    _STIXBase21,
)


class DomainNameModel(BaseSCOModel):
    """Model representing a Domain Name in STIX 2.1 format."""

    value: str = Field(
        ...,
        description="The domain name, which MUST conform to RFC1034 and RFC5890.",
    )
    resolves_to_refs: Optional[List[str]] = Field(
        default=None,
        description="(Deprecated) List of references to SCOs of type 'ipv4-addr', 'ipv6-addr', or 'domain-name' that this domain resolves to.",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return DomainName(**self.model_dump(exclude_none=True), allow_custom=True)
