"""The module defines the EmailAddressModel class, which represents a STIX 2.1 Email Address object."""

from typing import Optional

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    EmailAddress,
    _STIXBase21,
)


class EmailAddressModel(BaseSCOModel):
    """Model representing an Email Address in STIX 2.1 format."""

    value: str = Field(
        ...,
        description="The email address, conforming to addr-spec from RFC5322 (e.g., jane.smith@example.com). MUST NOT include a display name.",
    )
    display_name: Optional[str] = Field(
        default=None,
        description="The human-readable display name for this address, per RFC5322 (e.g., Jane Smith).",
    )
    belongs_to_ref: Optional[str] = Field(
        default=None,
        description="Reference to a user-account SCO object that this email address belongs to. MUST point to type 'user-account'.",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return EmailAddress(**self.model_dump(exclude_none=True))
