"""The module defines the EmailAddressModel class, which represents a STIX 2.1 Email Address object."""

from typing import Optional

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import EmailAddress, _STIXBase21  # type: ignore


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


def test_email_address_model() -> None:
    """Test function to demonstrate the usage of EmailAddressModel."""
    from uuid import uuid4

    # === Minimal Email Address ===
    minimal = EmailAddressModel(
        type="email-addr",
        spec_version="2.1",
        id=f"email-addr--{uuid4()}",
        value="ransom.note@protonmail.com",
    )

    print("=== MINIMAL EMAIL ADDRESS ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Email Address ===
    full = EmailAddressModel(
        type="email-addr",
        spec_version="2.1",
        id=f"email-addr--{uuid4()}",
        value="ghost.lead@hydra-spike.ru",
        display_name="Ghost Lead",
        belongs_to_ref=f"user-account--{uuid4()}",
    )

    print("\n=== FULL EMAIL ADDRESS ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_email_address_model()
