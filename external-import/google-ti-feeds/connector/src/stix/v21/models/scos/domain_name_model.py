"""The module defines the DomainNameModel class, which represents a STIX 2.1 Domain Name object."""

from typing import List, Optional

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import DomainName, _STIXBase21  # type: ignore


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
        return DomainName(**self.model_dump(exclude_none=True))


def test_domain_name_model() -> None:
    """Test function to demonstrate the usage of DomainNameModel."""
    from uuid import uuid4

    # === Minimal Domain Name ===
    minimal = DomainNameModel(
        type="domain-name",
        spec_version="2.1",
        id=f"domain-name--{uuid4()}",
        value="command.hydra-net.org",
    )

    print("=== MINIMAL DOMAIN NAME ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Domain Name ===
    full = DomainNameModel(
        type="domain-name",
        spec_version="2.1",
        id=f"domain-name--{uuid4()}",
        value="update.shadow-dropper.net",
        resolves_to_refs=[f"ipv4-addr--{uuid4()}", f"ipv6-addr--{uuid4()}"],
    )

    print("\n=== FULL DOMAIN NAME ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_domain_name_model()
