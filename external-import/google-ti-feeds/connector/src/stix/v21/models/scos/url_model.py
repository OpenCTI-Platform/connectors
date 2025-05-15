"""The module defines the URLModel class, which represents a STIX 2.1 URL object."""

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import URL, _STIXBase21  # type: ignore


class URLModel(BaseSCOModel):
    """Model representing a URL in STIX 2.1 format."""

    value: str = Field(
        ...,
        description="The URL value, which MUST conform to RFC3986 (Uniform Resource Locator).",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return URL(**self.model_dump(exclude_none=True))


def test_url_model() -> None:
    """Test function to demonstrate the usage of URLModel."""
    from uuid import uuid4

    # === Minimal URL ===
    minimal = URLModel(
        type="url",
        spec_version="2.1",
        id=f"url--{uuid4()}",
        value="https://exploit.hydra-spike.org/payload.exe",
    )

    print("=== MINIMAL URL ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full URL ===
    full = URLModel(
        type="url",
        spec_version="2.1",
        id=f"url--{uuid4()}",
        value="https://secure.shadowops.com/docs/index.php?ref=phish&lang=en",
    )

    print("\n=== FULL URL ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_url_model()
