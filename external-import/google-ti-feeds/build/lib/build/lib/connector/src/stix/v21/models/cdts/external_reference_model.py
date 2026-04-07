"""The module defines the ExternalReferenceModel class, which represents an external reference in STIX 2.1 format."""

from connector.src.stix.v21.models.ovs.hashing_algorithm_ov_enums import HashAlgorithmOV
from pydantic import BaseModel, Field


class ExternalReferenceModel(BaseModel):
    """Model representing an external reference in STIX 2.1 format."""

    source_name: str = Field(
        ..., description="The name of the source that defines the reference."
    )
    description: str | None = Field(
        default=None,
        description="A human-readable description of the external reference.",
    )
    url: str | None = Field(
        default=None, description="A URL pointing to an external resource."
    )
    hashes: dict[HashAlgorithmOV, str] | None = Field(
        default=None,
        description="A dictionary of hashes for the content referenced by the URL. Keys must be valid hash algorithms.",
    )
    external_id: str | None = Field(
        default=None,
        description="An external identifier for the referenced content.",
    )

    model_config = {"use_enum_values": True}
