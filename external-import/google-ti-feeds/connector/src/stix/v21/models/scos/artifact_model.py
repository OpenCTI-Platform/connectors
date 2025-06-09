"""The module defines the ArtifactModel class, which represents a STIX 2.1 Artifact object."""

from typing import Dict, Optional

from connector.src.stix.v21.models.ovs.encryption_algorithm_ov_enums import (
    EncryptionAlgorithmOV,
)
from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    Artifact,
    _STIXBase21,
)


class ArtifactModel(BaseSCOModel):
    """Model representing an Artifact in STIX 2.1 format."""

    mime_type: Optional[str] = Field(
        default=None,
        description="IANA media type of the artifact. SHOULD follow the IANA media type registry format if possible.",
    )
    payload_bin: Optional[bytes] = Field(
        default=None,
        description="Base64-encoded binary data of the artifact. MUST NOT be used if 'url' is present.",
    )
    url: Optional[str] = Field(
        default=None,
        description="URL to the artifact content. MUST NOT be used if 'payload_bin' is present.",
    )
    hashes: Optional[Dict[str, str]] = Field(
        default=None,
        description="Dictionary of hashes for the artifact. MUST be present if 'url' is used. Keys MUST come from hash-algorithm-ov.",
    )
    encryption_algorithm: Optional[EncryptionAlgorithmOV] = Field(
        default=None,
        description="Encryption algorithm used on the payload or URL content. MUST come from encryption-algorithm-enum.",
    )
    decryption_key: Optional[str] = Field(
        default=None,
        description="Decryption key for encrypted content. MUST NOT be present unless 'encryption_algorithm' is set.",
    )

    @model_validator(mode="after")
    def validate_artifact_logic(self) -> "ArtifactModel":
        """Validate the ArtifactModel instance."""
        if self.payload_bin and self.url:
            raise ValueError("Only one of 'payload_bin' or 'url' may be set—not both.")
        if self.url and not self.hashes:
            raise ValueError("'hashes' MUST be provided when 'url' is set.")
        if self.decryption_key and not self.encryption_algorithm:
            raise ValueError(
                "'decryption_key' MUST NOT be set unless 'encryption_algorithm' is also set."
            )
        return self

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Artifact(**self.model_dump(exclude_none=True))
