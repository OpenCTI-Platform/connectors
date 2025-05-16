"""The module defines the ArtifactModel class, which represents a STIX 2.1 Artifact object."""

from typing import Dict, Optional

from connector.src.stix.v21.models.ovs.encryption_algorithm_ov_enums import (
    EncryptionAlgorithmOV,
)
from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field, model_validator
from stix2.v21 import Artifact, _STIXBase21  # type: ignore


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


def test_artifact_model() -> None:
    """Test function to demonstrate the usage of ArtifactModel."""
    from uuid import uuid4

    # === Minimal Artifact: base64 payload only ===
    minimal = ArtifactModel(
        type="artifact",
        spec_version="2.1",
        id=f"artifact--{uuid4()}",
        mime_type="application/x-dosexec",
        payload_bin=b"FakeMZHeaderData==",  # Base64-safe binary
    )

    print("=== MINIMAL ARTIFACT (payload_bin) ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Artifact: URL-based delivery + encryption ===
    full = ArtifactModel(
        type="artifact",
        spec_version="2.1",
        id=f"artifact--{uuid4()}",
        mime_type="application/zip",
        url="https://evil.example.com/dropper_v3.zip",
        hashes={
            "SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        encryption_algorithm=EncryptionAlgorithmOV.AES_256_GCM,
        decryption_key="hydra2025$@!",
        object_marking_refs=[f"marking-definition--{uuid4()}"],
        granular_markings=[
            {
                "selectors": ["mime_type", "url"],
                "marking_ref": f"marking-definition--{uuid4()}",
            }
        ],
        extensions={
            f"extension-definition--{uuid4()}": {
                "extension_type": "new-sco",
                "source": "sandbox-exfil",
            }
        },
    )

    print("\n=== FULL ARTIFACT (url + encryption) ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_artifact_model()
