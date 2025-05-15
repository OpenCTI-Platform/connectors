"""The module defines the ObservedDataModel class, which represents a STIX 2.1 Observed Data object."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
from stix2.v21 import ObservedData, _STIXBase21  # type: ignore


class ObservedDataModel(BaseSDOModel):
    """Model representing an Observed Data in STIX 2.1 format."""

    first_observed: datetime = Field(
        ..., description="Start time of the observation window."
    )
    last_observed: datetime = Field(
        ...,
        description="End time of the observation window. MUST be >= first_observed.",
    )
    number_observed: int = Field(
        ...,
        ge=1,
        le=999_999_999,
        description="Number of times the data was observed. MUST be an integer between 1 and 999,999,999 inclusive.",
    )
    objects: Optional[Dict[str, Dict[str, Any]]] = Field(
        default=None,
        description="(Deprecated) Dictionary of SCOs observed. MUST NOT be present if object_refs is set. Will be removed in future STIX versions.",
    )
    object_refs: Optional[List[str]] = Field(
        default=None,
        description="List of references to SCOs/SROs observed. MUST NOT be set if 'objects' is present.",
    )

    @model_validator(mode="after")
    def validate_observed_data(self) -> "ObservedDataModel":
        """Validate the ObservedDataModel instance."""
        if self.last_observed < self.first_observed:
            raise ValueError(
                "'last_observed' must be greater than or equal to 'first_observed'."
            )
        if self.objects and self.object_refs:
            raise ValueError(
                "Only one of 'objects' or 'object_refs' may be set—not both."
            )
        if not self.objects and not self.object_refs:
            raise ValueError(
                "At least one of 'objects' or 'object_refs' must be set."
            )
        return self

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return ObservedData(**self.model_dump(exclude_none=True))


def test_observed_data_model() -> None:
    """Test function to demonstrate the usage of ObservedDataModel."""
    from datetime import UTC, datetime, timedelta
    from uuid import uuid4

    now = datetime.now(UTC)

    # === Minimal ObservedData ===
    minimal = ObservedDataModel(
        type="observed-data",
        spec_version="2.1",
        id=f"observed-data--{uuid4()}",
        created=now,
        modified=now,
        first_observed=now - timedelta(minutes=5),
        last_observed=now,
        number_observed=1,
        object_refs=[f"file--{uuid4()}"],
    )

    print("=== MINIMAL OBSERVED DATA ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full ObservedData ===
    full = ObservedDataModel(
        type="observed-data",
        spec_version="2.1",
        id=f"observed-data--{uuid4()}",
        created=now,
        modified=now,
        first_observed=now - timedelta(hours=3),
        last_observed=now - timedelta(hours=1),
        number_observed=5,
        objects={  # Deprecated but still technically allowed
            "0": {
                "type": "file",
                "name": "payload.exe",
                "hashes": {"SHA-256": "deadbeef" * 8},
            },
            "1": {
                "type": "network-traffic",
                "dst_ref": f"ipv4-addr--{uuid4()}",
                "protocols": ["tcp"],
                "src_port": 4444,
                "dst_port": 80,
            },
            "2": {"type": "ipv4-addr", "value": "203.0.113.42"},
        },
        labels=["evidence", "sandbox-observation"],
        confidence=60,
        lang="en",
        revoked=False,
        created_by_ref=f"identity--{uuid4()}",
        external_references=[],
        object_marking_refs=[f"marking-definition--{uuid4()}"],
        granular_markings=[
            {
                "selectors": ["number_observed", "first_observed"],
                "marking_ref": f"marking-definition--{uuid4()}",
            }
        ],
        extensions={
            f"extension-definition--{uuid4()}": {
                "extension_type": "new-sdo",
                "source": "detonation-sandbox",
            }
        },
    )

    print("\n=== FULL OBSERVED DATA ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_observed_data_model()
