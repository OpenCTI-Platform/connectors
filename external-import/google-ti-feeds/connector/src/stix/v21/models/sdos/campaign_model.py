"""The module contains the CampaignModel class, which represents a STIX 2.1 Campaign object."""

from datetime import datetime
from typing import List, Optional

from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field
from stix2.v21 import Campaign, _STIXBase21  # type: ignore


class CampaignModel(BaseSDOModel):
    """Model representing a Campaign in STIX 2.1 format."""

    name: str = Field(..., description="A name used to identify the Campaign.")
    description: Optional[str] = Field(
        default=None,
        description="A description that provides more details and context about the Campaign, potentially including its purpose and its key characteristics.",
    )
    aliases: Optional[List[str]] = Field(
        default=None,
        description="Alternative names used to identify this Campaign.",
    )
    first_seen: Optional[datetime] = Field(
        default=None,
        description="The time that this Campaign was first seen. May be updated if earlier sightings are received.",
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="The time that this Campaign was last seen. Must be >= first_seen. May be updated with newer sighting data.",
    )
    objective: Optional[str] = Field(
        default=None,
        description="Defines the Campaign’s primary goal, objective, desired outcome, or intended effect — what the Threat Actor or Intrusion Set hopes to accomplish.",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Campaign(**self.model_dump(exclude_none=True))


def test_campaign_model() -> None:
    """Test function to demonstrate the usage of CampaignModel."""
    from datetime import datetime, timedelta
    from uuid import uuid4

    from connector.src.stix.v21.models.cdts.external_reference_model import (
        ExternalReferenceModel,
    )

    # === Minimal Campaign ===
    minimal = CampaignModel(
        type="campaign",
        spec_version="2.1",
        id=f"campaign--{uuid4()}",
        created=datetime.now(),
        modified=datetime.now(),
        name="Operation Smoke Screen",
    )

    print("=== MINIMAL CAMPAIGN ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Fully Populated Campaign ===
    now = datetime.now()
    full = CampaignModel(
        type="campaign",
        spec_version="2.1",
        id=f"campaign--{uuid4()}",
        created=now,
        modified=now,
        name="Operation Black Aurora",
        description="A coordinated campaign targeting satellite uplinks and infrastructure supply chains.",
        aliases=["Aurora-X", "Shadowfire", "Red Echo"],
        first_seen=now - timedelta(days=120),
        last_seen=now - timedelta(days=5),
        objective="Disrupt global comms infrastructure and exfiltrate IP tied to aerospace R&D.",
        labels=["espionage", "infrastructure-targeting", "covert"],
        confidence=85,
        lang="en",
        revoked=False,
        created_by_ref=f"identity--{uuid4()}",
        external_references=[
            ExternalReferenceModel(
                source_name="mitre-attack",
                external_id="G0001",
                url="https://attack.mitre.org/groups/G0001/",
                description="APT1: Comment Crew",
            )
        ],
        object_marking_refs=[f"marking-definition--{uuid4()}"],
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": f"marking-definition--{uuid4()}",
            }
        ],
        extensions={
            f"extension-definition--{uuid4()}": {
                "extension_type": "new-sdo",
                "tactics_used": ["initial-access", "lateral-movement"],
            }
        },
    )

    print("\n=== FULL CAMPAIGN ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_campaign_model()
