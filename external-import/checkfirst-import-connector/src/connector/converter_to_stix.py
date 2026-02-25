from __future__ import annotations

"""STIX conversion helpers for the Checkfirst connector.

Converts API rows into STIX 2.1 objects using:
- `OrganizationAuthor` / `TLPMarking` from `connectors_sdk.models`
- `pycti.*.generate_id()` for deterministic IDs on OpenCTI custom entities
"""

from datetime import datetime
from typing import Literal

import stix2
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from pycti import (
    Campaign,
    Channel,
    CustomObjectChannel,
    CustomObservableMediaContent,
    IntrusionSet,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)


class ConverterToStix:
    """Convert API rows into STIX 2.1 objects + bundles."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: Literal[
            "clear",
            "white",
            "green",
            "amber",
            "amber+strict",
            "red",
        ] = "clear",
    ):
        self.helper = helper

        _author_model = OrganizationAuthor(name="CheckFirst")
        self.author = _author_model.to_stix2_object()
        self.author_id = self.author.id

        _tlp_model = TLPMarking(level=tlp_level.lower())
        self.tlp_marking = _tlp_model.to_stix2_object()
        self.tlp_marking_id = self.tlp_marking.id

        self.intrusion_set = self._create_intrusion_set()
        self.campaign = self._create_campaign()
        self.campaign_attributed_to_ims = self.create_relationship(
            source_id=self.campaign.id,
            relationship_type="attributed-to",
            target_id=self.intrusion_set.id,
        )

    def _create_intrusion_set(self) -> stix2.IntrusionSet:
        return stix2.IntrusionSet(
            id=IntrusionSet.generate_id(name="Pravda Network"),
            name="Pravda Network",
            description=(
                "Information Manipulation Set (IMS) conducting pro-Russian "
                "influence operations through a network of 190+ websites"
            ),
            aliases=["Portal-Kombat", "Pravda Network IMS"],
            goals=[
                "Undermine Western unity",
                "Promote Russian narratives",
                "Influence public opinion",
            ],
            resource_level="government",
            primary_motivation="ideology",
            created_by_ref=self.author_id,
            object_marking_refs=[self.tlp_marking_id],
            allow_custom=True,
        )

    def _create_campaign(self) -> stix2.Campaign:
        return stix2.Campaign(
            id=Campaign.generate_id(
                name="Pravda Network Campaigns",
            ),
            name="Pravda Network Campaigns",
            description=(
                "Coordinated FIMI campaign spreading pro-Russian narratives "
                "across multiple countries and languages"
            ),
            aliases=["Portal-Kombat Campaign", "Pravda"],
            first_seen="2023-09-01T00:00:00Z",
            objective=(
                "Manipulate public opinion, undermine trust in Western "
                "institutions, justify Russian actions"
            ),
            created_by_ref=self.author_id,
            object_marking_refs=[self.tlp_marking_id],
            allow_custom=True,
        )

    def create_channel(
        self, *, name: str, source_url: str | None = None
    ) -> CustomObjectChannel:
        external_refs: list[stix2.ExternalReference] = []
        if source_url:
            external_refs.append(
                stix2.ExternalReference(source_name="source", url=source_url)
            )

        channel = CustomObjectChannel(
            id=Channel.generate_id(name=name),
            name=name,
            channel_types=["website"],
            created_by_ref=self.author_id,
            object_marking_refs=[self.tlp_marking_id],
            external_references=external_refs,
            allow_custom=True,
        )
        return channel

    def create_media_content(
        self,
        *,
        title: str | None,
        description: str | None,
        url: str,
        publication_date: datetime,
    ) -> CustomObservableMediaContent:
        media = CustomObservableMediaContent(
            title=title,
            description=description,
            url=url,
            publication_date=publication_date,
            object_marking_refs=[self.tlp_marking_id],
            custom_properties={
                "x_opencti_created_by_ref": self.author_id,
            },
        )
        return media

    def create_url(self, *, value: str) -> stix2.URL:
        return stix2.URL(
            value=value,
            object_marking_refs=[self.tlp_marking_id],
            custom_properties={
                "x_opencti_created_by_ref": self.author_id,
            },
        )

    def create_relationship(
        self,
        *,
        source_id: str,
        relationship_type: str,
        target_id: str,
        start_time: datetime | None = None,
    ) -> stix2.Relationship:
        rel = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type,
                source_id,
                target_id,
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author_id,
            object_marking_refs=[self.tlp_marking_id],
            allow_custom=True,
            start_time=start_time,
        )
        return rel
