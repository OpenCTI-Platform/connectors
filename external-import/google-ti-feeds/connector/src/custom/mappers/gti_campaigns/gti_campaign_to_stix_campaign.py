"""Converts a GTI campaign to a STIX campaign object."""

from datetime import datetime, timezone
from typing import Any

from connector.src.custom.models.gti.gti_campaign_model import (
    CampaignModel,
    GTICampaignData,
)
from connector.src.stix.octi.models.campaign_model import OctiCampaignModel
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.stix.v21.models.cdts.external_reference_model import (
    ExternalReferenceModel,
)
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)
from stix2.v21 import Campaign  # type: ignore


class GTICampaignToSTIXCampaign(BaseMapper):
    """Converts a GTI campaign to a STIX campaign object."""

    def __init__(
        self,
        campaign: GTICampaignData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ) -> None:
        """Initialize the GTICampaignToSTIXCampaign object.

        Args:
            campaign (GTICampaignData): The GTI campaign data to convert.
            organization (OrganizationAuthor): The organization identity object.
            tlp_marking (TLPMarking): The TLP marking definition.

        """
        self.campaign = campaign
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> Campaign:
        """Convert the GTI campaign to a STIX campaign object.

        Returns:
            Campaign: The STIX campaign object.

        """
        if not hasattr(self.campaign, "attributes") or not self.campaign.attributes:
            raise ValueError("Invalid GTI campaign data")

        attributes = self.campaign.attributes

        name = attributes.name
        if len(name) < 2:
            raise ValueError("Campaign name must be at least 2 characters long")

        created = datetime.fromtimestamp(attributes.creation_date, tz=timezone.utc)
        modified = datetime.fromtimestamp(
            attributes.last_modification_date, tz=timezone.utc
        )
        first_seen, last_seen = self._get_activity_timestamps(attributes)
        labels = self._extract_labels(attributes)
        external_references = self._build_external_references(attributes)

        campaign_model = OctiCampaignModel.create(
            name=name,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            description=attributes.description,
            created=created,
            modified=modified,
            first_seen=first_seen,
            last_seen=last_seen,
            labels=labels,
            external_references=[
                ref.model_dump(exclude_none=True) for ref in external_references
            ],
        )

        return campaign_model

    @staticmethod
    def _get_activity_timestamps(
        attributes: CampaignModel,
    ) -> tuple[datetime | None, datetime | None]:
        """Extract first and last seen timestamps from attributes.

        Args:
            attributes: The campaign attributes

        Returns:
            tuple: (first_seen, last_seen) datetime objects or None

        """
        first_seen = None
        last_seen = None

        # Extract from first_seen_details
        if attributes.first_seen_details:
            for detail in attributes.first_seen_details:
                if detail.value:
                    try:
                        first_seen = datetime.fromisoformat(
                            detail.value.replace("Z", "+00:00")
                        )
                        break
                    except (ValueError, AttributeError):
                        continue

        # Extract from last_seen_details
        if attributes.last_seen_details:
            for detail in attributes.last_seen_details:
                if detail.value:
                    try:
                        last_seen = datetime.fromisoformat(
                            detail.value.replace("Z", "+00:00")
                        )
                        break
                    except (ValueError, AttributeError):
                        continue

        return first_seen, last_seen

    @staticmethod
    def _extract_labels(attributes: CampaignModel) -> list[str]:
        """Extract labels from campaign attributes.

        Args:
            attributes: The campaign attributes

        Returns:
            list: Extracted labels

        """
        labels = []
        if attributes.tags_details:
            for tag in attributes.tags_details:
                if tag.value and tag.value not in labels:
                    labels.append(tag.value)
        return labels

    def _build_external_references(
        self, attributes: CampaignModel
    ) -> list[ExternalReferenceModel]:
        """Build external references from campaign attributes.

        Args:
            attributes: The campaign attributes

        Returns:
            list: External references

        """
        external_references = []

        # Add GTI campaign reference
        if self.campaign.id and attributes.name:
            external_reference = ExternalReferenceModel(
                source_name=f"[GTI] Campaign {attributes.name}",
                description="Google Threat Intelligence Campaign Link",
                url=f"https://www.virustotal.com/gui/collection/{self.campaign.id}",
            )
            external_references.append(external_reference)

        return external_references

    @staticmethod
    def create_relationship(
        src_entity: Any, relation_type: str, target_entity: Any
    ) -> Any:
        """Create a relationship between a campaign and another entity.

        Args:
            src_entity: The source entity
            relation_type: The relationship type
            target_entity: The target entity

        Returns:
            OctiRelationshipModel: The relationship object

        """
        if not any(
            "Campaign" in str(type(entity).__name__)
            for entity in [src_entity, target_entity]
        ):
            return None

        return OctiRelationshipModel.create(
            relationship_type=relation_type,
            source_ref=src_entity.id,
            target_ref=target_entity.id,
            organization_id=src_entity.created_by_ref,
            marking_ids=src_entity.object_marking_refs,
            created=datetime.now(tz=timezone.utc),
            modified=datetime.now(tz=timezone.utc),
            description=f"{type(src_entity).__name__} {relation_type} {type(target_entity).__name__}",
        )
