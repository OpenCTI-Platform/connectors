"""The module contains the OctiCampaignModel class, which represents an OpenCTI Campaign."""

from datetime import datetime
from typing import Any, List, Optional

from connector.src.stix.v21.models.sdos.campaign_model import CampaignModel


class OctiCampaignModel:
    """Model for creating OpenCTI Campaign objects."""

    @staticmethod
    def create(
        name: str,
        organization_id: str,
        marking_ids: list[str],
        description: Optional[str] = None,
        aliases: Optional[List[str]] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
        objective: Optional[str] = None,
        labels: Optional[List[str]] = None,
        external_references: Optional[List[Any]] = None,
        **kwargs: Any,
    ) -> CampaignModel:
        """Create a Campaign model.

        Args:
            name: The name of the campaign
            organization_id: The ID of the organization that created this campaign
            marking_ids: List of marking definition IDs to apply to the campaign
            description: Description of the campaign
            aliases: Alternative names for the campaign
            first_seen: First time the campaign was observed
            last_seen: Last time the campaign was observed
            objective: The campaign's primary objective
            labels: Labels to apply to the campaign
            external_references: External references for the campaign
            **kwargs: Additional arguments to pass to CampaignModel

        Returns:
            CampaignModel: The created campaign model

        """
        data = {
            "type": "campaign",
            "spec_version": "2.1",
            "created": kwargs.pop("created", datetime.now()),
            "modified": kwargs.pop("modified", datetime.now()),
            "name": name,
            "description": description,
            "aliases": aliases,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "objective": objective,
            "labels": labels,
            "created_by_ref": organization_id,
            "object_marking_refs": marking_ids,
            **kwargs,
        }

        if external_references:
            data["external_references"] = external_references

        return CampaignModel(**data)
