"""The module contains the OctiCampaignModel class, which represents an OpenCTI Campaign."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from connector.src.stix.v21.models.sdos.campaign_model import CampaignModel


class OctiCampaignModel:
    """Model for creating OpenCTI Campaign objects."""

    @staticmethod
    def create(
        name: str,
        organization_id: str,
        marking_ids: list[str],
        description: Optional[str] = None,
        created: Optional[datetime] = None,
        modified: Optional[datetime] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
        objective: Optional[str] = None,
        aliases: Optional[List[str]] = None,
        labels: Optional[List[str]] = None,
        external_references: Optional[List[Dict[str, Any]]] = None,
        custom_properties: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> CampaignModel:
        """Create a Campaign model.

        Args:
            name: The name of the campaign
            organization_id: The ID of the organization that created this campaign
            marking_ids: List of marking definition IDs to apply to the campaign
            description: Description of the campaign
            created: Time the campaign was created
            modified: Time the campaign was last modified
            first_seen: Time the campaign was first seen
            last_seen: Time the campaign was last seen
            objective: Primary goal or objective of the campaign
            aliases: Alternative names for the campaign
            labels: Labels to apply to the campaign
            external_references: External references related to the campaign
            custom_properties: Additional custom properties to include in the campaign
            **kwargs: Additional arguments to pass to CampaignModel

        Returns:
            CampaignModel: The created campaign model

        """
        merged_custom_properties = custom_properties.copy() if custom_properties else {}

        data = {
            "type": "campaign",
            "spec_version": "2.1",
            "custom_properties": merged_custom_properties,
            "created": created or kwargs.pop("created", datetime.now()),
            "modified": modified or kwargs.pop("modified", datetime.now()),
            "name": name,
            "description": description,
            "aliases": aliases,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "objective": objective,
            "labels": labels,
            "external_references": external_references,
            "created_by_ref": organization_id,
            "object_marking_refs": marking_ids,
            **kwargs,
        }

        return CampaignModel(**data)
