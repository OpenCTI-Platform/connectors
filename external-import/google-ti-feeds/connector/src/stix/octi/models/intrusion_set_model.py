"""The module contains the OctiIntrusionSetModel class, which represents an OpenCTI Intrusion Set."""

from datetime import datetime
from typing import Any

from connector.src.stix.v21.models.sdos.intrusion_set_model import IntrusionSetModel


class OctiIntrusionSetModel:
    """Model for creating OpenCTI Intrusion Set objects."""

    @staticmethod
    def create(
        name: str,
        organization_id: str,
        marking_ids: list[str],
        description: str | None = None,
        aliases: list[str] | None = None,
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
        goals: list[str] | None = None,
        resource_level: str | None = None,
        primary_motivation: str | None = None,
        secondary_motivations: list[str] | None = None,
        labels: list[str] | None = None,
        **kwargs: Any,
    ) -> IntrusionSetModel:
        """Create an Intrusion Set model.

        Args:
            name: The name of the intrusion set
            organization_id: The ID of the organization that created this intrusion set
            marking_ids: list of marking definition IDs to apply to the intrusion set
            description: Description of the intrusion set
            aliases: Alternative names for the intrusion set
            first_seen: First time the intrusion set was observed
            last_seen: Last time the intrusion set was observed
            goals: High-level goals of the intrusion set
            resource_level: Resource level of the intrusion set
            primary_motivation: Primary motivation of the intrusion set
            secondary_motivations: Secondary motivations of the intrusion set
            labels: Labels to apply to the intrusion set
            **kwargs: Additional arguments to pass to IntrusionSetModel

        Returns:
            IntrusionSetModel: The created intrusion set model

        """
        data = {
            "type": "intrusion-set",
            "spec_version": "2.1",
            "created": kwargs.pop("created", datetime.now()),
            "modified": kwargs.pop("modified", datetime.now()),
            "name": name,
            "description": description,
            "aliases": aliases,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "goals": goals,
            "resource_level": resource_level,
            "primary_motivation": primary_motivation,
            "secondary_motivations": secondary_motivations,
            "labels": labels,
            "created_by_ref": organization_id,
            "object_marking_refs": marking_ids,
            **kwargs,
        }

        return IntrusionSetModel(**data)
