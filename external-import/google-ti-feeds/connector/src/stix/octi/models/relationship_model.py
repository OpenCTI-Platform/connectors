"""The module contains the OctiRelationshipModel class, which represents an OpenCTI Relationship."""

from datetime import datetime
from typing import Any, List, Optional

from connector.src.stix.v21.models.sros.relationship_model import RelationshipModel


class OctiRelationshipModel:
    """Model for creating OpenCTI Relationship objects."""

    @staticmethod
    def create(
        relationship_type: str,
        source_ref: str,
        target_ref: str,
        organization_id: str,
        marking_ids: List[str],
        created: datetime,
        modified: datetime,
        description: Optional[str] = None,
        **kwargs: Any,
    ) -> RelationshipModel:
        """Create a Relationship model with OpenCTI custom properties.

        Args:
            relationship_type: The type of relationship (e.g., 'targets', 'indicates')
            source_ref: The ID of the source entity
            target_ref: The ID of the target entity
            organization_id: The ID of the organization that created this relationship
            marking_ids: List of marking definition IDs to apply to the relationship
            created: When the relationship was created
            modified: When the relationship was last modified
            description: Description of the relationship
            **kwargs: Additional arguments to pass to RelationshipModel

        Returns:
            RelationshipModel: The created relationship model

        """
        data = {
            "type": "relationship",
            "spec_version": "2.1",
            "created": created,
            "modified": modified,
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
            "description": description,
            "created_by_ref": organization_id,
            "object_marking_refs": marking_ids,
            **kwargs,
        }

        return RelationshipModel(**data)

    @staticmethod
    def create_from_report(
        relationship_type: str,
        report_id: str,
        target_ref: str,
        organization_id: str,
        marking_ids: List[str],
        created: datetime,
        modified: datetime,
        report_name: Optional[str] = None,
        target_name: Optional[str] = None,
        **kwargs: Any,
    ) -> RelationshipModel:
        """Create a Relationship from a report to another entity.

        Args:
            relationship_type: The type of relationship (e.g., 'targets', 'indicates')
            report_id: The ID of the report
            target_ref: The ID of the target entity
            organization_id: The ID of the organization that created this relationship
            marking_ids: List of marking definition IDs to apply to the relationship
            created: When the relationship was created
            modified: When the relationship was last modified
            report_name: The name of the report, for description purposes
            target_name: The name of the target entity, for description purposes
            **kwargs: Additional arguments to pass to RelationshipModel

        Returns:
            RelationshipModel: The created relationship model

        """
        description = kwargs.pop("description", None)
        if description is None:
            if report_name and target_name:
                description = (
                    f"Report '{report_name}' {relationship_type} '{target_name}'"
                )
            elif report_name:
                description = f"Report '{report_name}' {relationship_type} entity"
            else:
                description = f"Report {relationship_type} entity"

        return OctiRelationshipModel.create(
            relationship_type=relationship_type,
            source_ref=report_id,
            target_ref=target_ref,
            organization_id=organization_id,
            marking_ids=marking_ids,
            created=created,
            modified=modified,
            description=description,
            **kwargs,
        )
