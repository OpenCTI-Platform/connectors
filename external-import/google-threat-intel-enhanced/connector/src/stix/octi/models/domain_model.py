"""The module contains the OctiDomainModel class, which represents an OpenCTI Domain Name."""

from typing import Any, Dict, List, Optional
from uuid import uuid4

from connector.src.stix.v21.models.scos.domain_name_model import DomainNameModel


class OctiDomainModel:
    """Model for creating OpenCTI Domain Name objects."""

    @staticmethod
    def create(
        value: str,
        organization_id: str,
        marking_ids: list[str],
        create_indicator: bool = False,
        score: Optional[int] = None,
        description: Optional[str] = None,
        external_references: Optional[List[Dict[str, Any]]] = None,
        labels: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> DomainNameModel:
        """Create a Domain Name model.

        Args:
            value: The domain name value
            organization_id: The ID of the organization that created this domain
            marking_ids: List of marking definition IDs to apply to the domain
            create_indicator: Whether to create an indicator for the domain name
            score: The confidence score of the domain name
            description: Optional description for the domain
            external_references: Optional list of external references
            labels: Optional list of labels (tags) for the domain
            **kwargs: Additional arguments to pass to DomainNameModel

        Returns:
            DomainNameModel: The created domain name model

        """
        custom_properties = kwargs.pop("custom_properties", {})
        if organization_id:
            custom_properties["x_opencti_created_by_ref"] = organization_id
        if score:
            custom_properties["x_opencti_score"] = score
        if create_indicator:
            custom_properties["x_opencti_create_indicator"] = create_indicator
        if description:
            custom_properties["x_opencti_description"] = description
        if labels:
            custom_properties["x_opencti_labels"] = labels

        data = {
            "id": f"domain-name--{uuid4()}",
            "type": "domain-name",
            "spec_version": "2.1",
            "value": value,
            "object_marking_refs": marking_ids,
            "custom_properties": custom_properties,
            **kwargs,
        }

        if external_references:
            data["external_references"] = external_references

        return DomainNameModel(**data)
