"""The module contains the OctiIPv4AddressModel class, which represents an OpenCTI IPv4 Address."""

from typing import Any, Dict, List, Optional
from uuid import uuid4

from connector.src.stix.v21.models.scos.ipv4_address_model import IPv4AddressModel


class OctiIPv4AddressModel:
    """Model for creating OpenCTI IPv4 Address objects."""

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
    ) -> IPv4AddressModel:
        """Create an IPv4 Address model.

        Args:
            value: The IPv4 address value
            organization_id: The ID of the organization that created this IPv4 address
            marking_ids: List of marking definition IDs to apply to the IPv4 address
            create_indicator: Whether to create an indicator for the IPv4 address
            score: The confidence score of the IPv4 address
            description: Optional description for the IPv4 address
            external_references: Optional list of external references
            labels: Optional list of labels (tags) for the IPv4 address
            **kwargs: Additional arguments to pass to IPv4AddressModel

        Returns:
            IPv4AddressModel: The created IPv4 address model

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
            "id": f"ipv4-addr--{uuid4()}",
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "value": value,
            "object_marking_refs": marking_ids,
            "custom_properties": custom_properties,
            **kwargs,
        }

        if external_references:
            data["external_references"] = external_references

        return IPv4AddressModel(**data)
