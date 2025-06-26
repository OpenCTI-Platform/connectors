"""The module contains the OctiIPv6AddressModel class, which represents an OpenCTI IPv6 Address."""

from typing import Any, Optional
from uuid import uuid4

from connector.src.stix.v21.models.scos.ipv6_address_model import IPv6AddressModel


class OctiIPv6AddressModel:
    """Model for creating OpenCTI IPv6 Address objects."""

    @staticmethod
    def create(
        value: str,
        organization_id: str,
        marking_ids: list[str],
        create_indicator: bool = False,
        score: Optional[int] = None,
        **kwargs: Any,
    ) -> IPv6AddressModel:
        """Create an IPv6 Address model.

        Args:
            value: The IPv6 address value
            organization_id: The ID of the organization that created this IPv6 address
            marking_ids: List of marking definition IDs to apply to the IPv6 address
            create_indicator: Whether to create an indicator for this IPv6 address
            score: The confidence score of the IPv6 address
            **kwargs: Additional arguments to pass to IPv6AddressModel

        Returns:
            IPv6AddressModel: The created IPv6 address model

        """
        custom_properties = kwargs.pop("custom_properties", {})
        if organization_id:
            custom_properties["x_opencti_created_by_ref"] = organization_id
        if score:
            custom_properties["x_opencti_score"] = score
        if create_indicator:
            custom_properties["x_opencti_create_indicator"] = create_indicator

        data = {
            "id": f"ipv6-addr--{uuid4()}",
            "type": "ipv6-addr",
            "spec_version": "2.1",
            "value": value,
            "object_marking_refs": marking_ids,
            "custom_properties": custom_properties,
            **kwargs,
        }

        return IPv6AddressModel(**data)
