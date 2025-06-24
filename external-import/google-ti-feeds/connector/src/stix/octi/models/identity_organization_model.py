"""The module contains the OctiOrganizationModel class, which represents an OpenCTI Organization Identity."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from connector.src.stix.v21.models.ovs.identity_class_ov_enums import IdentityClassOV
from connector.src.stix.v21.models.sdos.identity_model import IdentityModel


class OctiOrganizationModel:
    """Model for creating OpenCTI Organization Identity objects."""

    @staticmethod
    def create(
        name: str,
        description: Optional[str] = None,
        contact_information: Optional[str] = None,
        organization_type: Optional[str] = None,
        reliability: Optional[str] = None,
        aliases: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> IdentityModel:
        """Create an Organization Identity model with OpenCTI custom properties.

        Args:
            name: The name of the organization
            description: Description of the organization
            contact_information: Contact details for the organization
            organization_type: OpenCTI organization type (e.g., 'vendor')
            reliability: OpenCTI reliability level
            aliases: List of alternative names for the organization
            **kwargs: Additional arguments to pass to IdentityModel

        Returns:
            IdentityModel: The created identity model which can be converted to STIX using to_stix2_object()

        """
        custom_properties: Dict[str, Any] = {}
        if organization_type:
            custom_properties["x_opencti_organization_type"] = organization_type

        custom_properties["x_opencti_reliability"] = reliability

        if aliases:
            custom_properties["x_opencti_aliases"] = aliases

        existing_custom = kwargs.pop("custom_properties", {})
        custom_properties.update(existing_custom)

        data = {
            "type": "identity",
            "spec_version": "2.1",
            "created": kwargs.pop("created", datetime.now()),
            "modified": kwargs.pop("modified", datetime.now()),
            "name": name,
            "description": description,
            "contact_information": contact_information,
            "identity_class": IdentityClassOV.ORGANIZATION,
            "custom_properties": custom_properties,
            **kwargs,
        }

        return IdentityModel(**data)
