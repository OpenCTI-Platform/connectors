"""The module contains the OctiIdentitySectorModel class, which represents an OpenCTI Identity Sector."""

from datetime import datetime
from typing import Any, Optional

from connector.src.stix.v21.models.ovs.identity_class_ov_enums import IdentityClassOV
from connector.src.stix.v21.models.sdos.identity_model import IdentityModel


class OctiIdentitySectorModel:
    """Model for creating OpenCTI Identity Sector objects."""

    @staticmethod
    def create(
        name: str,
        organization_id: str,
        marking_ids: list[str],
        description: Optional[str] = None,
        **kwargs: Any,
    ) -> IdentityModel:
        """Create an Identity Sector model.

        Args:
            name: The name of the sector
            organization_id: The ID of the organization that created this sector
            marking_ids: List of marking definition IDs to apply to the sector
            description: Description of the sector
            **kwargs: Additional arguments to pass to IdentityModel

        Returns:
            IdentityModel: The created identity model

        """
        data = {
            "type": "identity",
            "spec_version": "2.1",
            "created": kwargs.pop("created", datetime.now()),
            "modified": kwargs.pop("modified", datetime.now()),
            "name": name,
            "description": description,
            "identity_class": IdentityClassOV.CLASS_,
            "created_by_ref": organization_id,
            "object_marking_refs": marking_ids,
            **kwargs,
        }

        return IdentityModel(**data)
