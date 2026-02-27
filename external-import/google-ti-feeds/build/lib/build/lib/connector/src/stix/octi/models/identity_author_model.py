"""The module contains the OctiIdentityAuthorModel class, which represents an OpenCTI Author Identity."""

from datetime import datetime
from typing import Any

from connector.src.stix.v21.models.ovs.identity_class_ov_enums import IdentityClassOV
from connector.src.stix.v21.models.sdos.identity_model import IdentityModel


class OctiIdentityAuthorModel:
    """Model for creating OpenCTI Author Identity objects."""

    @staticmethod
    def create(name: str, organization_id: str, **kwargs: Any) -> IdentityModel:
        """Create an Author Identity model.

        Args:
            name: The name of the author
            organization_id: The ID of the organization that created this author identity
            **kwargs: Additional arguments to pass to IdentityModel

        Returns:
            IdentityModel: The created identity model

        """
        identity_class = IdentityClassOV.ORGANIZATION

        data = {
            "type": "identity",
            "spec_version": "2.1",
            "created": kwargs.pop("created", datetime.now()),
            "modified": kwargs.pop("modified", datetime.now()),
            "name": name,
            "identity_class": identity_class,
            "created_by_ref": organization_id,
            **kwargs,
        }

        return IdentityModel(**data)
