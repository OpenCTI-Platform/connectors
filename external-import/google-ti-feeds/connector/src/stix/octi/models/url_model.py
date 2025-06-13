"""The module contains the OctiUrlModel class, which represents an OpenCTI URL."""

from typing import Any, Optional
from uuid import uuid4

from connector.src.stix.v21.models.scos.url_model import URLModel


class OctiUrlModel:
    """Model for creating OpenCTI URL objects."""

    @staticmethod
    def create(
        value: str,
        organization_id: str,
        marking_ids: list[str],
        create_indicator: bool = False,
        score: Optional[int] = None,
        **kwargs: Any,
    ) -> URLModel:
        """Create a URL model.

        Args:
            value: The URL value
            organization_id: The ID of the organization that created this URL
            marking_ids: List of marking definition IDs to apply to the URL
            create_indicator: Whether to create an indicator for the URL
            score: The confidence score of the URL
            **kwargs: Additional arguments to pass to URLModel

        Returns:
            URLModel: The created URL model

        """
        custom_properties = kwargs.pop("custom_properties", {})
        if organization_id:
            custom_properties["x_opencti_created_by_ref"] = organization_id
        if score:
            custom_properties["x_opencti_score"] = score
        if create_indicator:
            custom_properties["x_opencti_create_indicator"] = create_indicator

        data = {
            "id": f"url--{uuid4()}",
            "type": "url",
            "spec_version": "2.1",
            "value": value,
            "object_marking_refs": marking_ids,
            "custom_properties": custom_properties,
            **kwargs,
        }

        return URLModel(**data)
