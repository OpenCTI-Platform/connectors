"""The module contains the OctiFileModel class, which represents an OpenCTI File."""

from typing import Any, Dict, List, Optional
from uuid import uuid4

from connector.src.stix.v21.models.scos.file_model import FileModel


class OctiFileModel:
    """Model for creating OpenCTI File objects."""

    @staticmethod
    def create(
        organization_id: str,
        marking_ids: list[str],
        create_indicator: bool = False,
        hashes: Optional[Dict[str, str]] = None,
        name: Optional[str] = None,
        additional_names: Optional[List[str]] = None,
        size: Optional[int] = None,
        score: Optional[int] = None,
        **kwargs: Any,
    ) -> FileModel:
        """Create a File model.

        Args:
            organization_id: The ID of the organization that created this file
            marking_ids: List of marking definition IDs to apply to the file
            create_indicator: Whether to create an indicator for the file
            hashes: Dictionary of hash algorithm names and hash values
            name: The name of the file
            additional_names: Additional names for the file
            size: Size of the file in bytes
            score: The confidence score of the file
            **kwargs: Additional arguments to pass to FileModel

        Returns:
            FileModel: The created file model

        """
        custom_properties = kwargs.pop("custom_properties", {})
        if organization_id:
            custom_properties["x_opencti_created_by_ref"] = organization_id
        if score:
            custom_properties["x_opencti_score"] = score
        if additional_names:
            custom_properties["x_opencti_additional_names"] = additional_names
        if create_indicator:
            custom_properties["x_opencti_create_indicator"] = create_indicator

        data = {
            "id": f"file--{uuid4()}",
            "type": "file",
            "spec_version": "2.1",
            "object_marking_refs": marking_ids,
            "custom_properties": custom_properties,
            **kwargs,
        }

        if hashes:
            data["hashes"] = hashes
        if name:
            data["name"] = name
        if size is not None:
            data["size"] = size

        return FileModel(**data)
