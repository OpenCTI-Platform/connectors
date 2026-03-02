"""The module contains the OctiSoftwareModel class, which represents an OpenCTI Software."""

from typing import Any

from connector.src.stix.v21.models.scos.software_model import SoftwareModel


class OctiSoftwareModel:
    """Model for creating OpenCTI Software objects."""

    @staticmethod
    def create(
        organization_id: str,
        marking_ids: list[str],
        name: str,
        create_indicator: bool = False,
        cpe: str | None = None,
        languages: list[str] | None = None,
        vendor: str | None = None,
        version: str | None = None,
        score: int | None = None,
        product: str | None = None,
        **kwargs: Any,
    ) -> SoftwareModel:
        """Create a Software model.

        Args:
            organization_id: The ID of the organization that created this software
            marking_ids: list of marking definition IDs to apply to the software
            name: The name of the software
            create_indicator: Whether to create an indicator for the software
            cpe: CPE v2.3 entry for the software from the official NVD CPE dictionary
            languages: list of supported languages (ISO 639-2 codes)
            vendor: The name of the software vendor
            version: Version of the software
            score: The confidence score of the software
            product: The product name for OpenCTI
            **kwargs: Additional arguments to pass to SoftwareModel

        Returns:
            SoftwareModel: The created software model

        """
        custom_properties = kwargs.pop("custom_properties", {})
        if organization_id:
            custom_properties["x_opencti_created_by_ref"] = organization_id
        if score:
            custom_properties["x_opencti_score"] = score
        if create_indicator:
            custom_properties["x_opencti_create_indicator"] = create_indicator
        if product:
            custom_properties["x_opencti_product"] = product

        data = {
            "type": "software",
            "spec_version": "2.1",
            "object_marking_refs": marking_ids,
            "custom_properties": custom_properties,
            "name": name,
            **kwargs,
        }

        if cpe:
            data["cpe"] = cpe
        if languages:
            data["languages"] = languages
        if vendor:
            data["vendor"] = vendor
        if version:
            data["version"] = version

        return SoftwareModel(**data)
