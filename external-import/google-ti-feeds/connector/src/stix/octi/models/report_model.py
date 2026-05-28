"""The module contains the OctiReportModel class, which represents an OpenCTI Report."""

from datetime import datetime
from typing import Any

from connector.src.stix.v21.models.ovs.report_type_ov_enums import ReportTypeOV
from connector.src.stix.v21.models.sdos.report_model import ReportModel


class OctiReportModel:
    """Model for creating OpenCTI Report objects."""

    @staticmethod
    def create(
        name: str,
        created: datetime,
        modified: datetime,
        organization_id: str,
        marking_ids: list[str],
        description: str | None = None,
        report_types: list[ReportTypeOV] | None = None,
        published: datetime | None = None,
        object_refs: list[str] | None = None,
        labels: list[str] | None = None,
        external_references: list[dict[str, Any]] | None = None,
        content: str | None = None,
        **kwargs: Any,
    ) -> ReportModel:
        """Create a Report model with OpenCTI custom properties.

        Args:
            name: The name of the report
            created: When the report was created
            modified: When the report was last modified
            organization_id: The ID of the organization that created this report
            marking_ids: list of marking definition IDs to apply to the report
            description: Description of the report
            report_types: list of report types
            published: When the report was published (defaults to created if not provided)
            object_refs: list of referenced object IDs
            labels: list of labels for this report
            external_references: list of external references
            content: The full content of the report
            **kwargs: Additional arguments to pass to ReportModel

        Returns:
            ReportModel: The created report model

        """
        if published is None:
            published = created

        if report_types is None:
            report_types = [ReportTypeOV.THREAT_REPORT]

        if object_refs is None:
            object_refs = []

        if labels is None:
            labels = []

        custom_properties = kwargs.pop("custom_properties", {})
        if content:
            custom_properties["x_opencti_content"] = content

        data = {
            "type": "report",
            "spec_version": "2.1",
            "created": created,
            "modified": modified,
            "name": name,
            "description": description,
            "report_types": report_types,
            "published": published,
            "object_refs": object_refs,
            "created_by_ref": organization_id,
            "object_marking_refs": marking_ids,
            "labels": labels,
            "external_references": external_references,
            "custom_properties": custom_properties,
            **kwargs,
        }

        return ReportModel(**data)
