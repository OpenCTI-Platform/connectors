"""The module contains the OctiReportModel class, which represents an OpenCTI Report."""

from datetime import datetime
from typing import Any, Dict, List, Optional

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
        marking_ids: List[str],
        description: Optional[str] = None,
        report_types: Optional[List[ReportTypeOV]] = None,
        published: Optional[datetime] = None,
        object_refs: Optional[List[str]] = None,
        labels: Optional[List[str]] = None,
        external_references: Optional[List[Dict[str, Any]]] = None,
        content: Optional[str] = None,
        **kwargs: Any,
    ) -> ReportModel:
        """Create a Report model with OpenCTI custom properties.

        Args:
            name: The name of the report
            created: When the report was created
            modified: When the report was last modified
            organization_id: The ID of the organization that created this report
            marking_ids: List of marking definition IDs to apply to the report
            description: Description of the report
            report_types: List of report types
            published: When the report was published (defaults to created if not provided)
            object_refs: List of referenced object IDs
            labels: List of labels for this report
            external_references: List of external references
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
