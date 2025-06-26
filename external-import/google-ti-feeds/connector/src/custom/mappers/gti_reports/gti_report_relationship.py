"""Converts a GTI report into STIX relationship objects."""

from datetime import datetime
from typing import Any, List, Optional

from connector.src.custom.models.gti_reports.gti_report_model import GTIReportData
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.stix.v21.models.sros.relationship_model import RelationshipModel
from stix2.v21 import Identity, MarkingDefinition, Relationship  # type: ignore


class GTIReportRelationship:
    """Converts a GTI report into STIX relationship objects."""

    def __init__(
        self,
        report: GTIReportData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
        report_id: str,
    ):
        """Initialize the GTIReportRelationship object.

        Args:
            report (GTIReportData): The GTI report data to convert.
            organization (Identity): The organization identity object.
            tlp_marking (MarkingDefinition): The TLP marking definition.
            report_id (str): The STIX ID of the report object.

        """
        if hasattr(report, "attributes") and report.attributes is not None:
            created = datetime.fromtimestamp(report.attributes.creation_date)
            modified = datetime.fromtimestamp(report.attributes.last_modification_date)
        else:
            raise ValueError("Invalid report data")

        self.report = report

        self.organization = organization
        self.tlp_marking = tlp_marking
        self.report_id = report_id
        self.created = created
        self.modified = modified

    def create_relationship(
        self,
        relationship_type: str,
        target_ref: str,
        target_name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> RelationshipModel:
        """Create a generic relationship from report to any target entity.

        Args:
            relationship_type (str): The type of relationship (e.g., 'targets', 'indicates').
            target_ref (str): The ID of the target entity.
            target_name (Optional[str]): The name of the target entity, for description purposes.
            description (Optional[str]): Custom description for the relationship.

        Returns:
            Relationship: The STIX relationship object.

        """
        if hasattr(self.report, "attributes") and self.report.attributes is not None:
            name = self.report.attributes.name
        else:
            raise ValueError("Report not initialized")

        return OctiRelationshipModel.create_from_report(
            relationship_type=relationship_type,
            report_id=self.report_id,
            target_ref=target_ref,
            report_name=name,
            target_name=target_name,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            created=self.created,
            modified=self.modified,
            description=description,
        )

    @staticmethod
    def to_stix(**kwargs: Any) -> List[Relationship]:
        """Convert the GTI report into STIX relationship objects.

        Args:
            **kwargs: Additional arguments passed to the method.

        Returns:
            List[Relationship]: The list of STIX relationship objects.

        """
        result: List[Relationship] = []
        return result
