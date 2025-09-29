"""Converts a GTI report into STIX relationship objects."""

from datetime import datetime, timezone
from typing import Any

from connector.src.custom.models.gti.gti_report_model import GTIReportData
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.stix.v21.models.sros.relationship_model import RelationshipModel
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)
from stix2.v21 import Relationship  # type: ignore


class GTIReportRelationship:
    """Converts a GTI report into STIX relationship objects."""

    def __init__(
        self,
        report: GTIReportData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
        report_id: str,
    ):
        """Initialize the GTIReportRelationship object.

        Args:
            report (GTIReportData): The GTI report data to convert.
            organization (OrganizationAuthor): The organization identity object.
            tlp_marking (TLPMarking): The TLP marking definition.
            report_id (str): The STIX ID of the report object.

        """
        if hasattr(report, "attributes") and report.attributes is not None:
            created = datetime.fromtimestamp(
                report.attributes.creation_date, tz=timezone.utc
            )
            modified = datetime.fromtimestamp(
                report.attributes.last_modification_date, tz=timezone.utc
            )
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
        target_name: str | None = None,
        description: str | None = None,
    ) -> RelationshipModel:
        """Create a generic relationship from report to any target entity.

        Args:
            relationship_type (str): The type of relationship (e.g., 'targets', 'indicates').
            target_ref (str): The ID of the target entity.
            target_name (str | None): The name of the target entity, for description purposes.
            description (str | None): Custom description for the relationship.

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
    def to_stix(**kwargs: Any) -> list[Relationship]:
        """Convert the GTI report into STIX relationship objects.

        Args:
            **kwargs: Additional arguments passed to the method.

        Returns:
            list[Relationship]: The list of STIX relationship objects.

        """
        result: list[Relationship] = []
        return result
