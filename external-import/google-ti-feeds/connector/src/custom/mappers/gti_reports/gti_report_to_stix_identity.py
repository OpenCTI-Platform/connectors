"""Converts a GTI report to a STIX identity object."""

from connector.src.custom.models.gti_reports.gti_report_model import GTIReportData
from connector.src.stix.octi.models.identity_author_model import OctiIdentityAuthorModel
from stix2.v21 import Identity  # type: ignore


class GTIReportToSTIXIdentity:
    """Converts a GTI report to a STIX identity object."""

    def __init__(self, report: GTIReportData, organization: Identity):
        """Initialize the GTIReportToSTIXIdentity object.

        Args:
            report (GTIReportData): The GTI report data to convert.
            organization (Identity): The organization identity object.

        """
        self.report = report
        self.organization = organization

    def to_stix(self) -> Identity:
        """Convert the GTI report to a STIX identity object.

        Returns:
            Identity: The STIX identity object.

        """
        if not hasattr(self.report, "attributes") or not self.report.attributes:
            raise ValueError("Invalid report attributes")
        attributes = self.report.attributes
        author = "Google Threat Intelligence"
        if attributes.author and len(attributes.author) > 2:
            author = attributes.author

        identity = OctiIdentityAuthorModel.create(
            name=author,
            organization_id=self.organization.id,
        )

        identity_stix = identity.to_stix2_object()

        # noinspection PyTypeChecker
        return identity_stix
