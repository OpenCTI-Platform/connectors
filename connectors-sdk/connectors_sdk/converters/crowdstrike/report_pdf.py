"""CrowdStrikeReportPdfConverter."""

from connectors_sdk.converters.base import AbstractConverter
from connectors_sdk.converters.crowdstrike.models import CrowdStrikeReportPdf
from connectors_sdk.models import Artifact, BaseIdentifiedObject

PDF_MIME_TYPE = "application/pdf"


class CrowdStrikeReportPdfConverter(AbstractConverter[CrowdStrikeReportPdf]):
    """Convert a CrowdStrike report PDF into an artifact.

    The artifact id only depends on the PDF content, so a PDF shared by
    several reports gives a single artifact.

    Examples:
        >>> from connectors_sdk.models import OrganizationAuthor
        >>> converter = CrowdStrikeReportPdfConverter(
        ...     author=OrganizationAuthor(name="CrowdStrike"), markings=[]
        ... )
        >>> pdf = CrowdStrikeReportPdf(report_id=1, file_name="report.pdf", content=b"%PDF")
        >>> [obj.mime_type for obj in converter.transform(pdf)]
        ['application/pdf']

    """

    def transform(self, input: CrowdStrikeReportPdf) -> list[BaseIdentifiedObject]:
        """Convert a report PDF.

        Args:
            input: The report PDF.

        Returns:
            One artifact holding the PDF.
        """
        return [
            Artifact(
                content=input.content,
                mime_type=PDF_MIME_TYPE,
                additional_names=[input.file_name],
                author=self.author,
                markings=self.markings,
            )
        ]
