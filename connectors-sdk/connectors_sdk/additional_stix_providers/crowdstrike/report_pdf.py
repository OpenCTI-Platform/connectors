"""CrowdStrikeReportPdfAdditionalStixProvider."""

from typing import Any, Protocol

from connectors_sdk.additional_stix_providers.base import (
    AbstractAdditionalStixProvider,
)
from connectors_sdk.converters.crowdstrike.models import CrowdStrikeReportPdf
from connectors_sdk.converters.crowdstrike.report_pdf import (
    CrowdStrikeReportPdfConverter,
)
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.models import BaseAuthorEntity, BaseIdentifiedObject, TLPMarking
from pydantic import BaseModel, ConfigDict

# Assumed status for "this report has no PDF": not documented in falconpy, and the
# CrowdStrike API reference is not public.
NO_PDF_STATUS_CODE = 404


class CrowdStrikeReportPdfClient(Protocol):
    """Client able to download a report PDF, such as the connector's ``ReportsAPI``.

    ``get_report_pdf`` returns the PDF bytes, or the falconpy response dict
    (``status_code``, ``headers``, ``body``) when the API did not return a file.
    """

    def get_report_pdf(self, report_id: str) -> bytes | dict[str, Any]:
        """Download the PDF of a report."""
        ...  # pragma: no cover # Protocol method, never called


class CrowdStrikeReportKey(BaseModel):
    """Identify a report. The name is only used for the PDF file name."""

    model_config = ConfigDict(frozen=True)

    id: int
    name: str


class CrowdStrikeReportPdfAdditionalStixProvider(
    AbstractAdditionalStixProvider[CrowdStrikeReportKey]
):
    """Return the PDF of a CrowdStrike report as a shared artifact.

    The file name is built like the connector does (report name in lower case,
    spaces replaced by dashes, with ``.pdf``).

    Examples:
        >>> from connectors_sdk.models import OrganizationAuthor
        >>> class FakeClient:
        ...     def get_report_pdf(self, report_id):
        ...         return b"%PDF-1.7"
        >>> provider = CrowdStrikeReportPdfAdditionalStixProvider(
        ...     client=FakeClient(), author=OrganizationAuthor(name="CrowdStrike"), markings=[]
        ... )
        >>> [a.additional_names for a in provider.get(CrowdStrikeReportKey(id=1, name="Weekly Report"))]
        [['weekly-report.pdf']]

    """

    def __init__(
        self,
        client: CrowdStrikeReportPdfClient,
        author: BaseAuthorEntity,
        markings: list[TLPMarking],
        cache: bool = False,
    ) -> None:
        """Initialize the provider.

        Args:
            client: The client downloading report PDFs.
            author: The author referenced by every returned object.
            markings: The markings referenced by every returned object.
            cache: Fetch each report at most once until ``clear_cache()`` is called.
        """
        super().__init__(author=author, markings=markings, cache=cache)
        self.client = client
        self.converter = CrowdStrikeReportPdfConverter(author=author, markings=markings)

    def _fetch(self, id: CrowdStrikeReportKey) -> list[BaseIdentifiedObject] | None:
        """Download a report PDF and convert it into an artifact.

        Args:
            id: The report.

        Returns:
            The artifact, or ``None`` when the report has no PDF.

        Raises:
            DataRetrievalError: If the client fails or the API answers with an error.
        """
        try:
            response = self.client.get_report_pdf(str(id.id))
        except Exception as err:
            raise DataRetrievalError(
                f"Cannot download the PDF of report {id.id}"
            ) from err

        if isinstance(response, dict):
            status_code = response.get("status_code")
            if status_code == NO_PDF_STATUS_CODE:
                return None
            raise DataRetrievalError(
                f"Cannot download the PDF of report {id.id} (status {status_code})"
            )
        if not response:
            # falconpy returns empty bytes for an empty binary body.
            return None

        file_name = id.name.lower().replace(" ", "-") + ".pdf"
        return self.converter.transform(
            CrowdStrikeReportPdf(report_id=id.id, file_name=file_name, content=response)
        )
