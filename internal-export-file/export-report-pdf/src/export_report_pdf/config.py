from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalExportFileConnectorConfig,
    ListFromString,
)
from pydantic import Field


class InternalExportFileConnectorConfig(BaseInternalExportFileConnectorConfig):
    """Override BaseInternalExportFileConnectorConfig with ExportReportPdf defaults.

    Mirrors the connector's existing ``connector`` section variables one-to-one.
    """

    name: str = Field(
        description="The name of the connector.",
        default="ExportReportPdf",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the MIME type of the exported files.",
        default=["application/pdf"],
    )


class ExportReportPdfConfig(BaseConfigModel):
    """Config fields specific to the ExportReportPdf connector.

    Mirrors the connector's existing ``export_report_pdf`` section variables one-to-one.
    """

    primary_color: str = Field(
        description="The primary color for the output PDF (hex format, e.g. '#ff8c00').",
        default="#ff8c00",
    )
    secondary_color: str = Field(
        description="The secondary color for the output PDF (hex format, e.g. '#000000').",
        default="#000000",
    )
    company_address_line_1: str | None = Field(
        description="The first line of your company address (e.g. company name).",
        default=None,
    )
    company_address_line_2: str | None = Field(
        description="The second line of your company address (e.g. street address).",
        default=None,
    )
    company_address_line_3: str | None = Field(
        description="The third line of your company address (e.g. city, state, country).",
        default=None,
    )
    company_phone_number: str | None = Field(
        description="The phone number of your company, displayed in the PDF footer.",
        default=None,
    )
    company_email: str | None = Field(
        description="The email of your company, displayed in the PDF footer.",
        default=None,
    )
    company_website: str | None = Field(
        description="The website of your company, displayed in the PDF footer.",
        default=None,
    )
    indicators_only: bool = Field(
        description="Whether or not to only include Observables that are Indicators in the report.",
        default=False,
    )
    defang_urls: bool = Field(
        description="Whether or not to replace 'http' in Url observables with 'hxxp'.",
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the ExportReportPdf connector."""

    connector: InternalExportFileConnectorConfig = Field(
        default_factory=InternalExportFileConnectorConfig
    )
    export_report_pdf: ExportReportPdfConfig = Field(
        default_factory=ExportReportPdfConfig
    )
