"""Pydantic settings for the Import File MISP connector.

These settings mirror one-to-one the connector's historical
``pycti.get_config_variable`` based configuration, exposing it through the
``connectors-sdk`` base models so the connector becomes manager-supported.

The custom configuration section keeps its original name ``misp_import_file``,
which maps to the ``MISP_IMPORT_FILE_*`` environment variables.
"""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalImportFileConnectorConfig,
    ListFromString,
)
from pydantic import Field


class InternalImportFileConnectorConfig(BaseInternalImportFileConnectorConfig):
    """Connector section with defaults specific to Import File MISP."""

    name: str = Field(
        description="The name of the connector.",
        default="ImportFileMISP",
    )
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="a7cb9c9f-65d6-4919-bef2-e7a866a9fd80",
    )
    scope: ListFromString = Field(
        description="The scope (MIME types) handled by the connector.",
        default=["application/json"],
    )


class MispImportFileConfig(BaseConfigModel):
    """Config fields specific to the Import File MISP connector.

    Mirrors the ``misp_import_file`` variables historically read through
    ``get_config_variable``. Defaults reflect the connector's shipped
    configuration so existing behavior is preserved.
    """

    import_from_date: str | None = Field(
        description="Optional lower-bound date used when importing MISP events.",
        default=None,
    )
    create_reports: bool = Field(
        description="Create a report for each imported MISP event.",
        default=True,
    )
    report_type: str = Field(
        description="Report type to use for imported MISP events.",
        default="misp-event",
    )
    create_indicators: bool = Field(
        description="Create indicators from MISP attributes.",
        default=True,
    )
    create_observables: bool = Field(
        description="Create observables from MISP attributes.",
        default=True,
    )
    create_object_observables: bool = Field(
        description="Create text observables for MISP objects.",
        default=False,
    )
    create_tags_as_labels: bool = Field(
        description="Create MISP tags as OpenCTI labels.",
        default=True,
    )
    guess_threats_from_tags: bool = Field(
        description=(
            "Try to guess threats (threat actor, intrusion set, malware, etc.) "
            "from MISP tags when they are present in OpenCTI."
        ),
        default=False,
    )
    author_from_tags: bool = Field(
        description="Map creator:XX=YY so the event author is derived from MISP tags.",
        default=False,
    )
    markings_from_tags: bool = Field(
        description="Derive markings from MISP tags.",
        default=False,
    )
    import_to_ids_no_score: int | None = Field(
        description=(
            "Score applied to the indicator/observable when the attribute "
            "'to_ids' flag is false."
        ),
        default=None,
    )
    import_unsupported_observables_as_text: bool = Field(
        description="Import unsupported observables as x_opencti_text.",
        default=False,
    )
    import_unsupported_observables_as_text_transparent: bool = Field(
        description="Import unsupported observables as x_opencti_text just with the value.",
        default=True,
    )
    import_with_attachments: bool = Field(
        description="Try to import a PDF file from the attachment attribute.",
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the Import File MISP connector."""

    connector: InternalImportFileConnectorConfig = Field(
        default_factory=InternalImportFileConnectorConfig
    )
    misp_import_file: MispImportFileConfig = Field(default_factory=MispImportFileConfig)
