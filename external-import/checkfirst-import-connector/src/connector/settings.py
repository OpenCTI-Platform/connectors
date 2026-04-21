from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr, TypeAdapter


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="04e5ba20-0e6f-4265-a723-4803502fd6db",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Checkfirst Import Connector",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["checkfirst"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(weeks=1),
    )


class CheckfirstImportConnectorConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `CheckfirstImportConnector`.
    """

    api_url: HttpUrl = Field(
        description="Base URL for the API endpoint (e.g., https://api.example.com)."
    )
    api_endpoint: str = Field(
        description="API endpoint path (e.g., /v1/articles).",
        default="/v1/articles",
    )
    api_key: SecretStr = Field(
        description="API key for authentication (sent in Api-Key header)."
    )
    since: DatetimeFromIsoString = Field(
        description=(
            "Only ingest articles published on or after this date. "
            "Accepts ISO 8601 absolute dates (e.g., 2024-01-01T00:00:00Z) "
            "or durations relative to now (e.g., P365D, P1Y, P6M, P4W). "
            "Defaults to 1 year ago."
        ),
        # `default_factory` is used to set a dynamic default value (datetime) at runtime
        default_factory=lambda: TypeAdapter(DatetimeFromIsoString).validate_python(
            "P1Y"
        ),
        # but a fixed default value (ISO string) must be used in the schema for documentation purposes
        json_schema_extra={"default": "P1Y"},
    )
    force_reprocess: bool = Field(
        description=(
            "If true, ignore any saved connector state and start from page 1. "
            "Useful for debugging or re-importing all data."
        ),
        default=False,
    )
    tlp_level: TLPLevel = Field(
        description="TLP marking level applied to created STIX entities.",
        default=TLPLevel.CLEAR,
    )
    max_row_bytes: int | None = Field(
        description="Skip any API row larger than this approximate number of bytes.",
        default=None,
    )
    import_domain_name: bool = Field(
        description=(
            "If false, Domain-Name observables (extracted from article URLs) will not be created. "
            "Disabling this also suppresses the Infrastructure→consists-of→Domain and Domain→related-to→Channel relationships."
        ),
        default=True,
    )
    import_infrastructure: bool = Field(
        description=(
            "If false, Infrastructure objects (linked to each article's publishing domain) will not be created. "
            "Disabling this also suppresses Campaign→uses→Infrastructure, Infrastructure→consists-of→Domain, "
            "and Channel→related-to→Infrastructure."
        ),
        default=True,
    )
    import_channel: bool = Field(
        description=(
            "If false, Channel objects (website or subdomain of the publishing domain) will not be created. "
            "Disabling this also suppresses Campaign→uses→Channel, Channel→related-to→Infrastructure, "
            "Domain→related-to→Channel, Channel→publishes→Content, and Channel→related-to→SourceChannel."
        ),
        default=True,
    )
    import_source_channel: bool = Field(
        description=(
            "If false, Source Channel objects (Telegram channel or origin website) will not be created. "
            "Disabling this also suppresses Channel→related-to→SourceChannel and MediaContent→related-to→SourceChannel."
        ),
        default=True,
    )
    import_media_content: bool = Field(
        description=(
            "If false, Media-Content objects (article) will not be created. "
            "Disabling this also suppresses Channel→publishes→Content and MediaContent→related-to→SourceChannel."
        ),
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `CheckfirstImportConnectorConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    checkfirst: CheckfirstImportConnectorConfig = Field(
        default_factory=CheckfirstImportConnectorConfig
    )
