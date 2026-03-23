from datetime import datetime, timedelta, timezone

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr


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
        default=datetime.now(tz=timezone.utc) - timedelta(days=365),
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
