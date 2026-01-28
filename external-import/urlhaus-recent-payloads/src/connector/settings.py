from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="8534e9c8-3997-4a83-a263-52588ce9e671",
    )
    name: str = Field(
        description="The name of the connector.",
        default="UrlhausRecentPayloads",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class UrlhausRecentPayloadsConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `UrlhausRecentPayloadsConnector`.
    """

    api_url: str = Field(
        description="The URL of the URLhaus API.",
        default="https://urlhaus-api.abuse.ch/v1/",
    )
    api_key: SecretStr = Field(
        description="The API key for the URLhaus API.", default=SecretStr("ChangeMe")
    )
    cooldown_seconds: int = Field(
        description="The time to wait in seconds between subsequent requests.",
        default=300,
    )
    include_filetypes: str | None = Field(
        description="Only download files if file type matches. (Comma separated)",
        default=None,
    )
    include_signatures: str | None = Field(
        description="Only download files if match these Yara rules. (Comma separated)",
        default=None,
    )
    skip_unknown_filetypes: bool = Field(
        description="Skip files with an unknown file type.", default=True
    )
    skip_null_signature: bool = Field(
        description="Skip files that didn't match known Yara rules.", default=True
    )
    labels: str = Field(
        description="Labels to apply to uploaded Artifacts. (Comma separated)",
        default="urlhaus",
    )
    labels_color: str = Field(
        description="Color for labels specified above.", default="#54483b"
    )
    signature_label_color: str = Field(
        description="Color for Yara rule match label.", default="#0059f7"
    )
    filetype_label_color: str = Field(
        description="Color to use for filetype label.", default="#54483b"
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `UrlhausRecentPayloadsConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    urlhaus_recent_payloads: UrlhausRecentPayloadsConfig = Field(
        default_factory=UrlhausRecentPayloadsConfig
    )
