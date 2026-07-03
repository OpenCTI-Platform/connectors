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
        default="9b7c2e14-3f5a-4d8b-9c1e-6a2f4b8d0e37",
    )
    name: str = Field(
        description="The name of the connector.",
        default="IPsum",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["ipsum"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=6),
    )


class ConnectorIpsumConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the IPsum connector.
    """

    api_base_url: str = Field(
        description="The URL of the IPsum feed to fetch (levels 1-8 are available).",
        default="https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/5.txt",
    )
    api_key: SecretStr | None = Field(
        description="Optional GitHub API key used to avoid rate limiting.",
        default=None,
    )
    default_x_opencti_score: int = Field(
        description="Default x_opencti_score to set on imported observables.",
        default=60,
    )
    tlp_level: str = Field(
        description=(
            "TLP marking to apply to imported data "
            "(white, clear, green, amber, amber+strict, red)."
        ),
        default="white",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `ConnectorIpsumConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    connector_ipsum: ConnectorIpsumConfig = Field(default_factory=ConnectorIpsumConfig)
