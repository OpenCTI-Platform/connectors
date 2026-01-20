from datetime import timedelta
from typing import Literal

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
        default="905c3d83-9e5e-45c6-a85a-89e9a6796dae",
    )
    name: str = Field(
        description="The name of the connector.",
        default="AbuseIPDB IP Blacklist",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class AbuseipdbIpblacklistConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `AbuseipdbIpblacklistConnector`.
    """

    api_url: str = Field(
        description="AbuseIPDB API endpoint URL.",
        default="https://api.abuseipdb.com/api/v2/blacklist",
    )
    api_key: SecretStr = Field(
        description="Your AbuseIPDB API key.",
    )
    score: int = Field(
        description="Minimum confidence score threshold for IP addresses.", default=75
    )
    limit: int = Field(description="Maximum number of IPs to fetch.", default=500000)
    create_indicator: bool = Field(
        description="Whether to create Indicators from observables.", default=False
    )
    tlp_level: str = Field(
        description="TLP marking for imported data (`clear`, `green`, `amber`, `amber+strict`, `red`).",
        default="clear",
    )
    ipversion: Literal["4", "6", "mixed"] | None = Field(
        description="IP version filter: `4`, `6`, or `mixed`.", default="mixed"
    )
    exceptcountry: str | None = Field(
        description="Comma-separated country codes to exclude (e.g., `RU,CN`).",
        default=None,
    )
    onlycountry: str | None = Field(
        description="Comma-separated country codes to include only.", default=None
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `AbuseipdbIpblacklistConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    abuseipdb: AbuseipdbIpblacklistConfig = Field(
        default_factory=AbuseipdbIpblacklistConfig
    )
