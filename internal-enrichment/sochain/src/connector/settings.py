from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="333fb78c-6240-4ee5-afbd-6c27b2ccc673",
    )
    name: str = Field(
        description="The name of the connector.",
        default="SoChain",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Cryptocurrency-Wallet"],
    )


class SochainConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `SochainConnector`.
    """

    api_base_url: HttpUrl = Field(
        description="SoChain API v3 base URL.",
        default="https://sochain.com/api/v3",
    )
    api_key: SecretStr | None = Field(
        description=(
            "Optional SoChain API key, sent as the API-KEY header. Without one, "
            "lookups are limited to 2,500 a day per IP. Get a key at "
            "https://sochain.com/dashboard."
        ),
        default=None,
    )
    check_poisoning: bool = Field(
        description=(
            "Check whether the address was targeted by address poisoning, and "
            "add a note listing the look-alike addresses."
        ),
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `SochainConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    sochain: SochainConfig = Field(default_factory=SochainConfig)
