from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    id: str = Field(
        description="The unique identifier of the connector.",
        default="6f1b7d7d-4655-42e6-bef1-ad6f176d25a0",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Palo Alto Cortex XDR Intel",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["pan-cortex-xdr-intel"],
    )


class PanCortexXdrIntelConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the Cortex XDR API.
    """

    api_base_url: HttpUrl = Field(
        description="Cortex XDR API base URL (tenant FQDN), i.e. `https://api-<fqdn>`. ",
    )
    api_key_id: str = Field(
        description="Cortex XDR API key ID, sent as the `x-xdr-auth-id` header.",
    )
    api_key: SecretStr = Field(
        description="Cortex XDR API key (Advanced key) used to sign requests.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `PanCortexXdrIntelConfig`.
    """

    connector: StreamConnectorConfig = Field(
        default_factory=StreamConnectorConfig,
    )
    pan_cortex_xdr_intel: PanCortexXdrIntelConfig = Field(
        default_factory=PanCortexXdrIntelConfig
    )
