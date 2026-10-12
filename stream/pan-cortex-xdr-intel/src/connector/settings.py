from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    DeploymentConfig,
    HitsConfig,
    ListFromString,
    SecurityPlatformConfig,
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


class CortexXdrSecurityPlatformConfig(SecurityPlatformConfig):
    """
    Define the Security Platform entity representing Palo Alto Cortex XDR in OpenCTI (deployment write-back).
    """

    name: str = Field(
        default="Palo Alto Cortex XDR",
        min_length=2,
        description="Name of the Security Platform entity representing Palo Alto Cortex XDR in OpenCTI (created if it does not exist).",
    )
    type: str | None = Field(
        default="XDR",
        description="Type of the Security Platform entity (open vocabulary security_platform_type_ov).",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig`, `PanCortexXdrIntelConfig`
    and the deployment write-back namespaces (`deployment`, `hits`, `security_platform`).
    """

    connector: StreamConnectorConfig = Field(
        default_factory=StreamConnectorConfig,
    )
    pan_cortex_xdr_intel: PanCortexXdrIntelConfig = Field(
        default_factory=PanCortexXdrIntelConfig
    )
    deployment: DeploymentConfig = Field(default_factory=DeploymentConfig)
    hits: HitsConfig = Field(default_factory=HitsConfig)
    security_platform: CortexXdrSecurityPlatformConfig = Field(
        default_factory=CortexXdrSecurityPlatformConfig
    )
