from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Configuration for STREAM connector behavior.
    """

    name: str = Field(
        default="Akamai Connector",
        description="Connector name",
    )

    scope: ListFromString = Field(
        default=["indicator"],
        description="Connector scope",
    )


class AkamaiConfig(BaseConfigModel):
    """
    Akamai configuration.
    """

    base_url: HttpUrl = Field(
        description="External API base URL.",
    )

    client_token: SecretStr = Field(
        description="EdgeGrid client token.",
    )

    client_secret: SecretStr = Field(
        description="EdgeGrid client secret.",
    )

    access_token: SecretStr = Field(
        description="EdgeGrid access token.",
    )

    # Required Akamai Client List of type IP.
    client_list_id: str = Field(
        description="Target IP Client List ID",
    )

    # Optional Akamai Client List of type ASN.
    # Keeping this optional preserves backward compatibility
    # with existing IPv4-only deployments.
    asn_client_list_id: str | None = Field(
        default=None,
        description="Optional target ASN Client List ID",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Global connector settings.
    """

    connector: StreamConnectorConfig = Field(
        default_factory=StreamConnectorConfig,
    )

    akamai: AkamaiConfig = Field(
        default_factory=AkamaiConfig,
    )
