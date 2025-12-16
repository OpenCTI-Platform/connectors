from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
)
from pydantic import Field, SecretStr


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="CrowdstrikeEndpointSecurity",
    )
    live_stream_id: str = Field(
        description="The ID of the live stream to connect to.",
        default="live",  # listen the global stream (not filtered)
    )


class CrowdstrikeEndpointSecurityConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `CrowdstrikeEndpointSecurityConnector`.
    """

    api_base_url: str = Field(
        description="Crowdstrike base url.",
        default="https://api.crowdstrike.com",
    )
    client_id: str = Field(
        description="Crowdstrike client ID used to connect to the API.",
    )
    client_secret: SecretStr = Field(
        description="Crowdstrike client secret used to connect to the API.",
    )
    permanent_delete: bool = Field(
        description="Select whether or not to permanently delete data in Crowdstrike when data is deleted in OpenCTI. If set to `True`, `CONNECTOR_LIVE_STREAM_LISTEN_DELETE` must be set to `True`.",
        default=False,
    )
    falcon_for_mobile_active: bool = Field(
        description="Crowdstrike client secret used to connect to the API.",
        default=False,
    )
    enable: bool = Field(
        description="Whether or not Prometheus metrics should be enabled.",
        default=False,
    )
    port: int = Field(
        description="Port to use for metrics endpoint.",
    )
    addr: str = Field(
        description="Bind IP address to use for metrics endpoint.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `CrowdstrikeEndpointSecurityConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    crowdstrike_endpoint_security: CrowdstrikeEndpointSecurityConfig = Field(
        default_factory=CrowdstrikeEndpointSecurityConfig
    )
