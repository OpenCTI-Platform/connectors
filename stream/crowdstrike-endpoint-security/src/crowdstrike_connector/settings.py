from ipaddress import IPv4Address

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic.networks import HttpUrl


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="CrowdstrikeEndpointSecurity",
    )
    scope: ListFromString = Field(
        description="The scope of the connector",
        default=["crowdstrike-endpoint-security"],
    )
    live_stream_id: str = Field(
        description="The ID of the live stream to connect to.",
    )


class CrowdstrikeEndpointSecurityConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `CrowdstrikeEndpointSecurityConnector`.
    """

    api_base_url: HttpUrl = Field(
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
        description="Enable Android and iOS platform support.",
        default=False,
    )


class MetricsConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `Prometheus Metrics`.
    """

    enable: bool = Field(
        description="Whether or not Prometheus metrics should be enabled.",
        default=False,
    )
    port: int | str = Field(
        description="Port to use for metrics endpoint.",
        default=9113,
    )
    addr: str = Field(
        description="Bind IP address to use for metrics endpoint.",
        default="0.0.0.0",
    )

    @field_validator("port", mode="before")
    @classmethod
    def normalize_port(cls, v) -> int | str:
        try:
            return int(v)
        except (TypeError, ValueError):
            return v

    @model_validator(mode="after")
    def validate_metrics_if_enabled(self) -> "MetricsConfig":
        if not self.enable:
            return self
        try:
            IPv4Address(self.addr)
        except ValueError as e:
            raise ValueError(
                "Metrics address must be a valid IPv4 address when enabled."
            ) from e
        if not isinstance(self.port, int):
            raise ValueError("Metrics port must be an integer when enabled.")
        return self


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `CrowdstrikeEndpointSecurityConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    crowdstrike: CrowdstrikeEndpointSecurityConfig = Field(
        default_factory=CrowdstrikeEndpointSecurityConfig
    )
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)
