from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="5f8830a4-97ab-42f1-878c-1aa59b992dee",
    )
    name: str = Field(
        description="The name of the connector.",
        default="DatadogIntel",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )


class DatadogIntelConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DatadogIntelConnector`.
    """

    integration_api_url: str = Field(
        description=(
            "Datadog Threat Intel Feed API endpoint. If your Datadog site is "
            "'https://app.datadoghq.com', use "
            "'https://api.datadoghq.com/api/v2/security/threat-intel-feed'."
        )
    )
    indicator_type: list[str] = Field(
        description=(
            "List of indicator types to forward. Accepted values: "
            "'ip_address', 'domain', 'sha256'."
        ),
        default=["ip_address"],
    )
    dd_api_key: SecretStr = Field(
        description=(
            "Datadog API Key. Sent on every request as the 'dd-api-key' header "
            "to authenticate against 'integration_api_url'."
        )
    )
    dd_application_key: SecretStr = Field(
        description=(
            "Datadog Application Key (or Personal Access Token). Sent on every request "
            "as the 'dd-application-key' header to authenticate against 'integration_api_url'."
        )
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `DatadogIntelConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    datadog_intel: DatadogIntelConfig = Field(default_factory=DatadogIntelConfig)
