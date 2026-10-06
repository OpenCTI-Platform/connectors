from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator


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
        default="DatadogIntelConnector",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["indicator"],
    )
    live_stream_id: str = Field(
        description="The ID of the live stream to connect to.",
    )


class DatadogIntelConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DatadogIntelConnector`.
    """

    integration_api_url: HttpUrl = Field(
        description=(
            "Datadog's API URL as provided by the integration. "
            "If your Datadog site is `https://app.datadoghq.com`, use `https://api.datadoghq.com/api/v2/security/threat-intel-feed`"
        )
    )
    indicator_type: ListFromString = Field(
        description=(
            "Types of indicators to send to the API. Accepted values: "
            "'ip_address', 'domain', 'sha256'."
        ),
        default=["ip_address"],
    )
    dd_api_key: SecretStr = Field(
        description=(
            "Datadog's API key. "
            "Sent on every request as the `dd-api-key` header to authenticate against `integration_api_url`"
        )
    )
    dd_application_key: SecretStr = Field(
        description=(
            "Datadog's application key. "
            "Sent on every request as the `dd-application-key` header to authenticate against `integration_api_url`"
        )
    )

    @field_validator("indicator_type", mode="after")
    def _validate_indicator_type(cls, value: list[str]) -> list[str]:
        """
        Validate that the indicator types are valid.
        """
        valid_types = {"ip_address", "domain", "sha256"}
        invalid_types = set(value) - valid_types
        if invalid_types:
            raise ValueError(
                f"Invalid indicator types: {', '.join(invalid_types)}. "
                f"Valid types are: {', '.join(valid_types)}."
            )
        return value


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `DatadogIntelConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    datadog_intel: DatadogIntelConfig = Field(default_factory=DatadogIntelConfig)
