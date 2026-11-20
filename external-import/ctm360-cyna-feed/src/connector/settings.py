from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="6c7aa0f8-dd1b-419b-bb51-e8502c08c056",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["ctm360-cyna"],
    )
    name: str = Field(default="CTM360-CYNA")
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=24),
        gt=timedelta(0),
    )


class CTM360CynaConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        default="https://cyna.ctm360.com",
        description="CYNA API base URL.",
    )
    api_key: SecretStr = Field(description="API key for CYNA authentication.")
    import_interval: int | None = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda x: timedelta(seconds=int(x)),
        description="Interval in seconds between imports.",
    )
    page_size: int = Field(
        default=25,
        gt=0,
        description="Number of news items per API page (default: 25).",
    )
    max_pages: int = Field(
        default=100,
        gt=0,
        description="Maximum pages to fetch per import cycle (safety limit).",
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    ctm360_cyna: CTM360CynaConfig = Field(default_factory=CTM360CynaConfig)
