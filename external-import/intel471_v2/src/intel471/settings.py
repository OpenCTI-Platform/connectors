from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Intel471_V2",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class Intel471_V2Config(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `Intel471_V2Connector`.
    """

    api_username: str = Field(
        description="Titan API username",
    )
    api_key: SecretStr = Field(
        description="Titan API key",
    )
    interval_indicators: int = Field(
        description="How often malware indicators should be fetched in minutes. If not set, the stream will not be enabled.",
        default=60,
    )
    initial_history_indicators: int = Field(
        description="Initial date in epoch milliseconds UTC, such as 1643989649000, the malware indicators should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates.",
        default=0,
    )
    interval_yara: int = Field(
        description="How often YARA rules should be fetched in minutes. If not set, the stream will not be enabled.",
        default=60,
    )
    initial_history_yara: int = Field(
        description="Initial date in epoch milliseconds UTC, such as 1643989649000, the YARA rules should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates.",
        default=0,
    )
    interval_cves: int = Field(
        description="How often CVE reports should be fetched in minutes. If not set, the stream will not be enabled.",
        default=120,
    )
    initial_history_cves: int = Field(
        description="Initial date in epoch milliseconds UTC, such as 1643989649000, the CVE reports should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates.",
        default=0,
    )
    interval_reports: int = Field(
        description="How often reports should be fetched in minutes. If not set, the stream will not be enabled.",
        default=120,
    )
    initial_history_reports: int = Field(
        description="Initial date in epoch milliseconds UTC, such as 1643989649000, the reports should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates.",
        default=0,
    )
    proxy: str | None = Field(
        description="Optional Proxy URL, for example `http://user:pass@localhost:3128`",
        default=None,
    )
    ioc_score: int = Field(
        description="Indicator score. Defaults to `70`.",
        default=70,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `Intel471_V2Config`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    intel471: Intel471_V2Config = Field(default_factory=Intel471_V2Config)
