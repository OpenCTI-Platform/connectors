from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import AliasChoices, Field, HttpUrl, SecretStr
from pydantic.json_schema import SkipJsonSchema

from .backend import BackendNameLiteral


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="The UUID of the connector.",
        default="d5067b93-7f6a-47e2-b76d-bb4ed69e270d",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Intel471 v2",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'malware, vulnerability, indicator'.",
        default=["malware", "vulnerability", "indicator"],
    )
    # Override `BaseExternalImportConnectorConfig.duration_period` as `pycti`'s scheduler is not implemented yet
    duration_period: SkipJsonSchema[None] = Field(
        description="Dot not use. Not implemented in the connector yet.",
        default=None,
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
        description="Initial date in epoch milliseconds UTC, such as `1643989649000`, "
        "the malware indicators should be fetched from on the connector's first run. "
        "If not set, they will be fetched from the connector's start date. Excludes historical dates.",
        default=0,
    )
    interval_yara: int = Field(
        description="How often YARA rules should be fetched in minutes. If not set, the stream will not be enabled.",
        default=60,
    )
    initial_history_yara: int = Field(
        description="Initial date in epoch milliseconds UTC, such as `1643989649000`, "
        "the YARA rules should be fetched from on the connector's first run. "
        "If not set, they will be fetched from the connector's start date. Excludes historical dates.",
        default=0,
    )
    interval_cves: int = Field(
        description="How often CVE reports should be fetched in minutes. If not set, the stream will not be enabled.",
        default=120,
    )
    initial_history_cves: int = Field(
        description="Initial date in epoch milliseconds UTC, such as `1643989649000`, "
        "the CVE reports should be fetched from on the connector's first run. "
        "If not set, they will be fetched from the connector's start date. Excludes historical dates.",
        default=0,
    )
    interval_reports: int = Field(
        description="How often reports should be fetched in minutes. If not set, the stream will not be enabled.",
        default=120,
    )
    initial_history_reports: int = Field(
        description="Initial date in epoch milliseconds UTC, such as `1643989649000`, "
        "the reports should be fetched from on the connector's first run. "
        "If not set, they will be fetched from the connector's start date. Excludes historical dates.",
        default=0,
    )
    proxy: HttpUrl | None = Field(
        description="Optional Proxy URL, for example `http://user:pass@localhost:3128`",
        default=None,
    )
    ioc_score: int = Field(
        description="Indicator score. Defaults to `70`.",
        default=70,
    )
    backend: BackendNameLiteral = Field(
        description="Backend to use for Intel471 API calls. Defaults to `titan`.",
        default="titan",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `Intel471_V2Config`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    intel471: Intel471_V2Config = Field(default_factory=Intel471_V2Config)

    # Detached opencti-ng mode (optional). When both are set, the connector
    # ingests directly into opencti-ng over a JWT (no OpenCTI worker/queue); the
    # write tenant and connector id are read from the JWT, run state lives
    # server-side.
    opencti_ng_url: HttpUrl | None = Field(
        default=None,
        validation_alias=AliasChoices("opencti_ng_url", "OPENCTI_NG_URL"),
        description="opencti-ng base URL for detached mode (set with opencti_ng_jwt).",
    )
    opencti_ng_jwt: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("opencti_ng_jwt", "OPENCTI_NG_JWT"),
        description="Long-lived connector JWT for opencti-ng detached mode.",
    )

    @property
    def opencti_ng_enabled(self) -> bool:
        """Whether detached opencti-ng mode is configured."""
        return self.opencti_ng_url is not None and self.opencti_ng_jwt is not None

