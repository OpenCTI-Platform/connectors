from typing import Annotated

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import AfterValidator, Field, HttpUrl, SecretStr
from pydantic.json_schema import SkipJsonSchema

from .backend import BackendNameLiteral
from .common import MAX_EPOCH_SECONDS, MIN_EPOCH_SECONDS, coerce_epoch_millis


def normalize_epoch_millis(value: int) -> int:
    """
    Accept an `initial_history_*` setting given in either epoch milliseconds or epoch
    seconds and always return epoch milliseconds.

    A value that can only be seconds is scaled up; a value that is plausible as
    neither unit is rejected outright, rather than being turned into a 1970 date that
    would re-ingest the whole history unnoticed.

    `0` (the default) is left untouched: it means "no initial history", i.e. start
    from the connector's start date.
    """
    if value == 0:
        return value
    millis = coerce_epoch_millis(value)
    if millis is None:
        raise ValueError(
            f"{value} is not a valid epoch timestamp: expected epoch milliseconds "
            f"(such as `1643989649000`) or epoch seconds (such as `1643989649`) "
            f"between {MIN_EPOCH_SECONDS} and {MAX_EPOCH_SECONDS} seconds "
            f"(2000-01-01 .. 2100-01-01), or `0` for no initial history."
        )
    return millis


EpochMillis = Annotated[int, AfterValidator(normalize_epoch_millis)]


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
        description="Verity Client ID or Titan API Username.",
    )
    api_key: SecretStr = Field(
        description="Verity Client Secret or Titan API Key.",
    )
    backend: BackendNameLiteral = Field(
        description="Backend to use for Intel471 API calls. Defaults to `titan`.",
        default="titan",
    )
    interval_indicators: int = Field(
        description="How often malware indicators should be fetched in minutes. If not set, the stream will not be enabled.",
        default=60,
    )
    initial_history_indicators: EpochMillis = Field(
        description="Initial date in epoch milliseconds UTC, such as `1643989649000`, "
        "the malware indicators should be fetched from on the connector's first run. "
        "If not set, they will be fetched from the connector's start date. Excludes historical dates. "
        "A value given in epoch seconds, such as `1643989649`, is detected and converted to milliseconds.",
        default=0,
    )
    interval_cves: int = Field(
        description="How often CVE reports should be fetched in minutes. If not set, the stream will not be enabled.",
        default=120,
    )
    initial_history_cves: EpochMillis = Field(
        description="Initial date in epoch milliseconds UTC, such as `1643989649000`, "
        "the CVE reports should be fetched from on the connector's first run. "
        "If not set, they will be fetched from the connector's start date. Excludes historical dates. "
        "A value given in epoch seconds, such as `1643989649`, is detected and converted to milliseconds.",
        default=0,
    )
    interval_reports: int = Field(
        description="How often reports should be fetched in minutes. If not set, the stream will not be enabled.",
        default=120,
    )
    initial_history_reports: EpochMillis = Field(
        description="Initial date in epoch milliseconds UTC, such as `1643989649000`, "
        "the reports should be fetched from on the connector's first run. "
        "If not set, they will be fetched from the connector's start date. Excludes historical dates. "
        "A value given in epoch seconds, such as `1643989649`, is detected and converted to milliseconds.",
        default=0,
    )
    interval_yara: int = Field(
        description="How often YARA rules should be fetched in minutes (Titan only). If not set, the stream will not be enabled.",
        default=60,
    )
    initial_history_yara: EpochMillis = Field(
        description="Initial date in epoch milliseconds UTC, such as `1643989649000`, "
        "the YARA rules should be fetched from on the connector's first run (Titan only). "
        "If not set, they will be fetched from the connector's start date. Excludes historical dates. "
        "A value given in epoch seconds, such as `1643989649`, is detected and converted to milliseconds.",
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


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `Intel471_V2Config`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    intel471: Intel471_V2Config = Field(default_factory=Intel471_V2Config)
