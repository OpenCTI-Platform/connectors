from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from connectors_sdk.settings.annotated_types import parse_comma_separated_list
from pydantic import BeforeValidator, Field, SecretStr, field_validator
from spycloud_connector.models.opencti import TLPMarkingLevel
from spycloud_connector.models.spycloud import (
    BreachRecordSeverity,
    BreachRecordWatchlistType,
)


def _parse_severity_levels(value: Any) -> Any:
    """Coerce a comma-separated string (e.g. '20,25') into a list of ints."""
    if isinstance(value, str):
        return [int(string) for string in parse_comma_separated_list(value)]
    return value


class SpyCloudConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.

    Mirrors the existing `CONNECTOR_*` variables consumed by the SpyCloud connector.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="fac85592-0596-437b-8ee2-96e3c23c2fe9",
    )
    name: str = Field(
        description="The name of the connector.",
        default="SpyCloud",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["spycloud"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="debug",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class SpyCloudConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `SpyCloudConnector`.

    Mirrors the existing `SPYCLOUD_*` variables.
    """

    api_base_url: str = Field(
        description="SpyCloud API base URL (a trailing slash is added if missing).",
    )
    api_key: SecretStr = Field(
        description="SpyCloud API key.",
    )
    severity_levels: Annotated[
        list[BreachRecordSeverity], BeforeValidator(_parse_severity_levels)
    ] = Field(
        description=(
            "Comma-separated list of severities to filter breach records "
            "(allowed values are 2, 5, 20, 25). Leave empty to import all severities."
        ),
        default=[],
    )
    watchlist_types: Annotated[
        list[BreachRecordWatchlistType], BeforeValidator(parse_comma_separated_list)
    ] = Field(
        description=(
            "Comma-separated list of watchlist types to filter breach records "
            "(allowed values are 'email', 'domain', 'subdomain', 'ip'). "
            "Leave empty to import all watchlist types."
        ),
        default=[],
    )
    tlp_level: TLPMarkingLevel = Field(
        description="TLP level to set on imported entities.",
        default="amber+strict",
    )
    import_start_date: DatetimeFromIsoString = Field(
        description=(
            "The date to start importing breach records from, used only if the "
            "connector's state is not set. Can be either absolute (ISO 8601 date, "
            "e.g. '2024-01-01T00:00:00Z') or relative (ISO 8601 duration, "
            "e.g. 'P30D' for 30 days ago)."
        ),
        default_factory=lambda: datetime.now(UTC) - timedelta(days=30),
    )

    @field_validator("api_base_url")
    @classmethod
    def _add_trailing_slash(cls, value: str) -> str:
        """Ensure the API base URL ends with a slash, so that endpoints can be joined to it."""
        return value if value.endswith("/") else f"{value}/"


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `SpyCloudConnectorConfig` and `SpyCloudConfig`.
    """

    connector: SpyCloudConnectorConfig = Field(default_factory=SpyCloudConnectorConfig)
    spycloud: SpyCloudConfig = Field(default_factory=SpyCloudConfig)
