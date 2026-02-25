from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal, Optional

from pydantic import (
    AwareDatetime,
    Field,
    HttpUrl,
    PlainSerializer,
    PositiveInt,
    SecretStr,
    field_validator,
)
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    YamlConfigSettingsSource,
)
from src.connector.models import ConfigBaseSettings

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]
TimedeltaInSeconds = Annotated[
    timedelta, PlainSerializer(lambda v: int(v.total_seconds()), return_type=int)
]
TLPToLower = Annotated[
    Literal["clear", "green", "amber", "amber+strict", "red"],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]
LogLevelToLower = Annotated[
    Literal["debug", "info", "warn", "error"],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]


class _ConfigLoaderOCTI(ConfigBaseSettings):
    """Interface for loading OpenCTI dedicated configuration."""

    # Config Loader OpenCTI
    url: HttpUrlToString = Field(
        alias="OPENCTI_URL",
        description="The OpenCTI platform URL.",
    )
    token: str = Field(
        alias="OPENCTI_TOKEN",
        description="The token of the user who represents the connector in the OpenCTI platform.",
    )


class _ConfigLoaderConnector(ConfigBaseSettings):
    """Interface for loading Connector dedicated configuration."""

    # Config Loader Connector
    id: str = Field(
        alias="CONNECTOR_ID",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    type: Optional[str] = Field(
        alias="CONNECTOR_TYPE",
        default="EXTERNAL_IMPORT",
        description="Should always be set to EXTERNAL_IMPORT for this connector.",
    )
    name: Optional[str] = Field(
        alias="CONNECTOR_NAME",
        default="ServiceNow",
        description="Name of the connector.",
    )
    scope: Optional[str] = Field(
        alias="CONNECTOR_SCOPE",
        default="ServiceNow",
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )
    log_level: Optional[LogLevelToLower] = Field(
        alias="CONNECTOR_LOG_LEVEL",
        default="error",
        description="Determines the verbosity of the logs.",
    )
    duration_period: Optional[timedelta] = Field(
        alias="CONNECTOR_DURATION_PERIOD",
        default="PT24H",
        description="Duration between two scheduled runs of the connector (ISO 8601 format).",
    )
    queue_threshold: Optional[PositiveInt] = Field(
        alias="CONNECTOR_QUEUE_THRESHOLD",
        default=None,
        description="Connector queue max size in Mbytes. Default to 500.",
    )
    run_and_terminate: Optional[bool] = Field(
        alias="CONNECTOR_RUN_AND_TERMINATE",
        default=None,
        description="Connector run-and-terminate flag.",
    )
    send_to_queue: Optional[bool] = Field(
        alias="CONNECTOR_SEND_TO_QUEUE",
        default=None,
        description="Connector send-to-queue flag.",
    )
    send_to_directory: Optional[bool] = Field(
        alias="CONNECTOR_SEND_TO_DIRECTORY",
        default=None,
        description="Connector send-to-directory flag.",
    )
    send_to_directory_path: Optional[str] = Field(
        alias="CONNECTOR_SEND_TO_DIRECTORY_PATH",
        default=None,
        description="Connector send-to-directory path.",
    )
    send_to_directory_retention: Optional[PositiveInt] = Field(
        alias="CONNECTOR_SEND_TO_DIRECTORY_RETENTION",
        default=None,
        description="Connector send-to-directory retention in days.",
    )

    @field_validator("type")
    def force_value_for_type_to_be_external_import(cls, value):
        return "EXTERNAL_IMPORT"


class _ConfigLoaderServiceNow(ConfigBaseSettings):
    """Interface for loading ServiceNow dedicated configuration."""

    # Config Loader ServiceNow
    instance_name: str = Field(
        alias="SERVICENOW_INSTANCE_NAME",
        description="Corresponds to server instance name (will be used for API requests).",
    )
    api_key: SecretStr = Field(
        alias="SERVICENOW_API_KEY",
        description="Secure identifier used to validate access to ServiceNow APIs.",
    )
    api_version: Optional[Literal["v1", "v2"]] = Field(
        alias="SERVICENOW_API_VERSION",
        default="v2",
        description="ServiceNow API version used for REST requests.",
    )
    api_leaky_bucket_rate: Optional[PositiveInt] = Field(
        alias="SERVICENOW_API_LEAKY_BUCKET_RATE",
        default=10,
        description="Bucket refill rate (in tokens per second). Controls the rate at which API calls are allowed. "
        "For example, a rate of 10 means that 10 calls can be made per second, if the bucket is not empty.",
    )
    api_leaky_bucket_capacity: Optional[PositiveInt] = Field(
        alias="SERVICENOW_API_LEAKY_BUCKET_CAPACITY",
        default=10,
        description="Maximum bucket capacity (in tokens). Defines the number of calls that can be made immediately in a "
        "burst. Once the bucket is empty, it refills at the rate defined by 'api_leaky_bucket_rate'.",
    )
    api_retry: Optional[PositiveInt] = Field(
        alias="SERVICENOW_API_RETRY",
        default=5,
        description="Maximum number of retry attempts in case of API failure.",
    )
    api_backoff: Optional[TimedeltaInSeconds] = Field(
        alias="SERVICENOW_API_BACKOFF",
        default="PT30S",
        description="Exponential backoff duration between API retries (ISO 8601 duration format).",
    )
    import_start_date: Optional[date | AwareDatetime | timedelta] = Field(
        alias="SERVICENOW_IMPORT_START_DATE",
        default="P30D",
        description="Start date of first import (ISO date format).",
    )
    state_to_exclude: Optional[list[str]] = Field(
        alias="SERVICENOW_STATE_TO_EXCLUDE",
        default=None,
        description="List of security incident states to exclude from import.",
    )
    severity_to_exclude: Optional[list[str]] = Field(
        alias="SERVICENOW_SEVERITY_TO_EXCLUDE",
        default=None,
        description="List of security incident severities to exclude from import.",
    )
    priority_to_exclude: Optional[list[str]] = Field(
        alias="SERVICENOW_PRIORITY_TO_EXCLUDE",
        default=None,
        description="List of security incident priorities to exclude from import.",
    )
    comment_to_exclude: Optional[list[Literal["private", "public", "auto"]]] = Field(
        alias="SERVICENOW_COMMENT_TO_EXCLUDE",
        default=None,
        description="List of comment types to exclude: private, public, auto",
    )
    tlp_level: Optional[TLPToLower] = Field(
        alias="SERVICENOW_TLP_LEVEL",
        default="red",
        description="Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI.",
    )
    observables_default_score: Optional[PositiveInt] = Field(
        alias="SERVICENOW_OBSERVABLES_DEFAULT_SCORE",
        default=50,
        description="Allows you to define a default score for observables and indicators when the "
        "'promote_observables_as_indicators' variable is set to True.",
    )
    promote_observables_as_indicators: Optional[bool] = Field(
        alias="SERVICENOW_PROMOTE_OBSERVABLES_AS_INDICATORS",
        default=True,
        description="Boolean to promote observables into indicators.",
    )
    sysparam_display_value: Optional[bool] = Field(
        alias="SERVICENOW_SYSPARAM_DISPLAY_VALUE",
        default=True,
        description="Boolean to populate the queryparam syparam_display_value.",
    )

    @field_validator(
        "state_to_exclude",
        "severity_to_exclude",
        "priority_to_exclude",
        "comment_to_exclude",
        mode="before",
    )
    def parse_list(cls, value):
        if isinstance(value, str):
            return [x.strip().lower() for x in value.split(",") if x.strip()]
        return value

    @field_validator("import_start_date", mode="after", check_fields=True)
    def _convert_import_start_date_relative_to_utc_datetime(
        cls, value: date | AwareDatetime | timedelta
    ) -> date | AwareDatetime | datetime:
        """Allow relative import_start_date values (timedelta)."""
        if isinstance(value, timedelta):
            return datetime.now(tz=timezone.utc) - value
        return value


class ConfigLoader(ConfigBaseSettings):
    """Interface for loading global configuration settings."""

    opencti: _ConfigLoaderOCTI = Field(
        default_factory=_ConfigLoaderOCTI,
        description="OpenCTI configurations.",
    )
    connector: _ConfigLoaderConnector = Field(
        default_factory=_ConfigLoaderConnector,
        description="Connector configurations.",
    )
    servicenow: _ConfigLoaderServiceNow = Field(
        default_factory=_ConfigLoaderServiceNow,
        description="ServiceNow configurations.",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource]:
        env_path = Path(__file__).parents[2] / ".env"
        yaml_path = Path(__file__).parents[2] / "config.yml"

        if env_path.exists():
            return (
                DotEnvSettingsSource(
                    settings_cls,
                    env_file=env_path,
                    env_ignore_empty=True,
                    env_file_encoding="utf-8",
                ),
            )
        elif yaml_path.exists():
            return (
                YamlConfigSettingsSource(
                    settings_cls,
                    yaml_file=yaml_path,
                    yaml_file_encoding="utf-8",
                ),
            )
        else:
            return (
                EnvSettingsSource(
                    settings_cls,
                    env_ignore_empty=True,
                ),
            )
