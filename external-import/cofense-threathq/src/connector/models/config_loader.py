from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal, Optional

from connector.models import ConfigBaseSettings
from pydantic import (
    AwareDatetime,
    Field,
    HttpUrl,
    PlainSerializer,
    PlainValidator,
    PositiveInt,
    field_validator,
)
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]
TimedeltaInSeconds = Annotated[
    timedelta, PlainSerializer(lambda v: int(v.total_seconds()), return_type=int)
]
TLPToLower = Annotated[
    Literal["clear", "green", "amber", "amber+strict", "red"],
    PlainValidator(lambda v: v.lower() if isinstance(v, str) else v),
]
LogLevelToLower = Annotated[
    Literal["debug", "info", "warn", "error"],
    PlainValidator(lambda v: v.lower() if isinstance(v, str) else v),
]


class _ConfigLoaderOCTI(ConfigBaseSettings):
    """Interface for loading OpenCTI dedicated configuration."""

    # Config Loader OpenCTI
    url: HttpUrlToString = Field(
        description="The OpenCTI platform URL.",
    )
    token: str = Field(
        description="The token of the user who represents the connector in the OpenCTI platform.",
    )


class _ConfigLoaderConnector(ConfigBaseSettings):
    """Interface for loading Connector dedicated configuration."""

    # Config Loader Connector
    id: str = Field(
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    type: Optional[str] = Field(
        default="EXTERNAL_IMPORT",
        description="Should always be set to EXTERNAL_IMPORT for this connector.",
    )
    name: Optional[str] = Field(
        default="Cofense ThreatHQ",
        description="Name of the connector.",
    )
    scope: Optional[str] = Field(
        default="Cofense ThreatHQ",
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )
    log_level: Optional[LogLevelToLower] = Field(
        default="info",
        description="Determines the verbosity of the logs.",
    )
    duration_period: Optional[timedelta] = Field(
        default="PT5H",
        description="Duration between two scheduled runs of the connector (ISO 8601 format).",
    )
    queue_threshold: Optional[PositiveInt] = Field(
        default=None,
        description="Connector queue max size in Mbytes. Default to 500.",
    )
    run_and_terminate: Optional[bool] = Field(
        default=None,
        description="Connector run-and-terminate flag.",
    )
    send_to_queue: Optional[bool] = Field(
        default=None,
        description="Connector send-to-queue flag.",
    )
    send_to_directory: Optional[bool] = Field(
        default=None,
        description="Connector send-to-directory flag.",
    )
    send_to_directory_path: Optional[str] = Field(
        default=None,
        description="Connector send-to-directory path.",
    )
    send_to_directory_retention: Optional[PositiveInt] = Field(
        default=None,
        description="Connector send-to-directory retention in days.",
    )

    @field_validator("type")
    def force_value_for_type_to_be_external_import(cls, value):
        return "EXTERNAL_IMPORT"


class _ConfigLoaderCofenseThreatHQ(ConfigBaseSettings):
    """Interface for loading Cofense ThreatHQ dedicated configuration."""

    model_config = SettingsConfigDict(
        env_nested_delimiter="_",
        env_nested_max_split=2,
        frozen=True,
        str_strip_whitespace=True,
        str_min_length=1,
    )

    # Config Loader Cofense ThreatHQ
    token_user: str = Field(
        description="Token User associated with the user to access the Cofense ThreatHQ API.",
    )
    token_password: str = Field(
        description="Token Password associated with the user to access the Cofense ThreatHQ API.",
    )
    import_start_date: Optional[date | AwareDatetime | timedelta] = Field(
        default="P30D",
        description="Start date of first import (ISO date format).",
    )
    api_base_url: Optional[HttpUrlToString] = Field(
        default="https://www.threathq.com/apiv1/",
        description="Base URL of the Cofense ThreatHQ API.",
    )
    api_leaky_bucket_rate: Optional[int] = Field(
        default=10,
        description="Api leaky bucket rate.",
    )
    api_leaky_bucket_capacity: Optional[int] = Field(
        default=10,
        description="Api leaky bucket capacity.",
    )
    api_retry: Optional[int] = Field(
        default=5,
        description="Maximum number of retry attempts in case of API failure.",
    )
    api_backoff: Optional[TimedeltaInSeconds] = Field(
        default="PT30S",
        description="Exponential backoff duration between API retries (ISO 8601 duration format).",
    )
    impact_to_exclude: Optional[list[Literal["none", "moderate", "major"]]] = Field(
        default=None,
        description="List of impact types to exclude: None, Moderate, Major",
    )
    import_report_pdf: Optional[bool] = Field(
        default=True, description="Import Cofense ThreatHQ reports in pdf format."
    )
    tlp_level: Optional[TLPToLower] = Field(
        default="amber+strict",
        description="Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI.",
    )
    promote_observables_as_indicators: Optional[bool] = Field(
        default=True, description="Boolean to promote observables into indicators."
    )

    @field_validator(
        "impact_to_exclude",
        mode="before",
    )
    def parse_list(cls, value):
        if isinstance(value, str):
            return [x.strip().lower() for x in value.split(",") if x.strip()]
        if value is None:
            return []
        return value

    @field_validator("import_start_date", mode="after")
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
        default=_ConfigLoaderOCTI,
        description="OpenCTI configurations.",
    )
    connector: _ConfigLoaderConnector = Field(
        default=_ConfigLoaderConnector,
        description="Connector configurations.",
    )
    cofense_threathq: _ConfigLoaderCofenseThreatHQ = Field(
        default=_ConfigLoaderCofenseThreatHQ,
        description="Cofense ThreatHQ configurations.",
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
