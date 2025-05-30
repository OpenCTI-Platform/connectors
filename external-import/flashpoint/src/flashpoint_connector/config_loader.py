import os
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal

import __main__
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    HttpUrl,
    PlainSerializer,
    TypeAdapter,
    model_validator,
)
from pydantic_core.core_schema import SerializationInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

# Get the path of the __main__ module file (the entry point of the connector)
_MAIN_PATH = os.path.dirname(os.path.abspath(__main__.__file__))

"""
All the variables that have default values will override configuration from the OpenCTI helper.

All the variables of this classes are customizable through:
    - config.yml 
    - .env
    - environment variables.

If a variable is set in 2 different places, the first one will be used in this order:
    1. YAML file
    2. .env file
    3. Environment variables
    4. Default value
    
WARNING:
    The Environment variables in the .env or global environment must be set in the following format:
    OPENCTI_<variable>
    CONNECTOR_<variable>
    
    the split is made on the first occurrence of the "_" character.
"""


class ConfigRetrievalError(Exception):
    """Known errors wrapper for config loaders."""


def comma_separated_list_validator(value: str | list[str]) -> list[str]:
    """
    Convert comma-separated string into a list of values.

    Example:
        > values = pycti_list_validator("e1,e2,e3")
        > print(values) # [ "e1", "e2", "e3" ]
    """
    if isinstance(value, str):
        return [string.strip() for string in value.split(",")]
    return value


def iso_string_validator(value: str) -> datetime:
    """
    Convert ISO string into a datetime object.

    Example:
        > value = iso_string_validator("2023-10-01T00:00:00Z")
        > print(value) # 2023-10-01 00:00:00+00:00

        # If today is 2023-10-01:
        > value = iso_string_validator("P30D")
        > print(value) # 2023-09-01 00:00:00+00:00
    """
    if isinstance(value, str):
        try:
            # Convert presumed ISO string to datetime object
            return datetime.fromisoformat(value).astimezone(tz=timezone.utc)
        except ValueError:
            # If not a datetime ISO string, try to parse it as timedelta with pydantic first
            duration = TypeAdapter(timedelta).validate_python(value)
            # Then return a datetime minus the value
            return datetime.now(timezone.utc) - duration
    return value


def pycti_list_serializer(value: list[str], info: SerializationInfo) -> str | list[str]:
    """
    Serialize list of values as comma-separated string.

    Example:
        > serialized_values = pycti_list_serializer([ "e1", "e2", "e3" ])
        > print(serialized_values) # "e1,e2,e3"
    """
    if isinstance(value, list) and info.context and info.context.get("mode") == "pycti":
        return ",".join(value)
    return value


ListFromString = Annotated[
    list[str],
    BeforeValidator(comma_separated_list_validator),
    PlainSerializer(pycti_list_serializer, when_used="json"),
]

DatetimeFromIsoString = Annotated[
    datetime,
    BeforeValidator(iso_string_validator),
    # Replace the default serializer as it uses Z prefix instead of +00:00 offset
    PlainSerializer(datetime.isoformat, when_used="json"),
]


class ConfigBaseModel(BaseModel):
    """
    Base class for frozen config models, i.e. not alter-able after `model_post_init()`.
    """

    model_config = ConfigDict(frozen=True)


class OpenCTIConfig(ConfigBaseModel):
    """
    Define config specific to OpenCTI.
    """

    url: HttpUrl = Field(description="The base URL of the OpenCTI instance.")
    token: str = Field(description="The API token to connect to OpenCTI.")
    json_logging: bool = Field(
        description="Whether to format logs as JSON or not.",
        default=True,
    )
    ssl_verify: bool = Field(
        description="Whether to check SSL certificate or not.",
        default=False,
    )


class ConnectorConfig(ConfigBaseModel):
    """
    Define config specific to this type of connector, e.g. an `external-import`.
    """

    id: str = Field(description="A UUID v4 to identify the connector in OpenCTI.")
    name: str = Field(description="The name of the connector.")
    type: Literal["EXTERNAL_IMPORT"] = "EXTERNAL_IMPORT"
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'flashpoint'.",
        default=["flashpoint"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )

    log_level: Literal[
        "debug",
        "info",
        "warn",
        "error",
    ] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )
    expose_metrics: bool = Field(
        description="Whether to expose metrics or not.",
        default=False,
    )
    metrics_port: int = Field(
        description="The port to expose metrics.",
        default=9095,
    )
    only_contextual: bool = Field(
        description="Whether to expose metrics or not.",
        default=False,
    )
    run_and_terminate: bool = Field(
        description="Connector run-and-terminate flag.",
        default=False,
    )
    validate_before_import: bool = Field(
        description="Whether to validate data before import or not.",
        default=False,
    )
    queue_protocol: str = Field(
        description="The queue protocol to use.",
        default="amqp",
    )
    queue_threshold: int = Field(
        description="Connector queue max size in Mbytes. Default to pycti value.",
        default=500,
    )
    send_to_queue: bool = Field(
        description="Connector send-to-queue flag. Default to True.",
        default=True,
    )
    send_to_directory: bool = Field(
        description="Connector send-to-directory flag.",
        default=False,
    )
    send_to_directory_path: str | None = Field(
        description="Connector send-to-directory path.",
        default=None,
    )
    send_to_directory_retention: int = Field(
        description="Connector send-to-directory retention.",
        default=7,
    )


class FlashpointConfig(ConfigBaseModel):
    api_key: str = Field(description="The API key to connect to Flashpoint.")
    import_start_date: DatetimeFromIsoString = Field(
        description="The date from which to start importing data.",
        default_factory=lambda: iso_string_validator("P30D"),  # 30 days ago
    )
    import_reports: bool = Field(
        description="Whether to import reports from Flashpoint or not.",
        default=True,
    )
    indicators_in_reports: bool = Field(
        description="Whether to include indicators in the reports imported from MispFeed or not.",
        default=False,
    )
    guess_relationships_from_reports: bool = Field(
        description="Whether to guess relationships between entities or not.",
        default=False,
    )
    import_indicators: bool = Field(
        description="WHether to import indicators of compromise (IoCs) or not.",
        default=True,
    )
    import_alerts: bool = Field(
        description="Whether to import alert data from Flashpoint or not.",
        default=True,
    )
    alert_create_related_entities: bool = Field(
        description="Whether to create alert related Channel entity and Media-Content observable or not.",
        default=False,
    )
    import_communities: bool = Field(
        description="Whether to import community data or not.",
        default=False,
    )
    communities_queries: ListFromString = Field(
        description="List of community queries to execute.",
        default=["cybersecurity", "cyberattack"],
    )
    import_ccm_alerts: bool = Field(
        description="Whether to import Compromised Credentials Monitoring alerts or not.",
        default=False,
    )
    fresh_ccm_alerts_only: bool = Field(
        description="Whether to import only fresh Compromised Credentials Monitoring alerts or all of them.",
        default=True,
    )


class ConfigLoader(BaseSettings):
    """
    Define a complete config for a connector with:
        - opencti: the config specific to OpenCTI
        - connector: the config specific to the `external-import` connectors
        - flashpoint: the config specific to Flashpoint
    """

    opencti: OpenCTIConfig
    connector: ConnectorConfig
    flashpoint: FlashpointConfig

    # Setup model config and env vars parsing
    model_config = SettingsConfigDict(
        frozen=True,
        env_nested_delimiter="_",
        env_nested_max_split=1,
        enable_decoding=False,
        yaml_file=f"{_MAIN_PATH}/config.yml",
        env_file=f"{_MAIN_PATH}/../.env",
    )

    def __init__(self) -> None:
        """
        Wrap BaseConnectorConfig initialization to raise custom exception in case of error.
        """
        try:
            super().__init__()
        except Exception as e:
            raise ConfigRetrievalError("Invalid connector configuration.", e) from e

    def model_dump_pycti(self) -> dict:
        """
        Convert model into a valid dict for `pycti.OpenCTIConnectorHelper`.
        """
        return self.model_dump(mode="json", context={"mode": "pycti"})

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """
        Customise the sources of settings for the connector.

        This method is called by the Pydantic BaseSettings class to determine the order of sources

        The configuration come in this order either from:
            1. YAML file
            2. .env file
            3. Environment variables
            4. Default values
        """
        if Path(settings_cls.model_config["yaml_file"] or "").is_file():  # type: ignore
            return (YamlConfigSettingsSource(settings_cls),)
        if Path(settings_cls.model_config["env_file"] or "").is_file():  # type: ignore
            return (dotenv_settings,)
        return (env_settings,)

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `FLASHPOINT_INTERVAL` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        flashpoint_data: dict = data.get("flashpoint", {})

        if interval := flashpoint_data.pop("interval", None):
            warnings.warn(
                "Env var 'FLASHPOINT_INTERVAL' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
            )

            connector_data["duration_period"] = timedelta(minutes=int(interval))

        return data
