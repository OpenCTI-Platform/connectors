import json
import os
import warnings
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any, Literal

import __main__
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    HttpUrl,
    PlainSerializer,
    field_validator,
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
        > values = comma_separated_list_validator("a,b,c")
        > print(values) # [ "a", "b", "c" ]
    """
    if isinstance(value, str):
        return [string.strip() for string in value.split(",")]
    return value


def pycti_list_serializer(value: list[str], info: SerializationInfo) -> str | list[str]:
    """
    Serialize list of values as comma-separated string.

    Example:
        > serialized_values = pycti_list_serializer([ "a", "b", "c" ])
        > print(serialized_values) # "a,b,c"
    """
    if isinstance(value, list) and info.context and info.context.get("mode") == "pycti":
        return ",".join(value)
    return value


ListFromString = Annotated[
    list[str],
    BeforeValidator(comma_separated_list_validator),
    PlainSerializer(pycti_list_serializer, when_used="json"),
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
        description="The scope of the connector, e.g. 'socradar'.",
        default=["socradar"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=10),
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


class FeedList(ConfigBaseModel):
    name: str = Field(description="The name of SOCRadar feed list to fetch.")
    id: str = Field(description="The ID of SOCRadar feed list to fetch.")


class RadarConfig(ConfigBaseModel):
    base_feed_url: str = Field(description="SOCRadar Feed API base URL.")
    socradar_key: str = Field(description="The API key to connect to SOCRadar.")
    feed_lists: list[FeedList] = Field(description="The SOCRadar feed lists to fetch.")

    @field_validator("feed_lists", mode="before")
    @classmethod
    def convert_collections_uuid(cls, value: Any) -> dict:
        """
        Config/env vars must be as flat as possible.
        This is a util method to format collections, making them easier to use in the rest of the codebase.
        """
        if isinstance(value, str):
            value = json.loads(value)
        if isinstance(value, dict):
            return [{"name": name, "id": id} for (name, id) in value.items()]
        return value


class ConfigLoader(BaseSettings):
    """
    Define a complete config for a connector with:
        - opencti: the config specific to OpenCTI
        - connector: the config specific to the `external-import` connectors
        - socradar: the config specific to SOCRadar
    """

    opencti: OpenCTIConfig
    connector: ConnectorConfig
    radar: RadarConfig

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
        Env var `RADAR_RUN_INTERVAL` is deprecated.
        This is a workaround to keep the old config working while migrating to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        radar_data: dict = data.get("radar", {})

        if interval := radar_data.pop("run_interval", None):
            warnings.warn(
                "Env var 'RADAR_RUN_INTERVAL' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
            )

            connector_data["duration_period"] = timedelta(seconds=int(interval))

        return data

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_collections_uuid(cls, data: dict) -> dict:
        """
        Env var `RADAR_COLLECTIONS_UUID` is deprecated.
        This is a workaround to keep the old config working while migrating to `RADAR_FEED_LISTS`.
        """
        radar_data: dict = data.get("radar", {})

        # Legacy: key will differ whether data comes from env vars or from config.yml
        collections: dict | str = radar_data.pop(
            "collections_uuid", None
        ) or radar_data.pop("radar_collections_uuid", None)
        if collections:
            warnings.warn(
                "Env var 'RADAR_COLLECTIONS_UUID' is deprecated. Use 'RADAR_FEED_LISTS' instead."
            )

            # If data comes from env vars, collections is serialized JSON
            if isinstance(collections, str):
                collections: dict = json.loads(collections)

            feed_lists = radar_data.get("feed_lists", {})
            for collection_data in collections.values():
                name = collection_data.get("name")
                id = collection_data.get("id")
                if name and id:  # /!\ name and id are lists, not strings
                    feed_lists[name[0]] = id[0]

            radar_data["feed_lists"] = feed_lists

        return data
