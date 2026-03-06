import os
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal, Optional

import __main__
from pydantic import (
    AliasChoices,
    BeforeValidator,
    Field,
    HttpUrl,
    PlainSerializer,
    SecretStr,
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


class ConfigBaseModel(BaseSettings):
    """Base class for global config models. To prevent attributes from being modified after initialization."""

    model_config = SettingsConfigDict(
        env_nested_delimiter="_",
        env_nested_max_split=1,
        frozen=True,
        str_strip_whitespace=True,
        str_min_length=1,
        extra="allow",
        enable_decoding=False,
        # Allow both alias and field name for input
        validate_by_name=True,
        validate_by_alias=True,
    )


class OpenCTIConfig(ConfigBaseModel):
    """
    Define config specific to OpenCTI.
    """

    url: HttpUrl = Field(description="The base URL of the OpenCTI instance.")
    token: str = Field(description="The API token to connect to OpenCTI.")


class ConnectorConfig(ConfigBaseModel):
    """
    Define config specific to this type of connector, e.g. an `external-import`.
    """

    type: Literal["EXTERNAL_IMPORT"] = "EXTERNAL_IMPORT"
    id: str = Field(
        default="greynoise-feed--d063e13b-194a-44e3-8654-eb0609c57737",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        description="The name of the connector.",
        default="GreyNoise Feed",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'greynoise'.",
        default=["greynoisefeed"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=6),
    )
    log_level: Optional[
        Literal[
            "debug",
            "info",
            "warn",
            "warning",
            "error",
        ]
    ] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )


class GreynoiseConfig(ConfigBaseModel):
    api_key: SecretStr = Field(description="The API key to connect to Greynoise.")
    feed_type: Optional[
        Literal[
            "benign",
            "malicious",
            "suspicious",
            "benign+malicious",
            "malicious+suspicious",
            "benign+suspicious+malicious",
            "all",
        ]
    ] = Field(
        description="Type of feed to import.",
        default="malicious",
    )
    limit: int = Field(
        description="Max number of indicators to ingest.",
        default=10_000,
    )
    indicator_score_malicious: int = Field(
        description="Default indicator score for malicious indicators.",
        ge=0,
        le=100,
        default=75,
    )
    indicator_score_suspicious: int = Field(
        description="Default indicator score for suspicious indicators.",
        ge=0,
        le=100,
        default=50,
    )
    indicator_score_benign: int = Field(
        description="Default indicator score for benign indicators.",
        ge=0,
        le=100,
        default=20,
    )


class ConfigLoader(BaseSettings):
    """
    Define a complete config for a connector with:
        - opencti: the config specific to OpenCTI
        - connector: the config specific to the `external-import` connectors
        - greynoise: the config specific to Greynoise
    """

    opencti: OpenCTIConfig
    connector: ConnectorConfig
    greynoise_feed: GreynoiseConfig = Field(
        # For retro compatibility
        validation_alias=AliasChoices("greynoise_feed", "greynoise"),
    )

    # Setup model config and env vars parsing
    model_config = SettingsConfigDict(
        extra="ignore",
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
        Env var `GREYNOISE_INTERVAL` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        greynoise_data: dict = data.get("greynoise_feed") or data.get("greynoise") or {}

        if interval := greynoise_data.pop("interval", None):
            warnings.warn(
                "Env var 'GREYNOISE_INTERVAL' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
            )

            connector_data["duration_period"] = timedelta(hours=int(interval))

        return data
