import datetime
import os
import warnings
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    Field,
    HttpUrl,
    PlainSerializer,
    model_validator,
)
from pydantic_core.core_schema import SerializationInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


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


class LogLevelType(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


def environ_list_validator(value: str | list[str]) -> list[str]:
    if isinstance(value, str):
        return [string.strip() for string in value.split(",")]
    return value


def pycti_list_serializer(v: list[str], info: SerializationInfo) -> str | list[str]:
    if isinstance(v, list) and info.context and info.context.get("mode") == "pycti":
        return ",".join(v)  # [ "e1", "e2", "e3" ] -> "e1,e2,e3"
    return v


ListFromString = Annotated[
    list[str],  # Final type
    BeforeValidator(environ_list_validator),
    PlainSerializer(pycti_list_serializer, when_used="json"),
]


class _BaseModel(BaseModel):
    model_config = SettingsConfigDict(extra="allow", frozen=True)


class _OpenCTIConfig(_BaseModel):
    url: HttpUrl
    token: str


class _ConnectorConfig(_BaseModel):
    id: str
    type: str = "EXTERNAL_IMPORT"  # FIXME: double check
    name: str = Field(default="Shadowserver")
    scope: ListFromString = Field(default=["stix2"])
    log_level: LogLevelType = Field(default=LogLevelType.ERROR)
    duration_period: datetime.timedelta = Field(default=datetime.timedelta(days=1))

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated(cls, data: Any) -> datetime.timedelta:
        if run_every := data.pop("run_every", "").upper():
            # run_every is deprecated. This is a workaround to keep the old config working
            # while we migrate to duration_period.
            warnings.warn(
                "CONNECTOR_RUN_EVERY is deprecated. Use CONNECTOR_DURATION_PERIOD instead."
            )
            if data.get("duration_period"):
                raise ValueError("Cannot set both run_every and duration_period.")
            if run_every[-1] in ["H", "M", "S"]:
                data["duration_period"] = (
                    f"PT{int(float(run_every[:-1]))}{run_every[-1]}"
                )
            else:
                data["duration_period"] = (
                    f"P{int(float(run_every[:-1]))}{run_every[-1]}"
                )
        return data


class _ShadowserverConfig(_BaseModel):
    marking: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(default="TLP:WHITE")
    api_key: str
    api_secret: str
    create_incident: bool = Field(default=False)
    incident_severity: str = Field(default="low")
    incident_priority: str = Field(default="P4")


class ConnectorSettings(BaseSettings):
    # files needs to be at the same level as the module
    model_config = SettingsConfigDict(
        env_nested_delimiter="_",
        env_nested_max_split=1,
        enable_decoding=False,
        yaml_file=f"{_FILE_PATH}/../../config.yml",
        env_file=f"{_FILE_PATH}/../../.env",
        extra="allow",
    )

    opencti: _OpenCTIConfig = Field(default_factory=lambda: _OpenCTIConfig())
    connector: _ConnectorConfig = Field(default_factory=lambda: _ConnectorConfig())
    shadowserver: _ShadowserverConfig = Field(default_factory=_ShadowserverConfig)

    def __init__(self) -> None:
        try:
            super().__init__()
        except Exception as e:
            raise ConfigRetrievalError("Invalid OpenCTI configuration.", e) from e

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

    def model_dump_pycti(self) -> dict[str, Any]:
        return self.model_dump(mode="json", context={"mode": "pycti"})
