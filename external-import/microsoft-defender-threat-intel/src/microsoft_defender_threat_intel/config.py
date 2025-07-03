import datetime
import os
from pathlib import Path
from typing import Annotated, Any, Literal


from pydantic import Field, HttpUrl, BeforeValidator, PlainSerializer
from pydantic_core.core_schema import SerializationInfo
from pydantic_settings import (
    SettingsConfigDict,
    BaseSettings,
    PydanticBaseSettingsSource,
    YamlConfigSettingsSource,
)

from microsoft_defender_threat_intel.enums import LogLevelType
from microsoft_defender_threat_intel.errors import ConfigRetrievalError

_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


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


class _BaseSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="allow", frozen=True)


class _OpenCTIConfig(_BaseSettings):
    url: HttpUrl
    token: str


class _ConnectorConfig(_BaseSettings):
    id: str

    name: str = Field(default="Email Intel Microsoft")
    type: str = "EXTERNAL_IMPORT"
    scope: ListFromString = Field(default=["email-intel-microsoft"])
    duration_period: datetime.timedelta = Field(default=datetime.timedelta(hours=1))
    log_level: LogLevelType = Field(default=LogLevelType.ERROR)


class _MicrosoftDefenderThreatIntel(_BaseSettings):
    tenant_id: str
    client_id: str
    client_secret: str

    tlp_level: Literal["white", "clear", "green", "amber", "amber+strict", "red"] = (
        Field(default="amber+strict")
    )


class ConnectorSettings(_BaseSettings):
    model_config = SettingsConfigDict(
        env_nested_delimiter="_",
        env_nested_max_split=1,
        enable_decoding=False,
        yaml_file=f"{_FILE_PATH}/../../config.yml",
        env_file=f"{_FILE_PATH}/../../.env",
    )

    opencti: _OpenCTIConfig = Field(default_factory=lambda: _OpenCTIConfig())
    connector: _ConnectorConfig = Field(default_factory=lambda: _ConnectorConfig())
    microsoft_defender_threat_intel: _MicrosoftDefenderThreatIntel = Field(
        default_factory=lambda: _MicrosoftDefenderThreatIntel()
    )

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
