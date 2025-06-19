import os
import warnings
from datetime import timedelta
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


class OpenCTIConfig(BaseModel):
    url: HttpUrl
    token: str


class ConnectorConfig(BaseModel):
    id: str
    name: str
    type: Literal["EXTERNAL_IMPORT"] = Field(default="EXTERNAL_IMPORT")
    scope: ListFromString
    log_level: LogLevelType
    duration_period: timedelta = Field(default=timedelta(hours=1))


class SocPrimeConfig(BaseModel):
    api_key: str
    content_list_name: ListFromString = Field(default=[])
    job_ids: ListFromString = Field(default=[])
    siem_type: ListFromString = Field(default=[])
    indicator_siem_type: str = Field(default="sigma")

    @model_validator(mode="after")
    def check_dependencies(self):
        # At least one of content_list_name and job_ids must be set and non-empty
        if not self.content_list_name and not self.job_ids:
            raise ValueError(
                "Configuration error. At least one job id or one content list name must be provided."
            )

        # If content_list_name is set, indicator_siem_type must be set too (even if default=’sigma’)
        if self.content_list_name and not self.indicator_siem_type:
            raise ValueError(
                "'indicator_siem_type' must be provided when 'content_list_name' is set."
            )

        return self


class ConnectorSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_nested_delimiter="_",
        env_nested_max_split=1,
        enable_decoding=False,
        extra="allow",
        yaml_file=f"{_FILE_PATH}/../config.yml",
    )

    opencti: OpenCTIConfig
    connector: ConnectorConfig
    socprime: SocPrimeConfig

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
        if Path(settings_cls.model_config["yaml_file"] or "").is_file():  # type: ignore
            return (YamlConfigSettingsSource(settings_cls),)
        return (env_settings,)

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `SOCPRIME_INTERVAL_SEC` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        socprime_data: dict = data.get("socprime", {})

        if interval_sec := socprime_data.pop("interval_sec", None):
            warnings.warn(
                "Env var 'SOCPRIME_INTERVAL_SEC' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
            )

            connector_data["duration_period"] = timedelta(seconds=int(interval_sec))

        return data

    def model_dump_pycti(self) -> dict[str, Any]:
        return self.model_dump(mode="json", context={"mode": "pycti"})
