from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigBaseSettings(BaseSettings):
    """Base class for global config models. To prevent attributes from being modified after initialization."""

    model_config = SettingsConfigDict(
        env_nested_delimiter="_",
        env_nested_max_split=1,
        frozen=True,
        str_strip_whitespace=True,
        str_min_length=1,
        extra="allow",
    )
