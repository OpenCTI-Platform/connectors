from pydantic_settings import BaseSettings, SettingsConfigDict


class FrozenBaseSettings(BaseSettings):
    """Base class for frozen models. To prevent attributes from being modified after initialization."""

    model_config = SettingsConfigDict(frozen=True)
