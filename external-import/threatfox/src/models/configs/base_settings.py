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
        enable_decoding=False,
        # Allow both alias and field name for input
        validate_by_name=True,
        validate_by_alias=True,
        # A validation error echoes the raw input by default, which holds the Spamhaus
        # password, the Auth-Key and the OpenCTI token in clear text.
        hide_input_in_errors=True,
    )
