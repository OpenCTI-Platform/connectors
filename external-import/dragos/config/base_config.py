import abc

from pydantic import HttpUrl, SecretStr
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

"""
    This classes should be in pycti and be used by the OpenCTIHelper.
    
    All the commented variables have default values in the OpenCTI helper.
    - Remove old configuration from the OpenCTI helper.
    - Implement the new configuration classes in the OpenCTI helper.
    - Type and set properly all the properties of this classes
    
    Then, All the variables of this classes will be customizable through:
     .env, config.yml and/or environment variables.
     
    If a variable is set in 2 different places, the first one will be used in this order:
        1. Secret files
        2. YAML file
        3. .env file
        4. Initial settings
        5. Environment variables
        6. Default value
"""


class _BaseSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_nested_delimiter="_",  # FIXME: Should be "__"
        env_nested_max_split=1,  # FIXME: Must find another way
        yaml_file="config.yml",
    )

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
        Define the sources and their order for loading the settings values.
        """
        return (
            file_secret_settings,  # First: secret files
            YamlConfigSettingsSource(settings_cls),  # Optional: fallback YAML file
            dotenv_settings,  # Optional: fallback to .env file
            init_settings,  # Optional: fallback to initial settings
            env_settings,  # Optional: environment variables
        )


class _OpenCTIConfig(BaseSettings):

    url: HttpUrl
    token: SecretStr

    # json_logging: bool
    # ssl_verify: bool


class _ConnectorConfig(BaseSettings):
    # TODO : Enforce typing (Literal, etc.)

    id: str
    name: str
    type: str
    scope: list[str]

    # log_level: str
    # duration_period: datetime.timedelta
    # auto: bool
    # expose_metrics: bool
    # metrics_port: int
    # only_contextual: bool
    # run_and_terminate: bool
    # validate_before_import: bool
    # queue_protocol: str
    # queue_threshold: int

    # listen_protocol: str
    # listen_protocol_api_port: int
    # listen_protocol_api_path: str
    # listen_protocol_api_ssl: bool
    # listen_protocol_api_uri: str

    # live_stream_id: str
    # live_stream_listen_delete: bool
    # live_stream_no_dependencies: bool
    # live_stream_with_inferences: bool
    # live_stream_recover_iso_date: datetime.datetime
    # live_stream_start_timestamp: datetime.datetime

    # send_to_queue: bool
    # send_to_directory: bool
    # send_to_directory_path: str
    # send_to_directory_retention: int


class BaseConfig(_BaseSettings):
    opencti: _OpenCTIConfig
    connector: _ConnectorConfig
