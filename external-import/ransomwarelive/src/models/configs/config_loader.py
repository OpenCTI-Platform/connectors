from pathlib import Path

from models.configs.base_settings import ConfigBaseSettings
from models.configs.connector_configs import (
    _ConfigLoaderConnector,
    _ConfigLoaderOCTI,
)
from models.configs.ransomwarelive_configs import _ConfigLoaderRansomwareLive
from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    YamlConfigSettingsSource,
)


class ConfigLoaderConnector(_ConfigLoaderConnector):
    """A concrete implementation of _ConfigLoaderConnector defining default connector configuration values."""

    id: str = Field(
        default="ransomwarelive--51402e18-8b2a-4012-bec2-adaa2f41bd59",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        default="Ransomware Live",
        description="Name of the connector.",
    )
    scope: str = Field(
        default="identity,attack-pattern,course-of-action,intrusion-set,malware,tool,report",
        description="The scope defines the set of entity types that the enrichment connector is allowed to process.",
    )


class ConfigLoader(ConfigBaseSettings):
    """Interface for loading global configuration settings."""

    opencti: _ConfigLoaderOCTI = Field(
        default_factory=_ConfigLoaderOCTI,
        description="OpenCTI configurations.",
    )
    connector: ConfigLoaderConnector = Field(
        default_factory=ConfigLoaderConnector,
        description="Connector configurations.",
    )
    ransomwarelive: _ConfigLoaderRansomwareLive = Field(
        default_factory=_ConfigLoaderRansomwareLive,
        description="Ransomware Live configurations.",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource]:
        env_path = Path(__file__).parents[3] / ".env"
        yaml_path = Path(__file__).parents[3] / "config.yml"

        if env_path.exists():
            return (
                DotEnvSettingsSource(
                    settings_cls,
                    env_file=env_path,
                    env_ignore_empty=True,
                    env_file_encoding="utf-8",
                ),
            )
        elif yaml_path.exists():
            return (
                YamlConfigSettingsSource(
                    settings_cls,
                    yaml_file=yaml_path,
                    yaml_file_encoding="utf-8",
                ),
            )
        else:
            return (
                EnvSettingsSource(
                    settings_cls,
                    env_ignore_empty=True,
                ),
            )
