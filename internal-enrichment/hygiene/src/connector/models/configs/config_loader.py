from pathlib import Path

from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    YamlConfigSettingsSource,
)
from src.connector.models.configs.base_settings import ConfigBaseSettings
from src.connector.models.configs.connector_configs import (
    _ConfigLoaderConnector,
    _ConfigLoaderOCTI,
)
from src.connector.models.configs.hygiene_configs import _ConfigLoaderHygiene


class ConfigLoaderConnector(_ConfigLoaderConnector):
    """A concrete implementation of _ConfigLoaderConnector defining default connector configuration values."""

    id: str = Field(
        default="hygiene--c5079b30-4c65-45f0-b02c-eb51a3794b82",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        default="Hygiene",
        description="Name of the connector.",
    )
    scope: str = Field(
        default="IPv4-Addr,IPv6-Addr,Artifact,Domain-Name,StixFile,Indicator",
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
    hygiene: _ConfigLoaderHygiene = Field(
        default_factory=_ConfigLoaderHygiene,
        description="Hygiene configurations.",
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
