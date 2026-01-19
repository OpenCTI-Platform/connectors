from pathlib import Path
from typing import Any

from connectors_sdk import ListFromString
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
from src.connector.models.configs.virustotal_downloader_configs import (
    _ConfigLoaderVirusTotalDownloader,
)


class ConfigLoaderConnector(_ConfigLoaderConnector):
    """A concrete implementation of _ConfigLoaderConnector defining default connector configuration values."""

    id: str = Field(
        default="virustotaldownloader--0c1ac73d-f173-4349-9580-322c22fa7768",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        default="VirusTotal Downloader",
        description="Name of the connector.",
    )
    scope: ListFromString = Field(
        default=["StixFile"],
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
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
    virustotal_downloader: _ConfigLoaderVirusTotalDownloader = Field(
        default_factory=_ConfigLoaderVirusTotalDownloader,
        description="VirusTotal Downloader configurations.",
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

    def model_dump_pycti(self) -> dict[str, Any]:
        return self.model_dump(mode="json", context={"mode": "pycti"})
