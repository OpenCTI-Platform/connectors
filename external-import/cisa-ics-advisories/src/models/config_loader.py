from pathlib import Path
from typing import Any

from connectors_sdk import ListFromString
from models.configs import (
    ConfigBaseSettings,
    _ConfigLoaderCISAICS,
    _ConfigLoaderConnector,
    _ConfigLoaderOCTI,
)
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
        default="cisaicsadvisories--6f6e4a3c-1c8f-4c9a-9b7e-2d7a2f6c9a01",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        default="CISA ICS Advisories",
        description="Name of the connector.",
    )
    scope: ListFromString = Field(
        default=["cisa-ics-advisories"],
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
    cisa_ics: _ConfigLoaderCISAICS = Field(
        default_factory=_ConfigLoaderCISAICS,
        description="CISA ICS Advisories configurations.",
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
