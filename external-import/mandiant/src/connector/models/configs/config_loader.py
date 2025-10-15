from pathlib import Path
from typing import Any

from connector.models.configs import (
    ConfigBaseSettings,
    ConfigLoaderConnectorExtra,
    ConfigLoaderMandiant,
    ConfigLoaderOCTI,
)
from connectors_sdk.core.pydantic import ListFromString
from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    YamlConfigSettingsSource,
)


class ConfigLoaderConnector(ConfigLoaderConnectorExtra):
    """A concrete implementation of ConfigLoaderConnector defining default connector configuration values."""

    id: str = Field(
        default="mandiant--7736893c-8681-4884-89bd-458bcb3a5060",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        default="Mandiant",
        description="Name of the connector.",
    )
    scope: ListFromString = Field(
        default=["mandiant"],
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )


class ConfigLoader(ConfigBaseSettings):
    """Interface for loading global configuration settings."""

    opencti: ConfigLoaderOCTI = Field(
        default_factory=ConfigLoaderOCTI,
        description="OpenCTI configurations.",
    )
    connector: ConfigLoaderConnector = Field(
        default_factory=ConfigLoaderConnector,
        description="Connector configurations.",
    )
    mandiant: ConfigLoaderMandiant = Field(
        default_factory=ConfigLoaderMandiant,
        description="Mandiant configurations.",
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
