from pathlib import Path
from typing import Any

from connectors_sdk.core.pydantic import ListFromString
from models.configs.base_settings import ConfigBaseSettings
from models.configs.connector_configs import _ConfigLoaderConnector, _ConfigLoaderOCTI
from models.configs.recorded_future_configs import (
    _ConfigLoaderAlert,
    _ConfigLoaderPlaybookAlert,
    _ConfigLoaderRecordedFuture,
)
from pydantic import AliasChoices, Field
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
        default="recorded-future--1234abcd-1234-1234-1234-abcd12345678",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        default="Recorded Future",
        description="Name of the connector.",
    )
    scope: ListFromString = Field(
        default=[
            "ipv4-addr",
            "ipv6-addr",
            "vulnerability",
            "domain",
            "url",
            "file-sha256",
            "file-md5",
            "file-sha1",
        ],
        description=(
            "The scope or type of data the connector is importing, "
            "either a MIME type or Stix Object (for information only)."
        ),
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
    recorded_future: _ConfigLoaderRecordedFuture = Field(
        default_factory=_ConfigLoaderRecordedFuture,
        description="Recorded Future configurations.",
        validation_alias=AliasChoices("rf", "recorded_future"),
    )
    alert: _ConfigLoaderAlert = Field(
        default_factory=_ConfigLoaderAlert,
        description="Alert configurations.",
    )
    playbook_alert: _ConfigLoaderPlaybookAlert = Field(
        default_factory=_ConfigLoaderPlaybookAlert,
        description="Playbook Alert configurations.",
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
        env_path = Path(__file__).parents[2] / ".env"
        yaml_path = Path(__file__).parents[2] / "config.yml"

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
