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
from src.models.configs import (
    ConfigBaseSettings,
    _ConfigLoaderConnector,
    _ConfigLoaderMitre,
    _ConfigLoaderOCTI,
    _ConfigLoaderOCTING,
)


class ConfigLoaderConnector(_ConfigLoaderConnector):
    """A concrete implementation of _ConfigLoaderConnector defining default connector configuration values."""

    id: str = Field(
        default="mitre--c9dacf68-b0e6-476d-a24f-4269b1b9cd25",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        default="MITRE ATT&CK",
        description="Name of the connector.",
    )
    scope: ListFromString = Field(
        default=[
            "tool",
            "report",
            "malware",
            "identity",
            "campaign",
            "intrusion-set",
            "attack-pattern",
            "course-of-action",
            "x-mitre-data-source",
            "x-mitre-data-component",
            "x-mitre-matrix",
            "x-mitre-tactic",
            "x-mitre-collection",
        ],
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )


class ConfigLoader(ConfigBaseSettings):
    """Interface for loading global configuration settings."""

    # Optional: legacy OpenCTI (worker/queue) mode. Unset in detached opencti-ng
    # mode. Optional so the connector starts with only an `opencti-ng` block.
    opencti: _ConfigLoaderOCTI | None = Field(
        default=None,
        description="OpenCTI configurations (legacy worker mode).",
    )
    # Optional: detached opencti-ng mode. When set, the connector ingests
    # directly into opencti-ng with a JWT and keeps state in a local file.
    opencti_ng: _ConfigLoaderOCTING | None = Field(
        default=None,
        alias="opencti-ng",
        description="opencti-ng configurations (detached, JWT-authenticated).",
    )
    connector: ConfigLoaderConnector = Field(
        default_factory=ConfigLoaderConnector,
        description="Connector configurations.",
    )
    mitre: _ConfigLoaderMitre = Field(
        default_factory=_ConfigLoaderMitre,
        description="Mitre configurations.",
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
