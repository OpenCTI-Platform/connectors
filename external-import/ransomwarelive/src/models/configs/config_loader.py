import warnings
from datetime import timedelta
from pathlib import Path
from typing import Any

from connectors_sdk.core.pydantic import ListFromString
from models.configs.base_settings import ConfigBaseSettings
from models.configs.connector_configs import _ConfigLoaderConnector, _ConfigLoaderOCTI
from pydantic import Field, model_validator
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
        default="Ransomware Connector",
        description="Name of the connector.",
    )
    scope: ListFromString = Field(
        default=[
            "identity",
            "attack-pattern",
            "course-of-action",
            "intrusion-set",
            "malware",
            "tool",
            "report",
        ],
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

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `CONNECTOR_RUN_EVERY` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})

        if run_every := connector_data.pop("run_every", None):
            warnings.warn(
                "Env var 'CONNECTOR_RUN_EVERY' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
            )
            unit_run_every = run_every[-1:]
            if unit_run_every == "d":
                connector_data["duration_period"] = timedelta(days=int(run_every[:-1]))
            elif unit_run_every == "h":
                connector_data["duration_period"] = timedelta(hours=int(run_every[:-1]))
            elif unit_run_every == "m":
                connector_data["duration_period"] = timedelta(
                    minutes=int(run_every[:-1])
                )
            elif unit_run_every == "s":
                connector_data["duration_period"] = timedelta(
                    seconds=int(run_every[:-1])
                )
            else:
                raise ValueError(f"Invalid value for CONNECTOR_RUN_EVERY: {run_every}")

        return data

    def model_dump_pycti(self) -> dict[str, Any]:
        return self.model_dump(mode="json", context={"mode": "pycti"})
