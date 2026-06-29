from pathlib import Path
from typing import Any

from connectors_sdk import ListFromString
from pydantic import AliasChoices, Field, HttpUrl, SecretStr
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
from src.connector.models.configs.sekoia_configs import _ConfigLoaderSekoia


class ConfigLoaderConnector(_ConfigLoaderConnector):
    """A concrete implementation of _ConfigLoaderConnector defining default connector configuration values."""

    id: str = Field(
        default="sekoia--8c694370-34bb-4f5d-a934-856779a473a0",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        default="SEKOIA.IO",
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
            "location",
            "vulnerability",
            "indicator",
            "campaign",
            "infrastructure",
            "relationship",
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
    sekoia: _ConfigLoaderSekoia = Field(
        default_factory=_ConfigLoaderSekoia,
        description="Sekoia configurations.",
    )

    # Detached opencti-ng mode (optional). When both are set, the connector
    # ingests directly into opencti-ng over a JWT (no OpenCTI worker/queue); the
    # write tenant and connector id are read from the JWT, run state lives
    # server-side.
    opencti_ng_url: HttpUrl | None = Field(
        default=None,
        validation_alias=AliasChoices("opencti_ng_url", "OPENCTI_NG_URL"),
        description="opencti-ng base URL for detached mode (set with opencti_ng_jwt).",
    )
    opencti_ng_jwt: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("opencti_ng_jwt", "OPENCTI_NG_JWT"),
        description="Long-lived connector JWT for opencti-ng detached mode.",
    )

    @property
    def opencti_ng_enabled(self) -> bool:
        """Whether detached opencti-ng mode is configured."""
        return self.opencti_ng_url is not None and self.opencti_ng_jwt is not None

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
