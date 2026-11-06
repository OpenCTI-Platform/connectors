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
    _ConfigLoaderCVE,
    _ConfigLoaderOCTI,
)


class ConfigLoaderConnector(_ConfigLoaderConnector):
    """A concrete implementation of _ConfigLoaderConnector defining default connector configuration values."""

    id: str = Field(
        default="cve--e0c380ad-6665-4f2e-8558-5d2610e5abcf",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        default="NIST NVD CVE Enrichment",
        description="Name of the connector.",
    )
    scope: ListFromString = Field(
        default=[
            "Report",
            "Grouping",
            "Note",
            "Observed-Data",
            "Opinion",
            "Case-Incident",
            "Case-Rfi",
            "Case-Rft",
            "Task",
            "Feedback",
            "Incident",
            "Vulnerability",
        ],
        description="The scope of STIX entities the connector enriches (Containers and Vulnerability).",
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
    cve: _ConfigLoaderCVE = Field(
        default_factory=_ConfigLoaderCVE,
        description="CVE configurations.",
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
        env_path = Path(__file__).parents[2] / ".env"
        yaml_path = Path(__file__).parents[2] / "config.yml"

        return (
            init_settings,
            EnvSettingsSource(settings_cls, env_ignore_empty=True),
            DotEnvSettingsSource(
                settings_cls,
                env_file=env_path,
                env_ignore_empty=True,
                env_file_encoding="utf-8",
            ),
            YamlConfigSettingsSource(
                settings_cls,
                yaml_file=yaml_path,
                yaml_file_encoding="utf-8",
            ),
            file_secret_settings,
        )

    def model_dump_pycti(self) -> dict[str, Any]:
        data = self.model_dump(mode="json", context={"mode": "pycti"})
        if isinstance(self.opencti.token, object) and hasattr(
            self.opencti.token, "get_secret_value"
        ):
            data.setdefault("opencti", {})[
                "token"
            ] = self.opencti.token.get_secret_value()
        scope_val = data.get("connector", {}).get("scope")
        if isinstance(scope_val, list):
            data["connector"]["scope"] = ",".join(str(s) for s in scope_val)
        return data
