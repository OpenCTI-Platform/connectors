import warnings
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, model_validator


class ConnectorHuntIoConfig(BaseConfigModel):
    api_base_url: str = Field(description="API base URL", default_factory=str)
    api_key: str = Field(description="API key", default_factory=str)
    tlp_level: Literal["white", "clear", "green", "amber", "amber+strict", "red"] = (
        Field(description="TLP level", default="amber")
    )


class ConnectorSettings(BaseExternalImportConnectorConfig):
    name: str = Field(description="Connector name", default="Hunt IO")
    scope: ListFromString = Field(description="Connector scope", default=["Hunt IO"])


class ConfigLoader(BaseConnectorSettings):
    """Handles connector configuration loading and validation."""

    connector: ConnectorSettings = Field(default_factory=ConnectorSettings)
    hunt_io: ConnectorHuntIoConfig = Field(
        default_factory=ConnectorHuntIoConfig,
    )

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_connector_hunt_ui(cls, data) -> dict:
        """
        Env vars prefixed by `CONNECTOR_HUNT_UI` is deprecated.
        This is a workaround to keep the old config working while we migrate to `HUNT_IO` prefix.
        """
        for key, value in data.get("connector", {}).items():
            if key.startswith("hunt_ui_"):
                hunt_io = data.get("hunt_io", {})
                hunt_io[key[8:]] = value
                data["hunt_io"] = hunt_io
                warnings.warn(
                    message="Env vars prefixed by 'CONNECTOR_HUNT_UI' is deprecated. Use 'HUNT_IO' prefix instead.",
                    category=DeprecationWarning,
                )

        return data
