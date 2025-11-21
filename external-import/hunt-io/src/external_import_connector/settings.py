import warnings
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, model_validator


class ConnectorHuntIoConfig(BaseConfigModel):
    api_base_url: str = Field(description="API base URL", default_factory=str)
    api_key: str = Field(description="API key", default_factory=str)
    tlp_level: Literal["white", "clear", "green", "amber", "amber+strict", "red"] = (
        Field(description="TLP level", default="amber")
    )


class ConfigLoader(BaseConnectorSettings):
    """Handles connector configuration loading and validation."""

    connector: BaseExternalImportConnectorConfig = Field(
        default_factory=BaseExternalImportConnectorConfig
    )
    hunt_io: ConnectorHuntIoConfig = Field(
        default_factory=ConnectorHuntIoConfig,
        validation_alias="connector_hunt_ui",
    )

    @model_validator(mode="after")
    @classmethod
    def migrate_deprecated_connector_hunt_ui(cls, data) -> dict:
        """
        Env vars prefixed by `CONNECTOR_HUNT_UI` is deprecated.
        This is a workaround to keep the old config working while we migrate to `HUNT_IO` prefix.
        """
        if (
            "hunt_ui_api_key" in data.connector.model_fields_set
            or "hunt_ui_api_base_url" in data.connector.model_fields_set
        ):
            warnings.warn(
                message="Env vars prefixed by 'CONNECTOR_HUNT_UI' is deprecated. Use 'HUNT_IO' prefix instead.",
                category=DeprecationWarning,
            )
        return data
