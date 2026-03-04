from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, SkipValidation


class HuntIoConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        description="API base URL", default=HttpUrl("https://api.hunt.io/v1/feeds/c2")
    )
    api_key: SecretStr = Field(description="API key")
    tlp_level: Literal["white", "clear", "green", "amber", "amber+strict", "red"] = (
        Field(description="TLP level", default="amber")
    )


class ExternalImportConfig(BaseExternalImportConnectorConfig):
    name: str = Field(description="Connector name", default="Hunt IO")
    scope: ListFromString = Field(description="Connector scope", default=["Hunt IO"])
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="144c83b7-e267-4fc5-b77d-babd502dc56e",
    )

    duration_period: timedelta = Field(
        description="Duration period", default=timedelta(hours=24)
    )
    hunt_ui: SkipValidation[HuntIoConfig] = DeprecatedField(  # type: ignore[assignment]
        deprecated=(
            "Use 'hunt_io' prefix instead of 'hunt_ui'. This field is "
            "kept for backward compatibility and will be removed in a future release."
        ),
        new_namespace="hunt_io",
    )


class ConnectorSettings(BaseConnectorSettings):
    """Handles connector configuration loading and validation."""

    connector: ExternalImportConfig = Field(default_factory=ExternalImportConfig)
    # Legacy code used: get_config_variable(CONNECTOR_HUNT_UI, ["connector_hunt_io", ...]...)
    connector_hunt_ui: SkipValidation[HuntIoConfig] = DeprecatedField(  # type: ignore[assignment]
        deprecated=(
            "Env vars prefixed by 'CONNECTOR_HUNT_UI' is deprecated. Use 'HUNT_IO' "
            "prefix instead. This field is "
            "kept for backward compatibility and will be removed in a future release."
        ),
        new_namespace="hunt_io",
    )
    connector_hunt_io: SkipValidation[HuntIoConfig] = DeprecatedField(  # type: ignore[assignment]
        deprecated=(
            "Use 'hunt_io' prefix instead of 'connector_hunt_io'. This field is "
            "kept for backward compatibility and will be removed in a future release."
        ),
        new_namespace="hunt_io",
    )
    hunt_io: HuntIoConfig = Field(default_factory=HuntIoConfig)
