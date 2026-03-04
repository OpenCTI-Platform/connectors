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
        description="Hunt.io API endpoint URL for the C2 threat intelligence feeds",
        default=HttpUrl("https://api.hunt.io/v1/feeds/c2"),
    )
    api_key: SecretStr = Field(
        description=(
            "Authentication key for accessing the Hunt.io API. "
            "Obtain this from your Hunt.io account settings"
        )
    )
    tlp_level: Literal["white", "clear", "green", "amber", "amber+strict", "red"] = (
        Field(
            description=(
                "Traffic Light Protocol (TLP) marking level to apply to imported data, "
                "controlling information sharing restrictions"
            ),
            default="amber",
        )
    )


class ExternalImportConfig(BaseExternalImportConnectorConfig):
    name: str = Field(
        description="Display name for this connector instance in the OpenCTI platform",
        default="Hunt IO",
    )
    scope: ListFromString = Field(
        description=(
            "Entity types or categories this connector will handle. "
            "Used for filtering and organization within OpenCTI"
        ),
        default=["Hunt IO"],
    )
    id: str = Field(
        description=(
            "Unique identifier (UUID v4) for this connector instance in OpenCTI. "
            "Change this if running multiple instances"
        ),
        default="144c83b7-e267-4fc5-b77d-babd502dc56e",
    )

    duration_period: timedelta = Field(
        description=(
            "Time interval between consecutive data imports from Hunt.io. "
            "Controls how frequently the connector runs"
        ),
        default=timedelta(hours=24),
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
