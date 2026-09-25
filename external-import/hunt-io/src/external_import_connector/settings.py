from datetime import timedelta
from typing import Annotated, Any, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import (
    BeforeValidator,
    Field,
    HttpUrl,
    SecretStr,
    SkipValidation,
    model_validator,
)

DEFAULT_API_VERSION = "v2"


def _normalize_api_version(value: Any) -> Any:
    """Normalize an api_version coming from an environment variable.

    A compose passthrough such as `HUNT_IO_API_VERSION=${HUNT_IO_API_VERSION}` sets the
    variable to an empty string when it is not defined, which would otherwise fail
    validation instead of falling back to the default. Case is normalized too, since
    environment variables are commonly written in upper case.
    """
    if isinstance(value, str):
        normalized = value.strip().lower()
        return normalized or DEFAULT_API_VERSION
    return value


ApiVersion = Annotated[
    Literal["v2", "v3"],
    BeforeValidator(_normalize_api_version),
]


class HuntIoConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        description="Hunt.io API endpoint URL for the C2 threat intelligence feeds",
        default=HttpUrl("https://api.hunt.io/v1/feeds/c2"),
    )
    api_version: ApiVersion = Field(
        description=(
            "Which Hunt.io C2 feed API to target. 'v2' authenticates with a 'token' "
            "header against https://api.hunt.io/v1/feeds/c2. 'v3' authenticates with "
            "'Authorization: Bearer' against https://a.hunt.io/feeds/c2 and requires an "
            "'ak_'-prefixed key. The two APIs are mutually exclusive: set api_base_url "
            "to match the version, as changing one without the other returns HTTP 401"
        ),
        default=DEFAULT_API_VERSION,
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

    @model_validator(mode="after")
    def _validate_api_key_matches_version(self) -> "HuntIoConfig":
        """Fail fast when a V3 key is malformed.

        The V3 API rejects any key without an `ak_` prefix using the same opaque 401 it
        returns for a missing key, which makes a typo indistinguishable from an
        entitlement problem at runtime. V2 has no documented prefix rule, so this check
        is deliberately scoped to V3 only.
        """
        if self.api_version == "v3" and not self.api_key.get_secret_value().startswith(
            "ak_"
        ):
            raise ValueError(
                "api_version 'v3' requires an 'ak_'-prefixed API key; the V3 API "
                "rejects other keys with an HTTP 401 indistinguishable from a "
                "missing key"
            )
        return self


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
