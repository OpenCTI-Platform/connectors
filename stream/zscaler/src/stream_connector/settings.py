from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr

LEGACY_AUTH_DEPRECATION = (
    "The legacy Zscaler API authentication is no longer supported. "
    "Use 'client_id', 'client_secret' and 'vanity_domain' (Zscaler OneAPI) instead."
)


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """Connector-section configuration for the Zscaler STREAM connector.

    Mirrors the connector variables previously loaded via ``get_config_variable``.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Zscaler",
    )
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="5ee2f825-634f-4f87-b305-15f97f6f7678",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["domain-name"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="info",
    )


class ZscalerConfig(BaseConfigModel):
    """Zscaler-specific configuration (Zscaler OneAPI, authenticated through ZIdentity)."""

    client_id: str = Field(
        description="Client ID of the ZIdentity API client used to authenticate to Zscaler OneAPI.",
    )
    client_secret: SecretStr = Field(
        description="Client secret of the ZIdentity API client.",
    )
    vanity_domain: str = Field(
        description=(
            "ZIdentity vanity domain of the organization, i.e. the `<vanity_domain>` "
            "part of `https://<vanity_domain>.zslogin.net`."
        ),
    )
    cloud: str | None = Field(
        description=(
            "Zscaler cloud to target (for example `beta`). "
            "Leave empty to use the production cloud (`api.zsapi.net`)."
        ),
        default=None,
    )
    blacklist_name: str = Field(
        description=(
            "ID of the Zscaler URL category used as blacklist "
            "(for example `CUSTOM_01`), not its display name."
        ),
        default="BLACK_LIST_DYNDNS",
    )
    ssl_verify: bool = Field(
        description="Whether to verify SSL certificates when connecting to the Zscaler API.",
        default=True,
    )
    username: str | None = DeprecatedField(
        deprecated=LEGACY_AUTH_DEPRECATION,
        description="Zscaler account username (legacy API, no longer used).",
    )
    password: SecretStr | None = DeprecatedField(
        deprecated=LEGACY_AUTH_DEPRECATION,
        description="Zscaler account password (legacy API, no longer used).",
    )
    api_key: SecretStr | None = DeprecatedField(
        deprecated=LEGACY_AUTH_DEPRECATION,
        description="Zscaler API key (legacy API, no longer used).",
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the Zscaler STREAM connector."""

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    zscaler: ZscalerConfig = Field(default_factory=ZscalerConfig)
