from typing import Literal, Self

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, model_validator

LEGACY_AUTH_DEPRECATION = (
    "The legacy Zscaler API authentication is deprecated and stops working when "
    "Zscaler removes it. Use 'client_id', 'client_secret' and 'vanity_domain' "
    "(Zscaler OneAPI) instead."
)
LEGACY_CREDENTIAL_FIELDS = ("username", "password", "api_key")
ONEAPI_CREDENTIAL_FIELDS = ("client_id", "client_secret", "vanity_domain")


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
    """Zscaler-specific configuration.

    The connector uses Zscaler OneAPI (authenticated through ZIdentity). The legacy
    API credentials still work while Zscaler supports them, but are deprecated.
    """

    client_id: str | None = Field(
        description=(
            "Client ID of the ZIdentity API client used to authenticate to Zscaler "
            "OneAPI. Required unless the deprecated legacy credentials are used."
        ),
        default=None,
    )
    client_secret: SecretStr | None = Field(
        description=(
            "Client secret of the ZIdentity API client. "
            "Required unless the deprecated legacy credentials are used."
        ),
        default=None,
    )
    vanity_domain: str | None = Field(
        description=(
            "ZIdentity vanity domain of the organization, i.e. the `<vanity_domain>` "
            "part of `https://<vanity_domain>.zslogin.net`. "
            "Required unless the deprecated legacy credentials are used."
        ),
        default=None,
    )
    cloud: str | None = Field(
        description=(
            "Zscaler cloud to target with OneAPI (for example `beta`). "
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
        description="Zscaler account username (deprecated legacy API authentication).",
    )
    password: SecretStr | None = DeprecatedField(
        deprecated=LEGACY_AUTH_DEPRECATION,
        description="Zscaler account password (deprecated legacy API authentication).",
    )
    api_key: SecretStr | None = DeprecatedField(
        deprecated=LEGACY_AUTH_DEPRECATION,
        description="Zscaler API key (deprecated legacy API authentication).",
    )
    api_base_url: HttpUrl | None = DeprecatedField(
        deprecated=LEGACY_AUTH_DEPRECATION,
        description=(
            "Base URL of the legacy Zscaler ZIA API, without the `/api/v1` path "
            "(default: `https://zsapi.zscalertwo.net`). Only used with the "
            "deprecated legacy credentials; use 'cloud' with OneAPI."
        ),
    )

    @property
    def use_legacy_api(self) -> bool:
        """Whether the deprecated legacy API credentials are used instead of OneAPI."""
        return not any(self._raw(field) for field in ONEAPI_CREDENTIAL_FIELDS)

    def _raw(self, field: str) -> object:
        # Read deprecated fields without triggering pydantic's deprecation warning
        return self.__dict__.get(field)

    @model_validator(mode="after")
    def _check_credentials(self) -> Self:
        """Require complete OneAPI credentials, or complete legacy ones."""
        if self.use_legacy_api:
            missing = [f for f in LEGACY_CREDENTIAL_FIELDS if not self._raw(f)]
            if not missing:
                return self
            if len(missing) == len(LEGACY_CREDENTIAL_FIELDS):
                raise ValueError(
                    "Zscaler credentials are missing: set 'client_id', "
                    "'client_secret' and 'vanity_domain' (Zscaler OneAPI)."
                )
            raise ValueError(
                "Incomplete deprecated legacy Zscaler credentials "
                f"(missing: {', '.join(missing)}). Prefer the Zscaler OneAPI "
                "credentials 'client_id', 'client_secret' and 'vanity_domain'."
            )

        missing = [f for f in ONEAPI_CREDENTIAL_FIELDS if not self._raw(f)]
        if missing:
            raise ValueError(
                "Incomplete Zscaler OneAPI credentials "
                f"(missing: {', '.join(missing)})."
            )
        return self


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the Zscaler STREAM connector."""

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    zscaler: ZscalerConfig = Field(default_factory=ZscalerConfig)
