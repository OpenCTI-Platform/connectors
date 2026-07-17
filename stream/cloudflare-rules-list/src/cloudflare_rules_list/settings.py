"""Pydantic-settings configuration models for the connector.

Configuration is loaded (in precedence order) from environment variables, then
``config.yml`` or ``.env`` next to the connector, then field defaults -- the
same precedence the legacy ``get_config_variable`` helper used.

Environment variable mapping (nested by the first underscore):

    OPENCTI_URL                -> opencti.url
    OPENCTI_TOKEN              -> opencti.token
    CONNECTOR_ID               -> connector.id
    CONNECTOR_NAME             -> connector.name
    CONNECTOR_SCOPE            -> connector.scope
    CONNECTOR_LIVE_STREAM_ID   -> connector.live_stream_id
    CONNECTOR_SYNC_INTERVAL    -> connector.sync_interval
    CLOUDFLARE_ACCOUNT_ID      -> cloudflare.account_id
    CLOUDFLARE_API_TOKEN       -> cloudflare.api_token
    CLOUDFLARE_LIST_ID         -> cloudflare.list_id
"""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class _StreamConnectorConfig(BaseStreamConnectorConfig):
    """Stream connector namespace (``connector.*``).

    Inherits ``id``, ``type`` (forced to ``STREAM``), ``log_level``,
    ``live_stream_id``, ``live_stream_listen_delete`` and
    ``live_stream_no_dependencies`` from the SDK base class.
    """

    name: str = Field(
        default="Cloudflare Rules List",
        description="The name of the connector as shown in OpenCTI.",
    )
    scope: ListFromString = Field(
        default=["cloudflare"],
        description="Connector scope (comma-separated).",
    )
    sync_interval: str = Field(
        default="1h",
        description=(
            "Minimum interval between snapshot uploads to Cloudflare. "
            "Accepts a duration like '30m', '1h', '1h30m', or a bare number "
            "of seconds."
        ),
    )


class CloudflareConfig(BaseConfigModel):
    """Cloudflare namespace (``cloudflare.*``)."""

    account_id: str = Field(
        description="Cloudflare account ID that owns the Rules List.",
    )
    api_token: SecretStr = Field(
        description=(
            "Cloudflare API token with the 'Account > Account Filter Lists > "
            "Edit' permission."
        ),
    )
    list_id: str = Field(
        description="ID of the existing Cloudflare Rules List (IP kind) to sync into.",
    )
    api_base_url: str = Field(
        default="https://api.cloudflare.com/client/v4",
        description=(
            "Base URL of the Cloudflare API. Override only for testing against a "
            "mock server or a Cloudflare-compatible gateway."
        ),
    )


class ConnectorSettings(BaseConnectorSettings):
    """Top-level settings.

    ``opencti`` (url, token) is provided by :class:`BaseConnectorSettings`.
    """

    connector: _StreamConnectorConfig = Field(default_factory=_StreamConnectorConfig)
    cloudflare: CloudflareConfig = Field(default_factory=CloudflareConfig)
