from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr, model_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Team T5 External Import Connector",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(days=1),
    )


class TeamT5Config(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the TeamT5 connector.
    """

    api_base_url: str = Field(
        description="Base URL of the TeamT5 ThreatVision API.",
        default="https://api.threatvision.org/",
    )
    # OAuth 2.0 client credentials — recommended authentication path. When
    # both ``client_id`` and ``client_secret`` are set the connector will
    # exchange them for a Bearer token against ``<api_base_url>/oauth/token``
    # and refresh it automatically.
    client_id: SecretStr | None = Field(
        description="OAuth 2.0 client ID. Requires `client_secret` to also be set.",
        default=None,
    )
    client_secret: SecretStr | None = Field(
        description="OAuth 2.0 client secret. Requires `client_id` to also be set.",
        default=None,
    )
    # Deprecated: pre-obtained static Bearer token. Kept for backwards
    # compatibility; new deployments should use the OAuth flow above.
    api_key: SecretStr | None = Field(
        description="Deprecated. Static API key for authentication to TeamT5's ThreatVision Platform. Prefer `client_id` + `client_secret`.",
        default=None,
    )
    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP level of the imported entities.",
        default="clear",
    )
    first_run_retrieval_timestamp: int = Field(
        description="Unix timestamp indicating the earliest point in time from which intel should be retrieved from the TeamT5 API. Used only on the connector's first run to import previously published data. Defaults to 0 (i.e. the full TeamT5 catalogue) so existing deployments that never set this variable continue to start.",
        default=0,
    )

    @staticmethod
    def _has_secret_value(secret: SecretStr | None) -> bool:
        """Return True only when ``secret`` carries a non-empty value.

        Pydantic's ``SecretStr | None`` Field accepts an empty string as a
        valid populated value (``SecretStr("")`` is not None), but in
        practice an unset env var on a Compose deployment frequently
        materialises as ``""`` rather than ``None``. The earlier
        ``is not None`` check let those empties through validation, and
        ``Teamt5Client.__init__`` then resolved both branches to falsy
        values and silently fell through to a no-auth client. Treat
        empty / whitespace-only secrets as missing here so the operator
        sees the actionable startup error this validator is supposed to
        produce, instead of a silent no-auth start that fails at the
        first API call.
        """
        if secret is None:
            return False
        try:
            value = secret.get_secret_value()
        except AttributeError:
            return False
        return bool(value) and bool(str(value).strip())

    @model_validator(mode="after")
    def _require_some_authentication(self) -> "TeamT5Config":
        has_api_key = self._has_secret_value(self.api_key)
        has_oauth = self._has_secret_value(self.client_id) and self._has_secret_value(
            self.client_secret
        )
        if not (has_api_key or has_oauth):
            raise ValueError(
                "TeamT5 connector requires either `api_key` OR both "
                "`client_id` and `client_secret` to be configured "
                "(empty / whitespace-only values are treated as "
                "unset)."
            )
        return self


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `TeamT5Config`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )

    teamt5: TeamT5Config = Field(
        default_factory=TeamT5Config,
    )
