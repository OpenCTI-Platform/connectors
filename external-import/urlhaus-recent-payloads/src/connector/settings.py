import warnings
from datetime import timedelta
from typing import ClassVar

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from connectors_sdk.settings.deprecations import DeprecatedField
from pydantic import ConfigDict, Field, SecretStr, model_validator
from spamhaus_client import AbuseChAuthConfigMixin


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="8534e9c8-3997-4a83-a263-52588ce9e671",
    )
    name: str = Field(
        description="The name of the connector.",
        default="UrlhausRecentPayloads",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(seconds=300),
    )


class UrlhausRecentPayloadsConfig(AbuseChAuthConfigMixin, BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `UrlhausRecentPayloadsConnector`.
    """

    api_url: str = Field(
        description="The URL of the URLhaus API.",
        default="https://urlhaus-api.abuse.ch/v1/",
    )
    auth_env_prefix: ClassVar[str] = "URLHAUS_RECENT_PAYLOADS"

    api_key: SecretStr | None = DeprecatedField(
        deprecated="Use 'auth_key' (URLHAUS_RECENT_PAYLOADS_AUTH_KEY) instead.",
        new_namespaced_var="auth_key",
        description="Deprecated alias of `auth_key`.",
        default=None,
    )
    import_start_date: DatetimeFromIsoString = Field(
        description=(
            "Spamhaus commercial API only: how far back to fetch payloads on the first "
            "run, when the connector has no checkpoint yet. ISO-8601 datetime or "
            "duration (e.g. `P1D`)."
        ),
        default="P1D",  # type: ignore[assignment]
    )
    include_filetypes: ListFromString = Field(
        description="Only download files if file type matches. (Comma separated)",
        default=[],
    )
    include_signatures: ListFromString = Field(
        description="Only download files if match these Yara rules. (Comma separated)",
        default=[],
    )
    skip_unknown_filetypes: bool = Field(
        description="Skip files with an unknown file type.", default=True
    )
    skip_null_signature: bool = Field(
        description="Skip files that didn't match known Yara rules.", default=True
    )
    labels: ListFromString = Field(
        description="Labels to apply to uploaded Artifacts. (Comma separated)",
        default=["urlhaus"],
    )
    labels_color: str = Field(
        description="Color for labels specified above.", default="#54483b"
    )
    signature_label_color: str = Field(
        description="Color for Yara rule match label.", default="#0059f7"
    )
    filetype_label_color: str = Field(
        description="Color to use for filetype label.", default="#54483b"
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `UrlhausRecentPayloadsConfig`.
    """

    # Validation errors would otherwise echo the raw input, secrets included.
    model_config = ConfigDict(hide_input_in_errors=True)

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    urlhaus_recent_payloads: UrlhausRecentPayloadsConfig = Field(
        default_factory=UrlhausRecentPayloadsConfig
    )

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_cooldown_seconds(cls, data: dict) -> dict:
        """
        Env var `URLHAUS_RECENT_PAYLOADS_COOLDOWN_SECONDS` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        urlhaus_data: dict = data.get("urlhaus_recent_payloads", {})
        if cooldown_seconds := urlhaus_data.pop("cooldown_seconds", None):
            if connector_data.get("duration_period") is not None:
                warnings.warn(
                    "Both 'URLHAUS_RECENT_PAYLOADS_COOLDOWN_SECONDS' and 'CONNECTOR_DURATION_PERIOD' are set. "
                    "'CONNECTOR_DURATION_PERIOD' will take precedence."
                )
            else:
                warnings.warn(
                    "Env var 'URLHAUS_RECENT_PAYLOADS_COOLDOWN_SECONDS' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
                )
                connector_data["duration_period"] = timedelta(
                    seconds=int(cooldown_seconds)
                )

        return data
