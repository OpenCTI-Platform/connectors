import warnings
from datetime import timedelta
from typing import Optional
from urllib.parse import quote, urlparse

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr, field_validator, model_validator

EXPORT_URL_TEMPLATE = (
    "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
)
# Public downloads retired by abuse.ch (they answer 410 Gone), such as the
# former default https://urlhaus.abuse.ch/downloads/csv_recent/.
LEGACY_EXPORT_HOST = "urlhaus.abuse.ch"
LEGACY_EXPORT_PATH_PREFIX = "/downloads/"


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="e6b8818b-04f2-4781-81e0-fb2652799ab6",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Urlhaus",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=3),
    )


class UrlhausConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `UrlhausConnector`.
    """

    auth_key: Optional[SecretStr] = Field(
        description="abuse.ch Auth-Key, available at https://auth.abuse.ch. "
        "Required unless `csv_url` is set.",
        default=None,
    )
    # Secret: the export URL contains the Auth-Key.
    csv_url: Optional[SecretStr] = Field(
        description="Override of the URLhaus CSV export URL. "
        "Defaults to https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv, "
        "built from `auth_key`. The retired public URL "
        "(https://urlhaus.abuse.ch/downloads/...) is ignored.",
        default=None,
    )
    default_x_opencti_score: int = Field(
        description="Default x_opencti_score for imported indicators.", default=80
    )
    import_offline: bool = Field(
        description="Import URLs marked as 'offline' in addition to 'online'.",
        default=True,
    )
    interval: int = Field(
        description="Polling interval in hours.",
        default=3,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
    )
    threats_from_labels: bool = Field(
        description="Create relationships to existing threats based on URL tags.",
        default=True,
    )

    @field_validator("auth_key", "csv_url", mode="before")
    @classmethod
    def _blank_to_none(cls, value):
        """Treat a blank value, such as an empty `${VAR}` in compose, as unset."""
        raw = value.get_secret_value() if isinstance(value, SecretStr) else value
        if isinstance(raw, str) and not raw.strip():
            return None
        return value

    @model_validator(mode="after")
    def _require_auth_key_or_csv_url(self) -> "UrlhausConfig":
        if self.auth_key is None and self.has_legacy_csv_url:
            raise ValueError(
                "URLHAUS_AUTH_KEY is required: URLHAUS_CSV_URL points to the "
                "retired public download, which abuse.ch no longer serves. Get an "
                "Auth-Key at https://auth.abuse.ch and remove URLHAUS_CSV_URL."
            )
        if self.auth_key is None and self.csv_url is None:
            raise ValueError(
                "URLHAUS_AUTH_KEY is required: abuse.ch requires an Auth-Key to "
                "download URLhaus exports. Get one at https://auth.abuse.ch."
            )
        return self

    @property
    def has_legacy_csv_url(self) -> bool:
        """True when `csv_url` points to a retired public download."""
        if self.csv_url is None:
            return False
        # The SDK settings loader runs this check on an untyped copy of the
        # model, where `csv_url` is still the raw string.
        csv_url = self.csv_url
        if isinstance(csv_url, SecretStr):
            csv_url = csv_url.get_secret_value()
        url = urlparse(csv_url)
        return url.hostname == LEGACY_EXPORT_HOST and url.path.startswith(
            LEGACY_EXPORT_PATH_PREFIX
        )

    @property
    def export_url(self) -> str:
        """URL of the CSV export: `csv_url` if set (and not a retired public
        download), otherwise built from `auth_key`."""
        if self.csv_url is not None and not self.has_legacy_csv_url:
            return self.csv_url.get_secret_value()
        # Encode the key so `/`, `?`, `#` or `%` cannot change the URL path.
        return EXPORT_URL_TEMPLATE.format(
            auth_key=quote(self.auth_key.get_secret_value(), safe="")
        )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `UrlhausConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    urlhaus: UrlhausConfig = Field(default_factory=UrlhausConfig)

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `URLHAUS_INTERVAL` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        urlhaus_data: dict = data.get("urlhaus", {})
        if interval := urlhaus_data.pop("interval", None):
            if connector_data.get("duration_period") is not None:
                warnings.warn(
                    "Both 'URLHAUS_INTERVAL' and 'CONNECTOR_DURATION_PERIOD' are set. "
                    "'CONNECTOR_DURATION_PERIOD' will take precedence."
                )
            else:
                warnings.warn(
                    "Env var 'URLHAUS_INTERVAL' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
                )
                connector_data["duration_period"] = timedelta(hours=int(interval))

        return data
