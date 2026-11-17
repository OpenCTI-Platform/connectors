from typing import Optional
from urllib.parse import quote, urlparse

from pydantic import Field, SecretStr, model_validator
from src.models.configs.base_settings import ConfigBaseSettings

EXPORT_URL_TEMPLATE = (
    "https://threatfox-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
)
# Public exports retired by abuse.ch (they answer 410 Gone), such as the
# former default https://threatfox.abuse.ch/export/csv/recent/.
LEGACY_EXPORT_HOST = "threatfox.abuse.ch"
LEGACY_EXPORT_PATH_PREFIX = "/export/"


class _ConfigLoaderThreatFox(ConfigBaseSettings):
    """Interface for loading Threat Fox dedicated configuration."""

    # Config Loader
    auth_key: Optional[SecretStr] = Field(
        default=None,
        description="abuse.ch Auth-Key, available at https://auth.abuse.ch. "
        "Required unless `csv_url` is set.",
    )
    # Secret: setups that predate `auth_key` put the key in this URL.
    csv_url: Optional[SecretStr] = Field(
        default=None,
        description="Override of the ThreatFox CSV export URL. "
        "Defaults to https://threatfox-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv, "
        "built from `auth_key`. The retired public URL "
        "(https://threatfox.abuse.ch/export/...) is ignored.",
    )
    import_offline: bool = Field(
        default=True,
        description="Create records for indicators that are offline.",
    )
    create_indicators: bool = Field(
        default=True,
        description="Create indicators in addition to observables.",
    )
    default_x_opencti_score: int = Field(
        default=50,
        description="The default x_opencti_score to use.",
    )
    x_opencti_score_ip: Optional[int] = Field(
        default=None,
        description="Set the x_opencti_score for IP observables.",
    )
    x_opencti_score_domain: Optional[int] = Field(
        default=None,
        description="Set the x_opencti_score for Domain observables.",
    )
    x_opencti_score_url: Optional[int] = Field(
        default=None,
        description="Set the x_opencti_score for URL observables.",
    )
    x_opencti_score_hash: Optional[int] = Field(
        default=None,
        description="Set the x_opencti_score for Hash observables.",
    )
    interval: int = Field(
        default=3,
        description="[DEPRECATED] Interval in days between two scheduled runs of the connector.",
    )
    ioc_to_import: str = Field(
        default="all_types",
        description="List of IOC types to retrieve, available parameters: all_types, ip:port, domain, url, md5_hash, sha1_hash, sha256_hash",
    )

    @model_validator(mode="after")
    def _require_auth_key_or_csv_url(self) -> "_ConfigLoaderThreatFox":
        if self.auth_key is None and self.has_legacy_csv_url:
            raise ValueError(
                "THREATFOX_AUTH_KEY is required: THREATFOX_CSV_URL points to the "
                "retired public export, which abuse.ch no longer serves. Get an "
                "Auth-Key at https://auth.abuse.ch and remove THREATFOX_CSV_URL."
            )
        if self.auth_key is None and self.csv_url is None:
            raise ValueError(
                "THREATFOX_AUTH_KEY is required: abuse.ch requires an Auth-Key to "
                "download ThreatFox exports. Get one at https://auth.abuse.ch."
            )
        return self

    @property
    def has_legacy_csv_url(self) -> bool:
        """True when `csv_url` points to a retired public export."""
        if self.csv_url is None:
            return False
        url = urlparse(self.csv_url.get_secret_value())
        return url.hostname == LEGACY_EXPORT_HOST and url.path.startswith(
            LEGACY_EXPORT_PATH_PREFIX
        )

    @property
    def export_url(self) -> str:
        """URL of the CSV export: `csv_url` if set (and not a retired public
        export), otherwise built from `auth_key`."""
        if self.csv_url is not None and not self.has_legacy_csv_url:
            return self.csv_url.get_secret_value()
        # Encode the key so `/`, `?`, `#` or `%` cannot change the URL path.
        return EXPORT_URL_TEMPLATE.format(
            auth_key=quote(self.auth_key.get_secret_value(), safe="")
        )
