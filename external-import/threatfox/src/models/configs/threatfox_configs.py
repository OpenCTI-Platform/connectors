from typing import ClassVar, Optional
from urllib.parse import quote, urlparse

from connectors_sdk.shared.spamhaus import AbuseChAuthConfigMixin
from pydantic import Field, SecretStr, model_validator
from src.models.configs.base_settings import ConfigBaseSettings

EXPORT_URL_TEMPLATE = (
    "https://threatfox-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
)
# Public exports retired by abuse.ch (they answer 410 Gone), such as the
# former default https://threatfox.abuse.ch/export/csv/recent/.
LEGACY_EXPORT_HOST = "threatfox.abuse.ch"
LEGACY_EXPORT_PATH_PREFIX = "/export/"


class _ConfigLoaderThreatFox(AbuseChAuthConfigMixin, ConfigBaseSettings):
    """Interface for loading Threat Fox dedicated configuration."""

    # Config Loader
    auth_env_prefix: ClassVar[str] = "THREATFOX"

    # Secret: setups that predate `auth_key` put the key in this URL.
    csv_url: Optional[SecretStr] = Field(
        default=None,
        description="Override of the ThreatFox CSV export URL. "
        "Defaults to https://threatfox-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv, "
        "built from `auth_key`. Only used in community mode. The retired public URL "
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
    def _check_auth_modes(self) -> "_ConfigLoaderThreatFox":
        """Report the retired export URL first, then check the auth modes."""
        if (
            self.auth_key is None
            and not self.commercial_configured
            and self.has_legacy_csv_url
        ):
            raise ValueError(
                "THREATFOX_AUTH_KEY is required: THREATFOX_CSV_URL points to the "
                "retired public export, which abuse.ch no longer serves. Get an "
                "Auth-Key at https://auth.abuse.ch (or set the Spamhaus credentials "
                "THREATFOX_SPAMHAUS_USERNAME and THREATFOX_SPAMHAUS_PASSWORD) and "
                "remove THREATFOX_CSV_URL."
            )
        return super()._check_auth_modes()

    @property
    def community_configured(self) -> bool:
        """Whether the community mode is usable: an Auth-Key or a current CSV URL."""
        return self.auth_key is not None or (
            self.csv_url is not None and not self.has_legacy_csv_url
        )

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
    def export_url(self) -> Optional[str]:
        """URL of the community CSV export: `csv_url` if set (and not a retired
        public export), otherwise built from `auth_key`. None without a
        community setup (Spamhaus credentials only)."""
        if self.csv_url is not None and not self.has_legacy_csv_url:
            return self.csv_url.get_secret_value()
        if self.auth_key is None:
            return None
        # Encode the key so `/`, `?`, `#` or `%` cannot change the URL path.
        return EXPORT_URL_TEMPLATE.format(
            auth_key=quote(self.auth_key.get_secret_value(), safe="")
        )
