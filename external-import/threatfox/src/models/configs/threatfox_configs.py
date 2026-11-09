from typing import Optional

from pydantic import Field, SecretStr, model_validator
from src.models.configs.base_settings import ConfigBaseSettings

EXPORT_URL_TEMPLATE = (
    "https://threatfox-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
)


class _ConfigLoaderThreatFox(ConfigBaseSettings):
    """Interface for loading Threat Fox dedicated configuration."""

    # Config Loader
    auth_key: Optional[SecretStr] = Field(
        default=None,
        description="abuse.ch Auth-Key, available at https://auth.abuse.ch. "
        "Required unless `csv_url` is set.",
    )
    csv_url: Optional[str] = Field(
        default=None,
        description="Override of the ThreatFox CSV export URL. "
        "Defaults to https://threatfox-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv, "
        "built from `auth_key`.",
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
        if self.auth_key is None and self.csv_url is None:
            raise ValueError(
                "THREATFOX_AUTH_KEY is required: abuse.ch requires an Auth-Key to "
                "download ThreatFox exports. Get one at https://auth.abuse.ch."
            )
        return self

    @property
    def export_url(self) -> str:
        """URL of the CSV export: `csv_url` if set, otherwise built from `auth_key`."""
        if self.csv_url is not None:
            return self.csv_url
        return EXPORT_URL_TEMPLATE.format(auth_key=self.auth_key.get_secret_value())
