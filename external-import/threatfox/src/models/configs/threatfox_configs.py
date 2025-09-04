from typing import Optional

from pydantic import Field
from src.models.configs.base_settings import ConfigBaseSettings


class _ConfigLoaderThreatFox(ConfigBaseSettings):
    """Interface for loading Threat Fox dedicated configuration."""

    # Config Loader
    csv_url: Optional[str] = Field(
        default="https://threatfox.abuse.ch/export/csv/recent/",
        description="The Threat Fox URL",
    )
    import_offline: Optional[bool] = Field(
        default=True,
        description="Create records for indicators that are offline.",
    )
    create_indicators: Optional[bool] = Field(
        default=True,
        description="Create indicators in addition to observables.",
    )
    default_x_opencti_score: Optional[int] = Field(
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
    interval: Optional[int] = Field(
        default=3,
        description="[DEPRECATED] Interval in days between two scheduled runs of the connector.",
    )
    ioc_to_import: Optional[str] = Field(
        default="all_types",
        description="List of IOC types to retrieve, available parameters: all_types, ip:port, domain, url, md5_hash, sha1_hash, sha256_hash",
    )
