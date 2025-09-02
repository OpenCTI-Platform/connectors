from typing import Optional

from pydantic import Field
from src.connector.models.configs import ConfigBaseSettings


class _ConfigLoaderHygiene(ConfigBaseSettings):
    """Interface for loading Hygiene dedicated configuration."""

    # Config Loader
    warninglists_slow_search: Optional[bool] = Field(
        default=False,
        description="Enable slow search mode for the warning lists. If true, uses the most appropriate search method. Can be slower. Default: exact match.",
    )
    label_name: Optional[str] = Field(
        default="hygiene",
        description="Set the label name.",
    )
    label_color: Optional[str] = Field(
        default="#fc0341",
        description="Color to use for the label.",
    )
    label_parent_name: Optional[str] = Field(
        default="hygiene_parent",
        description="Label name to be used when enriching sub-domains.",
    )
    label_parent_color: Optional[str] = Field(
        default="#fc0341",
        description="Color to use for the label when enriching subdomains.",
    )
    enrich_subdomains: Optional[bool] = Field(
        default=False,
        description="Enable enrichment of sub-domains, This option will add 'hygiene_parent' label and ext refs of the parent domain to the subdomain, if sub-domain is not found but parent is.",
    )
