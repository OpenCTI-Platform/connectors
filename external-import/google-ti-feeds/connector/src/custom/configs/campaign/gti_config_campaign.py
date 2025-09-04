"""GTI configuration for campaigns.

This module defines configuration settings specific to GTI campaign imports.
"""

from datetime import timedelta
from typing import List

from connector.src.custom.configs.gti_config_common import (
    ALLOWED_ORIGINS,
    GTIBaseConfig,
    validate_origins_list,
)
from pydantic import Field, field_validator


class GTICampaignConfig(GTIBaseConfig):
    """Configuration for GTI campaign imports."""

    campaign_import_start_date: timedelta = Field(
        default=timedelta(days=1),
        description="ISO 8601 duration string specifying how far back to import campaigns (e.g., P1D for 1 day, P7D for 7 days)",
    )

    import_campaigns: bool = Field(
        default=True,
        description="Whether to enable importing campaign data from GTI",
    )

    campaign_origins: List[str] | str = Field(
        default="All",
        description="Comma-separated list of campaign origins to import, or 'All' for all origins. "
        f"Allowed values: {', '.join(ALLOWED_ORIGINS)}",
        examples=["All", "partner,google threat intelligence", "crowdsourced"],
    )

    @field_validator("campaign_origins", mode="before")
    @classmethod
    def split_and_validate_campaign_origins(cls, v: str) -> List[str]:
        """Split and validate a comma-separated string into a list and validate its contents."""
        return validate_origins_list(v, "campaign origin", ALLOWED_ORIGINS)
