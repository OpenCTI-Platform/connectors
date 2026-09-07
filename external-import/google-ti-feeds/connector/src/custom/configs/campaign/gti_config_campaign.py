"""GTI configuration for campaigns.

This module defines configuration settings specific to GTI campaign imports.
"""

from datetime import timedelta

from connector.src.custom.configs.gti_config_common import (
    ALLOWED_CAMPAIGN_SUBENTITIES,
    ALLOWED_ORIGINS,
    GTIBaseConfig,
    validate_origins_list,
    validate_subentities_list,
)
from connectors_sdk import ListFromString
from pydantic import Field, field_validator


class GTICampaignConfig(GTIBaseConfig):
    """Configuration for GTI campaign imports."""

    campaign_import_start_date: timedelta = Field(
        default=timedelta(days=1),
        description="ISO 8601 duration string specifying how far back to import campaigns (e.g., P1D for 1 day, P7D for 7 days)",
    )

    import_campaigns: bool = Field(
        default=False,
        description="Whether to enable importing campaign data from GTI",
    )

    campaign_origins: ListFromString = Field(
        default=["google threat intelligence"],
        description="Comma-separated list of campaign origins to import, or 'All' for all origins. "
        f"Allowed values: {', '.join(ALLOWED_ORIGINS)}",
        examples=["All", "partner", "google threat intelligence", "crowdsourced"],
    )

    campaign_extra_filters: ListFromString = Field(
        default=[],
        description="Optional List of additional filters to add to query when fetching campaigns",
        examples=["name:Operation Shadow"],
    )

    campaign_subentities: ListFromString = Field(
        default=[
            "malware_families",
            "attack_techniques",
            "vulnerabilities",
            "threat_actors",
            # "domains",
            # "files",
            # "urls",
            # "ip_addresses",
            "software_toolkits",
        ],
        description="Comma-separated list of sub-entity types to fetch and link for each campaign. "
        "An empty list disables sub-entity fetching entirely for campaigns, which can help reduce API quota usage. "
        f"Allowed values: {', '.join(ALLOWED_CAMPAIGN_SUBENTITIES)}",
        examples=["malware_families,threat_actors", ""],
    )

    @field_validator("campaign_origins", mode="after")
    @classmethod
    def validate_campaign_origins(cls, v: list[str]) -> list[str]:
        """Validate campaign origins against allowed values."""
        return validate_origins_list(v, "campaign origin", ALLOWED_ORIGINS)

    @field_validator("campaign_subentities", mode="after")
    @classmethod
    def validate_campaign_subentities(cls, v: list[str]) -> list[str]:
        """Validate campaign sub-entities against allowed values."""
        return validate_subentities_list(
            v, "campaign subentity", ALLOWED_CAMPAIGN_SUBENTITIES
        )
