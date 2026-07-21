"""GTI configuration for software toolkits.

This module defines configuration settings specific to GTI software toolkit imports.
"""

from datetime import timedelta

from connector.src.custom.configs.gti_config_common import (
    ALLOWED_SOFTWARE_TOOLKIT_SUBENTITIES,
    GTIBaseConfig,
    validate_origins_list,
    validate_subentities_list,
)
from connectors_sdk import ListFromString
from pydantic import Field, field_validator

ALLOWED_ORIGINS = [
    "All",
    "partner",
    "google threat intelligence",
]


class GTISoftwareToolkitConfig(GTIBaseConfig):
    """Configuration for GTI software toolkit imports."""

    software_toolkit_import_start_date: timedelta = Field(
        default=timedelta(days=1),
        description="ISO 8601 duration string specifying how far back to import software toolkits (e.g., P1D for 1 day, P7D for 7 days)",
    )

    import_software_toolkits: bool = Field(
        default=False,
        description="Whether to enable importing software toolkit data from GTI",
    )

    software_toolkit_origins: ListFromString = Field(
        default=["google threat intelligence"],
        description="Comma-separated list of software toolkit origins to import, or 'All' for all origins. "
        f"Allowed values: {', '.join(ALLOWED_ORIGINS)}",
        examples=["All", "partner", "google threat intelligence"],
    )

    software_toolkit_extra_filters: ListFromString = Field(
        default=[],
        description="Optional list of additional filters to add to query when fetching software toolkits",
        examples=["name:Cobalt Strike"],
    )

    software_toolkit_subentities: ListFromString = Field(
        default=[
            "malware_families",
            "attack_techniques",
        ],
        description="Comma-separated list of sub-entity types to fetch and link for each software toolkit. "
        "An empty list disables sub-entity fetching entirely for software toolkits, which can help reduce API quota usage. "
        f"Allowed values: {', '.join(ALLOWED_SOFTWARE_TOOLKIT_SUBENTITIES)}",
        examples=["malware_families", ""],
    )

    @field_validator("software_toolkit_origins", mode="after")
    @classmethod
    def validate_software_toolkit_origins(cls, v: list[str]) -> list[str]:
        """Validate software toolkit origins against allowed values."""
        return validate_origins_list(v, "software toolkit origin", ALLOWED_ORIGINS)

    @field_validator("software_toolkit_subentities", mode="after")
    @classmethod
    def validate_software_toolkit_subentities(cls, v: list[str]) -> list[str]:
        """Validate software toolkit sub-entities against allowed values."""
        return validate_subentities_list(
            v, "software toolkit subentity", ALLOWED_SOFTWARE_TOOLKIT_SUBENTITIES
        )
