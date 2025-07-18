"""GTI configuration for threat actors.

This module defines configuration settings specific to GTI threat actor imports.
"""

from typing import List

from connector.src.custom.configs.gti_config_common import (
    ALLOWED_ORIGINS,
    GTIBaseConfig,
    validate_origins_list,
)
from pydantic import Field, field_validator


class GTIThreatActorConfig(GTIBaseConfig):
    """Configuration for GTI threat actor imports."""

    threat_actor_import_start_date: str = Field(
        default="P1D",
        description="ISO 8601 duration string specifying how far back to import threat actors (e.g., P1D for 1 day, P7D for 7 days)",
        pattern=r"^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$",
    )

    import_threat_actors: bool = Field(
        default=False,
        description="Whether to enable importing threat actor data from GTI",
    )

    threat_actor_origins: List[str] | str = Field(
        default="All",
        description="Comma-separated list of threat actor origins to import, or 'All' for all origins. "
        f"Allowed values: {', '.join(ALLOWED_ORIGINS)}",
        examples=["All", "partner,google threat intelligence", "crowdsourced"],
    )

    @field_validator("threat_actor_origins", mode="before")
    @classmethod
    def split_and_validate_threat_actor_origins(cls, v: str) -> List[str]:
        """Split and validate a comma-separated string into a list and validate its contents."""
        return validate_origins_list(v, "threat actor origin", ALLOWED_ORIGINS)
