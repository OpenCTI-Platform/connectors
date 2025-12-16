"""GTI configuration for threat actors.

This module defines configuration settings specific to GTI threat actor imports.
"""

from datetime import timedelta

from connector.src.custom.configs.gti_config_common import (
    ALLOWED_ORIGINS,
    GTIBaseConfig,
    validate_origins_list,
)
from connectors_sdk import ListFromString
from pydantic import Field, field_validator


class GTIThreatActorConfig(GTIBaseConfig):
    """Configuration for GTI threat actor imports."""

    threat_actor_import_start_date: timedelta = Field(
        default=timedelta(days=1),
        description="ISO 8601 duration string specifying how far back to import threat actors (e.g., P1D for 1 day, P7D for 7 days)",
    )

    import_threat_actors: bool = Field(
        default=False,
        description="Whether to enable importing threat actor data from GTI",
    )

    threat_actor_origins: ListFromString = Field(
        default=["google threat intelligence"],
        description="Comma-separated list of threat actor origins to import, or 'All' for all origins. "
        f"Allowed values: {', '.join(ALLOWED_ORIGINS)}",
        examples=["All", "partner,google threat intelligence", "crowdsourced"],
    )

    enable_threat_actor_aliases: bool = Field(
        default=False,
        description="Whether to enable importing threat actor aliases from GTI",
    )

    @field_validator("threat_actor_origins", mode="after")
    @classmethod
    def validate_threat_actor_origins(cls, v: list[str]) -> list[str]:
        """Validate threat actor origins against allowed values."""
        return validate_origins_list(v, "threat actor origin", ALLOWED_ORIGINS)
