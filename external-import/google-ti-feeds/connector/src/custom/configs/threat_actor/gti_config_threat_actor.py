"""GTI configuration for threat actors.

This module defines configuration settings specific to GTI threat actor imports.
"""

from typing import List

from connector.src.custom.configs.gti_config_common import (
    ALLOWED_ORIGINS,
    GTIBaseConfig,
    validate_origins_list,
)
from pydantic import field_validator


class GTIThreatActorConfig(GTIBaseConfig):
    """Configuration for GTI threat actor imports."""

    threat_actor_import_start_date: str = "P1D"
    import_threat_actors: bool = False
    threat_actor_origins: List[str] | str = "All"

    @field_validator("threat_actor_origins", mode="before")
    @classmethod
    def split_and_validate_threat_actor_origins(cls, v: str) -> List[str]:
        """Split and validate a comma-separated string into a list and validate its contents."""
        return validate_origins_list(v, "threat actor origin", ALLOWED_ORIGINS)
