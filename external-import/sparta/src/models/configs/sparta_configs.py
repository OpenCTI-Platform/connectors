from pydantic import (
    Field,
    PositiveInt,
)
from src.models.configs import ConfigBaseSettings

SPARTA_FILE_URL = "https://sparta.aerospace.org/download/STIX?f=latest"


class _ConfigLoaderSparta(ConfigBaseSettings):
    """Interface for loading dedicated configuration."""

    interval: PositiveInt = Field(
        default=7,
        description=(
            "Polling interval in days for fetching and refreshing SPARTA data. "
            "Determines how often the system checks for updates to SPARTA datasets."
        ),
    )
    sparta_file_url: str = Field(
        default=SPARTA_FILE_URL,
        description=(
            "URL to the SPARTA JSON file. "
            "This dataset includes tactics, techniques, and procedures (TTPs) "
            "for enterprise IT environments."
        ),
    )
