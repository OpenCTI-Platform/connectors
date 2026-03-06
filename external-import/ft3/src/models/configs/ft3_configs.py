from pydantic import (
    Field,
    PositiveInt,
)
from src.models.configs.base_settings import ConfigBaseSettings

FT3_TACTICS_URL = (
    "https://raw.githubusercontent.com/stripe/ft3/refs/heads/master/FT3_Tactics.json"
)
FT3_TECHNIQUES_URL = (
    "https://raw.githubusercontent.com/stripe/ft3/refs/heads/master/FT3_Techniques.json"
)


class _ConfigLoaderFT3(ConfigBaseSettings):
    """Interface for loading FT3 dedicated configuration."""

    # Config Loader
    interval: PositiveInt = Field(
        default=5,
        description=(
            "Polling interval in days for fetching and refreshing FT3 data. "
            "Determines how often the system checks for updates to FT3 datasets."
        ),
    )
    tactics_url: str = Field(
        default=FT3_TACTICS_URL,
        description=(
            "URL to the FT3 Tactics JSON file. "
            "This dataset includes fraud tactics from the FT3 framework."
        ),
    )
    techniques_url: str = Field(
        default=FT3_TECHNIQUES_URL,
        description=(
            "URL to the FT3 Techniques JSON file. "
            "Contains fraud techniques and their relationships to tactics."
        ),
    )
