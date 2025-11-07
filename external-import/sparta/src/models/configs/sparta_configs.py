from models.configs.base_settings import ConfigBaseSettings
from pydantic import Field


class _ConfigLoaderSparta(ConfigBaseSettings):
    """Interface for loading SPARTA dedicated configuration."""

    # Config Loader
    base_url: str = Field(
        default="https://sparta.aerospace.org/download/STIX?f=latest",
        description="SPARTA base url used for retrieving SPARTA STIX",
    )
