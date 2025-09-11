from typing import Annotated, Optional

from models.configs import ConfigBaseSettings
from pydantic import Field, HttpUrl, PlainSerializer, PositiveInt

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]


class _ConfigLoaderRansomwareLive(ConfigBaseSettings):
    """Interface for loading Ransomware Live dedicated configuration."""

    # Config Loader
    pull_history: Optional[bool] = Field(
        default=False,
        description="Whether to pull historic data. It is not recommended to set it to true as there will a large influx of data",
    )
    history_start_year: Optional[PositiveInt] = Field(
        default=2023,
        description="The year to start from",
    )
    create_threat_actor: Optional[bool] = Field(
        default=False,
        description="Whether to create a Threat Actor object",
    )
    run_every: Optional[str] = Field(
        default="10m",
        description="[DEPRECATED] Interval in days between two scheduled runs of the connector.",
    )
