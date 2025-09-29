from connectors_sdk.core.pydantic import ListFromString
from models.configs import ConfigBaseSettings
from pydantic import Field, PositiveInt, SecretStr


class _ConfigLoaderFeedly(ConfigBaseSettings):
    """Interface for loading Feedly dedicated configuration."""

    # Config Loader Feedly
    interval: PositiveInt = Field(
        default=60,
        description=(
            "Polling interval in minutes for fetching and refreshing Feedly data. "
            "Determines how often the system checks for updates from Feedly streams."
        ),
    )
    stream_ids: ListFromString = Field(
        default=None,
        description=(
            "Comma separated list of Feedly stream IDs to monitor. "
            "Each stream ID represents a specific feed or collection to import from Feedly."
        ),
    )
    days_to_back_fill: PositiveInt = Field(
        default=7,
        description=(
            "Number of days to back fill for new streams. "
            "When a new stream is added, the connector will fetch articles from this many days in the past."
        ),
    )
    api_key: SecretStr = Field(
        description=(
            "Feedly API key for authentication. "
            "Generate your API key at https://feedly.com/i/team/api"
        ),
    )
