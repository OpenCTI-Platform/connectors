"""Connector configuration.

Values come from environment variables or ``config.yml``. Environment
variables win. The Cyble-specific section is ``cyble_vision_writeback`` /
``CYBLE_VISION_WRITEBACK_*``.
"""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """OpenCTI-level options for the write-back connector."""

    id: str = Field(
        description="Unique connector ID. Must differ from the Cyble Vision import connector ID.",
        default="db8442d4-2e03-4bcb-9d9c-7c119d50df61",
    )
    name: str = Field(
        description="Display name in OpenCTI.",
        default="Cyble Vision Writeback",
    )
    scope: ListFromString = Field(
        description="Entity types this connector reacts to.",
        default=["Incident"],
    )
    live_stream_id: str = Field(
        description="ID of the live stream to listen to. 'live' is the global stream; a stream filtered on Incidents labelled 'cyble' reduces traffic.",
        default="live",
    )
    live_stream_listen_delete: bool = Field(
        description="Listen to delete events. Disabled by default, since write-back never deletes anything in Vision.",
        default=False,
    )
    live_stream_recover: bool = Field(
        description="Replay stream history on first start. Disabled by default so only new analyst updates are written back.",
        default=False,
    )


class CybleVisionWritebackConfig(BaseConfigModel):
    """Credentials and options for writing back to Cyble Vision."""

    api_base_url: HttpUrl = Field(
        description="Cyble Vision API base URL.",
        default="https://bifrost.cyble.ai",
    )
    api_token: SecretStr = Field(
        description="Cyble Vision API bearer token with permission to update alerts.",
    )
    ignored_user_names: ListFromString = Field(
        description="OpenCTI user names whose changes are not written back. Set it to the user the Cyble Vision import connector runs as, so imported values are not echoed back to Vision.",
        default=["Cyble Vision"],
    )


class ConnectorSettings(BaseConnectorSettings):
    """All configuration sections this connector needs."""

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    cyble_vision_writeback: CybleVisionWritebackConfig = Field(
        default_factory=CybleVisionWritebackConfig
    )
