from datetime import timedelta

from connectors_sdk import (
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector configuration extended with live stream settings.

    The three `live_stream_*` fields map to the `CONNECTOR_LIVE_STREAM_*` environment
    variables and the matching `["connector", "live_stream_*"]` paths consumed by
    `OpenCTIConnectorHelper` to drive the SSE consumer used by this connector.
    """

    name: str = Field(
        description="The name of the connector.",
        default="OpenCTI Stream",
    )
    duration_period: timedelta = Field(
        description=(
            "Period between scheduled health checks of the SSE consumer thread. "
            "The thread itself runs continuously; this only controls how often the "
            "watchdog verifies it is alive and restarts it if it has died."
        ),
        default=timedelta(minutes=1),
    )
    live_stream_id: str = Field(
        description=(
            "The OpenCTI live stream to subscribe to. "
            "Use 'live' for the global live stream, 'raw' for the raw stream, "
            "or the UUID of a stream collection."
        ),
    )
    live_stream_listen_delete: bool = Field(
        description=(
            "Whether to subscribe to delete events. Disabled by default since this "
            "connector only forwards create/update (upsert) events."
        ),
        default=False,
    )
    live_stream_no_dependencies: bool = Field(
        description=(
            "Whether to receive only the event's own object from the stream "
            "(without dependent objects). False by default so dependencies are included "
            "and forwarded together with each event."
        ),
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Top-level settings for the OpenCTI Stream connector."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
