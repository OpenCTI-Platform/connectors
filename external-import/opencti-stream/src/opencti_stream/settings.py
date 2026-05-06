from datetime import timedelta

from connectors_sdk import (
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
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
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["opencti-stream"],
    )
    duration_period: timedelta = Field(
        description=(
            "Required by the base connector configuration but unused by this connector. "
            "Events are streamed continuously via SSE; there is no scheduled run."
        ),
        default=timedelta(hours=1),
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
