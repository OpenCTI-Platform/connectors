from datetime import timedelta

from connectors_sdk import (
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector configuration extended with live stream settings.

    The `live_stream_*` fields map to `CONNECTOR_LIVE_STREAM_*` environment variables
    and the matching `["connector", "live_stream_*"]` config paths.

    `live_stream_opencti_url` / `live_stream_opencti_token` decouple the OpenCTI the
    connector listens to (the source) from the OpenCTI the connector is registered
    with (the target, used by `OPENCTI_URL` / `OPENCTI_TOKEN` and where bundles are
    pushed in queue mode). When unset, the source defaults to the target so the
    connector listens to the same OpenCTI it pushes to (typical diode-export setup
    where the connector runs alongside the source instance).
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
    live_stream_opencti_url: HttpUrl | None = Field(
        description=(
            "URL of the OpenCTI instance whose live stream to consume. "
            "Defaults to `OPENCTI_URL` (the OpenCTI the connector is registered with) "
            "when unset. Set this to point at a remote / source OpenCTI different "
            "from the one this connector pushes bundles to."
        ),
        default=None,
    )
    live_stream_opencti_token: SecretStr | None = Field(
        description=(
            "API token for the OpenCTI instance whose live stream to consume. "
            "Defaults to `OPENCTI_TOKEN` when unset. Required when "
            "`live_stream_opencti_url` points to a remote instance with a different "
            "auth context."
        ),
        default=None,
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
