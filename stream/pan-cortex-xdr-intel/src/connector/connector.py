from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from cortex_xdr_client import CortexXdrClient
    from pycti import OpenCTIConnectorHelper


class Connector:
    """
    Cortex XDR Intel stream connector.

    ---

    Attributes:
        helper (OpenCTIConnectorHelper):
            Handle the connection and the requests between the connector, OpenCTI and the workers.
        settings (ConnectorSettings):
            Store the connector's configuration.
        client (CortexXdrClient):
            Provide methods to request the Cortex XDR API.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        settings: ConnectorSettings,
        client: CortexXdrClient,
    ) -> None:
        self.helper = helper
        self.settings = settings
        self.client = client

    def _process_message(self, message: dict) -> None:
        # TODO: implement IOC upsert/delete mapping from the stream message (#7184/#7185)
        self.helper.connector_logger.info(
            "Received stream event (baseline wiring phase)"
        )

    def start(self) -> None:
        self.helper.listen_stream(self._process_message)
