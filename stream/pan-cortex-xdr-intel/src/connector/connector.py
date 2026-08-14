from typing import Any

from cortex_xdr_client import CortexXdrClient
from pycti import OpenCTIConnectorHelper


class Connector:
    """
    Cortex XDR Intel stream connector.

    ---

    Attributes:
        helper (OpenCTIConnectorHelper):
            Handle the connection and the requests between the connector, OpenCTI and the workers.
        settings (Any):
            Store the connector's configuration.
        client (CortexXdrClient):
            Provide methods to request the Cortex XDR API.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        settings: Any,
        client: CortexXdrClient,
    ) -> None:
        self.helper = helper
        self.settings = settings
        self.client = client

    def start(self) -> None:
        raise NotImplementedError
