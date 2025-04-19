import abc

from base_connector.config import BaseConnectorConfig
from pycti import OpenCTIConnectorHelper


class BaseClient(abc.ABC):
    def __init__(
        self, helper: OpenCTIConnectorHelper, config: BaseConnectorConfig
    ) -> None:
        """Base class for the client configuration."""
        self.helper = helper
        self.config = config
