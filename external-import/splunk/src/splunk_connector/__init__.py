"""OpenCTI Splunk external import connector."""

from splunk_connector.connector import SplunkConnector
from splunk_connector.settings import ConnectorSettings

__all__ = [
    "ConnectorSettings",
    "SplunkConnector",
]
