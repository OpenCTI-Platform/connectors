from typing import Any

from base_connector.connector import BaseConnector
from email_intel_imap.client import ConnectorClient
from email_intel_imap.config import ConnectorConfig
from email_intel_imap.converter import ConnectorConverter


class Connector(BaseConnector[ConnectorConfig, ConnectorClient, ConnectorConverter]):
    def _collect_intelligence(self) -> list[Any]:
        return []
