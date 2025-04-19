from base_connector.client import BaseClient
from email_intel_imap.config import ConnectorConfig


class ConnectorClient(BaseClient):
    config: ConnectorConfig
