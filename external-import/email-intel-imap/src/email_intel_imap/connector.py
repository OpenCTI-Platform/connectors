import stix2
from base_connector.connector import BaseConnector
from email_intel_imap.client import ConnectorClient
from email_intel_imap.config import ConnectorConfig
from email_intel_imap.converter import ConnectorConverter


class Connector(BaseConnector[ConnectorConfig, ConnectorClient, ConnectorConverter]):
    def _collect_intelligence(self) -> list[stix2.Report]:
        return [
            stix_object
            for email in self.client.fetch_from_relative_import_start_date()
            for stix_object in self.converter.to_stix(email)
        ]
