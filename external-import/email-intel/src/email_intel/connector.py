import datetime
from typing import Any

from base_connector.connector import BaseConnector
from email_intel.client import Client
from email_intel.config import ConnectorConfig
from email_intel.converter import ConnectorConverter


class Connector(BaseConnector[ConnectorConfig, Client, ConnectorConverter]):
    def _collect_intelligence(self) -> list[Any]:
        with self.client:
            since_date = datetime.date.today() - datetime.timedelta(
                days=self.config.email_intel.relative_import_since_days
            )
            return [
                stix_object
                for entity in self.client.fetch_since(since_date=since_date)
                for stix_object in self.converter.to_stix(entity)
            ]
