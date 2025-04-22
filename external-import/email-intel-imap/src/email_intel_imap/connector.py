import datetime

import stix2
from base_connector.connector import BaseConnector
from email_intel_imap.client import ConnectorClient
from email_intel_imap.config import ConnectorConfig
from email_intel_imap.converter import ConnectorConverter


class Connector(BaseConnector):
    config: ConnectorConfig
    converter: ConnectorConverter
    client: ConnectorClient

    def collect_intelligence(
        self, last_run: datetime.datetime | None
    ) -> list[stix2.Report]:
        since_date = (
            datetime.date.today()
            - self.config.email_intel_imap.relative_import_start_date
        )
        return [
            stix_object
            for email in self.client.fetch_from_relative_import_start_date(since_date)
            for stix_object in self.converter.to_stix_objects(email)
        ]
