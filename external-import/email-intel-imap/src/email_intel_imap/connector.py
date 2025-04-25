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

    def get_last_run(self) -> datetime.datetime | None:
        if last_run_str := self.state.get("last_run"):
            last_run = datetime.datetime.fromisoformat(last_run_str)
            self.helper.connector_logger.info(
                f"Connector last run: {last_run.isoformat()}"
            )
            return last_run
        self.helper.connector_logger.info("Connector last run: Never")
        return None

    def get_stix_objects(self) -> list[stix2.Report]:
        since_date = self.get_last_run() or (
            datetime.datetime.now(tz=datetime.UTC)
            - self.config.email_intel_imap.relative_import_start_date
        )
        return [
            stix_object
            for email in self.client.fetch_from_relative_import_start_date(
                since_date.date()
            )
            if email.date > since_date
            for stix_object in self.converter.to_stix_objects(email)
        ]

    def process_data(self) -> list[stix2.Report]:
        run_time = datetime.datetime.now(tz=datetime.UTC)

        stix_objects = self.get_stix_objects()

        self.update_state(last_run=run_time.isoformat(timespec="seconds"))
        return stix_objects
