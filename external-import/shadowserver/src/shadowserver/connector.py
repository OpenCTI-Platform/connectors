from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
from typing import Generator

from lib.external_import import ExternalImportConnector
from pycti import OpenCTIConnectorHelper
from shadowserver.api import ShadowserverAPI
from shadowserver.settings import ConnectorSettings
from shadowserver.utils import remove_duplicates


class CustomConnector(ExternalImportConnector):

    def __init__(
        self, helper: OpenCTIConnectorHelper, config: ConnectorSettings
    ) -> None:
        """Initialization of the connector"""
        super().__init__(helper, config)
        self.first_run = True
        self.lookback = None
        if last_run := self.state.get("last_run"):
            last_run = (
                datetime.fromtimestamp(last_run, tz=UTC)
                if isinstance(last_run, float | int)
                else datetime.fromisoformat(last_run)
            )
            self.lookback = (
                self.start_time - last_run
            ).days + self.config.shadowserver.lookback
            self.first_run = False
        else:
            self.lookback = self.config.shadowserver.initial_lookback
        self.helper.connector_logger.info(
            f"Connector initialized. Lookback: {self.lookback} days. First run: {self.first_run}"
        )

    def _collect_intelligence(self) -> Generator[tuple[list, str], None, None]:
        """Collects intelligence from channels

        Add your code depending on the use case as stated at https://docs.opencti.io/latest/development/connectors/.
        Some sample code is provided as a guide to add a specific observable and a reference to the main object.
        Consider adding additional methods to the class to make the code more readable.

        Returns:
            stix_objects: A list of STIX2 objects."""
        self.helper.connector_logger.info(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )
        shadowserver_api = ShadowserverAPI(
            api_key=self.config.shadowserver.api_key.get_secret_value(),
            api_secret=self.config.shadowserver.api_secret.get_secret_value(),
            marking_refs=self.config.shadowserver.marking,
        )
        report_types = self.config.shadowserver.report_types
        if report_types:
            self.helper.connector_logger.info(
                f"Report types to retrieve: {', '.join(report_types)}."
            )

        for days_lookback in range(self.lookback, -1, -1):
            stix_objects = []
            date = self.start_time - timedelta(days=days_lookback)
            date_str = date.strftime("%Y-%m-%d")
            self.helper.connector_logger.info(f"Getting reports for {date_str}.")
            report_list = shadowserver_api.get_report_list(
                date=date_str, reports=report_types
            )
            if not report_list:
                self.helper.connector_logger.info(f"No reports found for {date_str}.")
                continue
            self.helper.connector_logger.info(f"Found {len(report_list)} reports.")
            incident = {
                "create": self.config.shadowserver.create_incident,
                "severity": self.config.shadowserver.incident_severity,
                "priority": self.config.shadowserver.incident_priority,
            }

            with ThreadPoolExecutor(
                max_workers=self.config.shadowserver.max_threads
            ) as executor:
                futures = [
                    executor.submit(
                        shadowserver_api.get_stix_report,
                        report=report,
                        api_helper=self.helper,
                        incident=incident,
                    )
                    for report in report_list
                ]

                for future in as_completed(futures):
                    try:
                        report_stix_objects = future.result()
                        stix_objects.extend(
                            stix_object
                            for stix_object in report_stix_objects
                            if stix_object
                        )
                    except Exception as e:
                        self.helper.connector_logger.error(
                            f"Error processing report: {e}"
                        )
            self.helper.connector_logger.info(
                f"{len(stix_objects)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
            )
            unique_stix_objects = remove_duplicates(stix_objects)
            yield unique_stix_objects, date_str
