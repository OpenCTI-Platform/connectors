"""
This module contains the implementation of the `ReportProcessor` class for the `PouetPouetConnector`.
"""

from time import sleep
from typing import TYPE_CHECKING, Generator, override

from connector.converter_to_stix import ConverterToStix
from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import BaseIdentifiedObject, Report
from pouet_pouet_client.api_client import PouetPouetClient

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from connector.state_manager import ConnectorStateManager
    from pycti import OpenCTIConnectorHelper


class ReportProcessor(BaseDataProcessor):
    """
    Report processor implementation for the `PouetPouetConnector`.
    This class inherits from `BaseDataProcessor` and is used to process the reports retrieved
    from the Pouet API before it is ingested into OpenCTI.
    """

    def __init__(
        self,
        config: "ConnectorSettings",
        helper: "OpenCTIConnectorHelper",
        state_manager: "ConnectorStateManager",
    ):
        """
        Initialize the `ReportProcessor` with its dependencies.
        """
        super().__init__(
            config=config,
            helper=helper,
            state_manager=state_manager,
        )
        # Redundant assignments kept for typing purposes
        self.config = config
        self.state_manager = state_manager

        self.api_client = PouetPouetClient(
            helper=helper,
            base_url=self.config.pouet_pouet.api_base_url,
            api_key=self.config.pouet_pouet.api_key,
        )
        self.converter_to_stix = ConverterToStix(
            helper=helper,
            tlp_level=self.config.pouet_pouet.tlp_level,
        )

    @override
    def collect(self) -> Generator[dict, None, None]:
        """
        Collect data from the Pouet API.
        This method return retrieved data as a generator of dictionaries,
        where each dictionary represents a report to be ingested into OpenCTI.
        """
        last_ingested_at = self.state_manager.last_ingested_at
        pouet_reports = self.api_client.get_reports(since=last_ingested_at)

        return pouet_reports

    @override
    def transform(
        self, data: Generator[dict, None, None]
    ) -> Generator[list[BaseIdentifiedObject], None, None]:
        """
        Transform the collected data into OCTI objects.
        This method takes the raw data collected from the Pouet API and transform it into
        the format expected by OpenCTI for ingestion.
        Returns a generator of lists of `BaseIdentifiedObject`, where each list contains the OCTI objects of one bundle.
        """
        for pouet_report in data:
            sleep(1)  # simulate long running conversion
            octi_report = self.converter_to_stix.create_report(pouet_report)

            octi_objects = [
                self.converter_to_stix.tlp_marking,
                self.converter_to_stix.author,
                octi_report,
            ]

            yield octi_objects

    @override
    def send(self, data: Generator[list[BaseIdentifiedObject], None, None]) -> None:  # type: ignore[override]
        """
        Bundle and send the OCTI objects for ingestion to OpenCTI.
        """
        last_report = None

        for octi_objects in data:
            # Call the send method of the BaseDataProcessor to handle the actual sending of data
            super().send(data=octi_objects)

            # Update the state with custom fields after sending the data to OpenCTI
            bundle_last_report = next(
                (
                    obj
                    for obj in reversed(list(octi_objects))
                    if isinstance(obj, Report)
                ),
                None,
            )
            if bundle_last_report:

                if (
                    last_report is None
                    or last_report.publication_date
                    < bundle_last_report.publication_date
                ):
                    last_report = bundle_last_report

                    self.state_manager.last_pouet_id = bundle_last_report.id
                    self.state_manager.last_ingested_at = (
                        bundle_last_report.publication_date
                    )
                    self.state_manager.save()
