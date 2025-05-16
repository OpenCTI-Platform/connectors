"""Processor module will be in charge of converting the Google Threat Intelligence feeds reports into STIX2.1 SDO report entities.
This module will also handle the conversion of embedded entities from the reports, like locations and identities.

The processed entities will be send into a broker queue for further ingestion.
"""

from connector.src.custom.interfaces.base_processor import BaseProcessor
from typing import Optional, Dict, TYPE_CHECKING, List
import logging
import asyncio
from connector.src.custom.pubsub import broker
from connector.src.custom.reports_constants import PREFIX_BROKER, SENTINEL

if TYPE_CHECKING:
    from stix2.v21 import Identity, MarkingDefinition, Report, Location

event_map: Dict[str, asyncio.Event] = {}

class ProcessReports(BaseProcessor):
    """The class will defined all the necessary methods to process Google Threat Intelligence feeds reports into STIX2.1 SDO report entities.
    This class will also handle the conversion of embedded entities from the reports, like locations and identities.
    """

    def __init__(self, organization: "Identity", tlp_marking: "MarkingDefinition", logger: Optional["Logger"] = None) -> None:
        """Initialize the class with a subscription to the broker queue receiving the reports.

        Args:
            organization (Identity): The organization of the reports.
            tlp_marking (MarkingDefinition): The TLP marking to use for the reports.
            logger (Optional[Logger], optional): The logger to use. Defaults to None.

        """
        self.queue = broker.subscribe(f"{PREFIX_BROKER}/reports")
        self.organization = organization
        self.tlp_marking = tlp_marking
        self._logger = logger or logging.getLogger(__name__)

    async def process(self) -> None:
        """Process the reports received from the broker queue."""
        while True:
            last_modification_timestamp, reports = await self.queue.get()
            try:
                if reports is SENTINEL:
                   break
                self._convert_reports_to_stix21(last_modification_timestamp, reports)
            finally:
                self.queue.task_done()

    async def _convert_reports_to_stix21(self, last_modification_timestamp: int, reports: List["Report"]) -> None:
        """Convert the reports into STIX2.1 SDO report pydantic model."""
        # for report in reports:
            # stix21_identity: Identity = GtiReportToStixIdentity(report, self.organization)
            # stix21_location: Location = GtiReportToOctiLocation(report, self.organization)
            # stix21_report: Report = GtiReportToStixReport(report, stix21_identity, self.tlp_marking)

            # origin_id = report.id
            # event = asyncio.Event()
            # event_map[origin_id] = event
            # event.set()
            # await broker.publish(f"{PREFIX_BROKER}/final", (last_modification_timestamp, stix21_identity))
            # await broker.publish(f"{PREFIX_BROKER}/final", (last_modification_timestamp, stix21_location))
            # await broker.publish(f"{PREFIX_BROKER}/final", (last_modification_timestamp, stix21_report))
        ...

# TODO:    Scenario Outline: Should map STIX2.1 SDO report into a pydantic model for ease of use.
# TODO:    Scenario Outline: Should convert gti report response model into STIX2.1 SDO report pydantic model.
# TODO:    Scenario Outline: Some values are required for STIX2.1 SDO report.
# TODO:    Scenario Outline: Some values are optionals for STIX2.1 SDO report.
# TODO:    Scenario Outline: Need to raise an error if the convert to pydantic model failed.
# TODO:    Scenario Outline: Should convert STIX2.1 SDO report pydantic model into valid STIX2.1 SDO report object.
# TODO:    Scenario Outline: Should create a STIX2.1 bundle with those entities.
# TODO:    Scenario Outline: Should add the gti report id into a queue for later sub-api call.

# TODO:    Scenario Outline: Should map STIX2.1 SDO Location as a pydantic model for ease of use.
# TODO:    Scenario Outline: Should map STIX2.1 SDO Identity/Industry Sector as a pydantic model for ease of use.
# TODO:    Scenario Outline: Should convert gti report response model into STIX2.1 SDO Location pydantic model.
# TODO:    Scenario Outline: Should convert gti report response model into STIX2.1 SDO Identity/Industry Sector pydantic model.
# TODO:    Scenario Outline: Some values are required for STIX2.1 SDO Location.
# TODO:    Scenario Outline: Some values are optionals for STIX2.1 SDO Location.
# TODO:    Scenario Outline: Some values are required for STIX2.1 SDO Identity/Industry Sector.
# TODO:    Scenario Outline: Some values are optionals for STIX2.1 SDO Identity/Industry Sector.
# TODO:    Scenario Outline: Need to raise an error if the convert to pydantic models failed.
# TODO:    Scenario Outline: Should convert STIX2.1 SDO Location pydantic model into valid STIX2.1 SDO Location object.
# TODO:    Scenario Outline: Should convert STIX2.1 SDO Identity/Industry Sector pydantic model into valid STIX2.1 SDO Identity/Industry Sector object.
# TODO:    Scenario Outline: Should use the same STIX2.1 bundle for those entities.
