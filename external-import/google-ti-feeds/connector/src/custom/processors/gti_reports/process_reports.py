"""Processor module will be in charge of converting the Google Threat Intelligence feeds reports into STIX2.1 SDO report entities.
This module will also handle the conversion of embedded entities from the reports, like locations and identities.

The processed entities will be send into a broker queue for further ingestion.
"""

import logging
from typing import TYPE_CHECKING, List, Optional

from connector.src.custom.interfaces.base_processor import BaseProcessor
from connector.src.custom.mappers.gti_reports.gti_report_relationship import (
    GTIReportRelationship,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_identity import (
    GTIReportToSTIXIdentity,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_location import (
    GTIReportToSTIXLocation,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_report import (
    GTIReportToSTIXReport,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_sector import (
    GTIReportToSTIXSector,
)
from connector.src.custom.meta.gti_reports.reports_meta import (
    FINAL_BROKER,
    REPORTS_BROKER,
    SENTINEL,
)
from connector.src.octi.pubsub import broker

if TYPE_CHECKING:
    from logger import Logger  # type: ignore
    from stix2.v21 import Identity, Location, MarkingDefinition, Report  # type: ignore


LOG_PREFIX = "[Process Reports]"


class ProcessReports(BaseProcessor):
    """The class will defined all the necessary methods to process Google Threat Intelligence feeds reports into STIX2.1 SDO report entities.
    This class will also handle the conversion of embedded entities from the reports, like locations and identities.
    """

    def __init__(
        self,
        organization: "Identity",
        tlp_marking: "MarkingDefinition",
        logger: Optional["Logger"] = None,
    ) -> None:
        """Initialize the class with a subscription to the broker queue receiving the reports.

        Args:
            organization (Identity): The organization of the reports.
            tlp_marking (MarkingDefinition): The TLP marking to use for the reports.
            logger (Optional[Logger], optional): The logger to use. Defaults to None.

        """
        self.queue = broker.subscribe(f"{REPORTS_BROKER}")
        self.organization = organization
        self.tlp_marking = tlp_marking
        self._logger = logger or logging.getLogger(__name__)

    async def process(self) -> bool:
        """Process the reports received from the broker queue.

        Returns:
            bool: True if the processing was successful, False otherwise.

        """
        while True:
            reports = await self.queue.get()
            try:
                if reports is SENTINEL:
                    break

                await self._convert_reports_to_stix21(reports)
            except Exception as e:
                self._logger.error(
                    f"{LOG_PREFIX} Error processing reports.", meta={"error": str(e)}
                )  # type: ignore[call-arg]
                return False
            finally:
                self.queue.task_done()
        return True

    async def _convert_reports_to_stix21(self, reports: List["Report"]) -> None:
        """Convert the reports into STIX2.1 SDO report pydantic model."""
        self._logger.info(
            f"{LOG_PREFIX} Converting {len(reports)} reports to STIX2.1 entities with associated identity, locations, and sectors."
        )
        total_entities = 0
        for report in reports:
            stix21_identity = await self._process_identity(report)
            stix21_locations = await self._process_locations(report)
            stix21_sectors = await self._process_sectors(report)
            stix21_report = await self._process_report(
                report, stix21_identity, stix21_sectors, stix21_locations
            )
            await self._process_relationships(report, stix21_report)
            total_entities += (
                len(stix21_report)
                + len(stix21_locations)
                + len(stix21_sectors)
                + len(stix21_identity)
            )

        self._logger.info(
            f"{LOG_PREFIX} Total entities processed in this batch: {total_entities}"
        )

    async def _process_identity(self, report: "Report") -> "Identity":
        """Process report into STIX identity."""
        try:
            self._logger.debug(
                f"{LOG_PREFIX} Processing to extract identity from report."
            )
            stix21_identity: "Identity" = GTIReportToSTIXIdentity(
                report, self.organization
            ).to_stix()
            await broker.publish(FINAL_BROKER, stix21_identity)
            self._logger.debug(
                f"{LOG_PREFIX} Identity extracted from report and pushed into broker for further ingestion."
            )
            return stix21_identity
        except Exception as ex:
            self._logger.error(
                f"{LOG_PREFIX} Error processing reports into identity.",
                meta={"error": str(ex)},
            )  # type: ignore[call-arg]
            raise

    async def _process_locations(self, report: "Report") -> List["Location"]:
        """Process report into STIX locations."""
        try:
            self._logger.debug(
                f"{LOG_PREFIX} Processing to extract locations from report."
            )
            stix21_locations: List["Location"] = GTIReportToSTIXLocation(
                report, self.organization, self.tlp_marking
            ).to_stix()
            await broker.publish(FINAL_BROKER, stix21_locations)
            self._logger.debug(
                f"{LOG_PREFIX} Locations extracted from report and pushed into broker for further ingestion."
            )
            return stix21_locations
        except Exception as ex:
            self._logger.error(
                f"{LOG_PREFIX} Error processing reports into location.",
                meta={"error": str(ex)},
            )  # type: ignore[call-arg]
            raise

    async def _process_sectors(self, report: "Report") -> List["Identity"]:
        """Process report into STIX sectors."""
        try:
            self._logger.debug(
                f"{LOG_PREFIX} Processing to extract sectors from report."
            )
            stix21_sectors: List["Identity"] = GTIReportToSTIXSector(
                report, self.organization, self.tlp_marking
            ).to_stix()
            await broker.publish(FINAL_BROKER, stix21_sectors)
            self._logger.debug(
                f"{LOG_PREFIX} Sectors extracted from report and pushed into broker for further ingestion."
            )
            return stix21_sectors
        except Exception as ex:
            self._logger.error(
                f"{LOG_PREFIX} Error processing reports into sector.",
                meta={"error": str(ex)},
            )  # type: ignore[call-arg]
            raise

    async def _process_report(
        self,
        report: "Report",
        stix21_identity: "Identity",
        stix21_sectors: List["Identity"],
        stix21_locations: List["Location"],
    ) -> "Report":
        """Process GTI report into STIX report."""
        try:
            self._logger.debug(f"{LOG_PREFIX} Processing report into STIX report.")
            stix21_report: "Report" = GTIReportToSTIXReport(
                report,
                self.organization,
                self.tlp_marking,
                stix21_identity,
                stix21_sectors,
                stix21_locations,
            ).to_stix()
            await broker.publish(FINAL_BROKER, stix21_report)
            self._logger.debug(
                f"{LOG_PREFIX} Report processed into STIX report and pushed into broker for further ingestion."
            )
            return stix21_report
        except Exception as ex:
            self._logger.error(
                f"{LOG_PREFIX} Error processing GTI report into STIX report.",
                meta={"error": str(ex)},
            )  # type: ignore[call-arg]
            raise

    async def _process_relationships(
        self, report: "Report", stix21_report: "Report"
    ) -> None:
        """Process report relationships."""
        try:
            self._logger.debug(f"{LOG_PREFIX} Processing report relationships.")
            stix21_relationships = GTIReportRelationship(
                report, self.organization, self.tlp_marking, stix21_report.id
            ).to_stix()
            await broker.publish(FINAL_BROKER, stix21_relationships)
            self._logger.debug(
                f"{LOG_PREFIX} Report relationships processed and pushed into broker for further ingestion."
            )
        except Exception as ex:
            self._logger.error(
                f"{LOG_PREFIX} Error processing report relationships.",
                meta={"error": str(ex)},
            )  # type: ignore[call-arg]
            raise
