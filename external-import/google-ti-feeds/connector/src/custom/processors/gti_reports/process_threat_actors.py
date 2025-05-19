"""Processor module will be in charge of converting the Google Threat Intelligence feeds threat actors into STIX2.1 SDO intrusion set entities.
This module will also handle the relationships between intrusion sets and reports.

The processed entities will be sent into a broker queue for further ingestion.
"""

import asyncio
import logging
from typing import TYPE_CHECKING, List, Optional

from connector.src.custom.interfaces.base_processor import BaseProcessor
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_report import (
    GTIReportToSTIXReport,
)
from connector.src.custom.mappers.gti_reports.gti_threat_actor_to_stix_intrusion_set import (
    GTIThreatActorToSTIXIntrusionSet,
)
from connector.src.custom.meta.gti_reports.reports_meta import (
    EVENT_MAP,
    FINAL_BROKER,
    SENTINEL,
    THREAT_ACTORS_BROKER,
)
from connector.src.octi.pubsub import broker

if TYPE_CHECKING:
    from connector.src.custom.models.gti_reports.gti_report_model import GTIReportData
    from connector.src.custom.models.gti_reports.gti_threat_actor_model import (
        GTIThreatActorData,
    )
    from logger import Logger  # type: ignore
    from stix2.v21 import Identity, IntrusionSet, MarkingDefinition  # type: ignore


LOG_PREFIX = "[Process Threat Actors]"


class ProcessThreatActors(BaseProcessor):
    """The class will define all the necessary methods to process Google Threat Intelligence feeds threat actors into STIX2.1 SDO intrusion set entities.
    This class will also handle the relationships between intrusion sets and reports.
    """

    def __init__(
        self,
        organization: "Identity",
        tlp_marking: "MarkingDefinition",
        logger: Optional["Logger"] = None,
    ) -> None:
        """Initialize the class with a subscription to the broker queue receiving the threat actors.

        Args:
            organization (Identity): The organization of the reports.
            tlp_marking (MarkingDefinition): The TLP marking to use for the reports.
            logger (Optional[Logger], optional): The logger to use. Defaults to None.

        """
        self.queue = broker.subscribe(f"{THREAT_ACTORS_BROKER}")
        self.organization = organization
        self.tlp_marking = tlp_marking
        self._logger = logger or logging.getLogger(__name__)

    async def process(self) -> bool:
        """Process the threat actors received from the broker queue.

        Returns:
            bool: True if the processing was successful, False otherwise.

        """
        while True:
            data = await self.queue.get()
            try:
                if data is SENTINEL:
                    break

                report_data, threat_actors = data

                await self._convert_threat_actors_to_stix21(report_data, threat_actors)
            except Exception as e:
                self._logger.error(
                    f"{LOG_PREFIX} Error processing threat actors.",
                    meta={"error": str(e)},
                )  # type: ignore[call-arg]
                return False
            finally:
                self.queue.task_done()
        return True

    async def _convert_threat_actors_to_stix21(
        self,
        report_data: "GTIReportData",
        threat_actors_data: List["GTIThreatActorData"],
    ) -> None:
        """Convert the threat actors into STIX2.1 SDO intrusion set pydantic models and update the report's object_refs.

        Args:
            report_data: The report data associated with the threat actors.
            threat_actors_data: The threat actors data to convert.

        """
        try:
            self._logger.info(
                f"{LOG_PREFIX} Converting threat actors to STIX2.1 entities and updating associated report."
            )

            stix21_intrusion_set_list = [
                self._process_threat_actor(threat_actor_data)
                for threat_actor_data in threat_actors_data
            ]
            if stix21_intrusion_set_list:
                stix21_intrusion_set_list_ids = [
                    intrusion_set.id for intrusion_set in stix21_intrusion_set_list
                ]
                updated_report = GTIReportToSTIXReport.add_object_refs(
                    report_data, stix21_intrusion_set_list_ids
                )

                while updated_report.id not in EVENT_MAP:
                    await asyncio.sleep(0.01)
                await EVENT_MAP[updated_report.id].wait()

                await broker.publish(FINAL_BROKER, stix21_intrusion_set_list)
                await broker.publish(FINAL_BROKER, updated_report)

                self._logger.info(
                    f"{LOG_PREFIX} Threat actors processed and relationships created with report: {report_data.attributes.name}."
                )
        except Exception as ex:
            self._logger.error(  # type: ignore[call-arg]
                f"{LOG_PREFIX} Error converting threat actor to STIX2.1.",
                meta={"error": str(ex)},
            )
            raise

    def _process_threat_actor(
        self, threat_actor_data: "GTIThreatActorData"
    ) -> "IntrusionSet":
        """Process threat actor into STIX intrusion set.

        Args:
            threat_actor_data: The threat actor data to process.

        Returns:
            IntrusionSet: The STIX intrusion set object.

        """
        try:
            self._logger.debug(
                f"{LOG_PREFIX} Processing threat actor into STIX intrusion set."
            )
            stix21_intrusion_set: "IntrusionSet" = GTIThreatActorToSTIXIntrusionSet(
                threat_actor_data, self.organization, self.tlp_marking
            ).to_stix()
            self._logger.debug(
                f"{LOG_PREFIX} Threat actor processed into STIX intrusion set."
            )
            return stix21_intrusion_set
        except Exception as ex:
            self._logger.error(  # type: ignore[call-arg]
                f"{LOG_PREFIX} Error processing threat actor into STIX intrusion set.",
                meta={"error": str(ex), "threat_actor_id": threat_actor_data.id},
            )
            raise
