"""Convert to STIX - Main entry point that delegates to specialized converters."""

import logging
from typing import Any

from connector.src.custom.convert_to_stix.convert_to_stix_shared import (
    ConvertToSTIXShared,
)
from connector.src.custom.convert_to_stix.malware.convert_to_stix_malware import (
    ConvertToSTIXMalware,
)
from connector.src.custom.convert_to_stix.report.convert_to_stix_report import (
    ConvertToSTIXReport,
)
from connector.src.custom.convert_to_stix.threat_actor.convert_to_stix_threat_actor import (
    ConvertToSTIXThreatActor,
)

LOG_PREFIX = "[ConvertToSTIX]"


class ConvertToSTIX:
    """Main converter that delegates to specialized converters."""

    def __init__(self, config: Any, logger: logging.Logger, tlp_level: str):
        """Initialize Convert to STIX with specialized converters."""
        self.config = config
        self.logger = logger
        self.tlp_level = tlp_level.lower()

        self.logger.info("Initializing converter", {"prefix": LOG_PREFIX})

        self.shared_converter = ConvertToSTIXShared(config, logger, tlp_level)

        self.report_converter = ConvertToSTIXReport(config, logger, tlp_level)
        self.threat_actor_converter = ConvertToSTIXThreatActor(
            config, logger, tlp_level
        )
        self.malware_converter = ConvertToSTIXMalware(config, logger, tlp_level)

        self.organization = self.shared_converter.organization
        self.tlp_marking = self.shared_converter.tlp_marking

    def convert_report_to_stix(self, report_data: Any) -> list[Any]:
        """Convert report to location, identity, and report STIX objects.

        Args:
            report_data: GTIReportData object from fetcher

        Returns:
            list of STIX entities (location, identity, report)

        """
        self.logger.debug("Starting report conversion", {"prefix": LOG_PREFIX})
        return self.report_converter.convert_report_to_stix(report_data)

    def convert_threat_actor_to_stix(self, threat_actor_data: Any) -> list[Any]:
        """Convert threat actor to location, identity, and threat actor STIX objects.

        Args:
            threat_actor_data: GTIThreatActorData object from fetcher

        Returns:
            list of STIX entities (location, identity, threat_actor)

        """
        self.logger.debug("Starting threat actor conversion", {"prefix": LOG_PREFIX})
        return self.threat_actor_converter.convert_threat_actor_to_stix(
            threat_actor_data
        )

    def convert_malware_family_to_stix(self, malware_family_data: Any) -> list[Any]:
        """Convert malware family to location, identity, and malware STIX objects.

        Args:
            malware_family_data: GTIMalwareFamilyData object from fetcher

        Returns:
            list of STIX entities (location, identity, malware)

        """
        self.logger.debug("Starting malware family conversion", {"prefix": LOG_PREFIX})
        return self.malware_converter.convert_malware_family_to_stix(
            malware_family_data
        )

    def convert_subentities_to_stix(
        self, subentities: dict[str, list[Any]], main_entity: str | None = None
    ) -> list[Any]:
        """Convert each subentity to STIX format.

        Args:
            subentities: dictionary mapping entity types to lists of entities
            main_entity: Type of the main entity

        Returns:
            list of converted STIX objects

        """
        return self.shared_converter.convert_subentities_to_stix(
            subentities, main_entity
        )

    def convert_subentities_to_stix_with_linking(
        self,
        subentities: dict[str, list[Any]],
        main_entity: str,
        main_entities: list[Any],
    ) -> list[Any] | None:
        """Convert each subentity to STIX format with linking.

        Args:
            subentities: dictionary mapping entity types to lists of entities
            main_entity: The main entity type
            main_entities: list containing the main entity STIX object

        Returns:
            list of converted STIX objects

        """
        return self.shared_converter.convert_subentities_to_stix_with_linking(
            subentities, main_entity, main_entities
        )
