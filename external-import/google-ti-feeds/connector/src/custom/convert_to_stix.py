"""Convert to STIX - Extracted convert-related methods from orchestrator."""

import logging
from typing import Any, Dict, List, Literal, Optional, cast

from connector.src.custom.configs.converter_configs import (
    CONVERTER_CONFIGS,
)
from connector.src.utils.converters import GenericConverterFactory
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)

LOG_PREFIX = "[Converters]"


class ConvertToSTIX:
    """Convert to STIX for handling conversion operations."""

    def __init__(self, config: Any, logger: logging.Logger, tlp_level: str):
        """Initialize Convert to STIX."""
        self.config = config
        self.logger = logger
        self.tlp_level = tlp_level.lower()
        self.organization = self._create_organization()
        self.tlp_marking = self._create_tlp_marking()
        self.converter_factory = self._create_converter_factory()

    def _create_converter_factory(self) -> GenericConverterFactory:
        """Create and configure the converter factory with all configurations.

        Returns:
            Configured GenericConverterFactory instance

        """
        global_dependencies = {
            "organization": self.organization,
            "tlp_marking": self.tlp_marking,
        }

        factory = GenericConverterFactory(
            global_dependencies=global_dependencies,
            logger=self.logger,
        )

        for entity_type, config in CONVERTER_CONFIGS.items():
            factory.register_config(entity_type, config)
            self.logger.debug(
                f"{LOG_PREFIX} Registered converter config for {entity_type}"
            )

        return factory

    def _create_organization(self) -> OrganizationAuthor:
        """Create the organization identity object.

        Returns:
            Identity: The organization identity object

        """
        organization = OrganizationAuthor(
            name="Google Threat Intelligence",
            description="Google Threat Intelligence provides information on the latest threats.",
            contact_information="https://gtidocs.virustotal.com",
            organization_type="vendor",
            reliability=None,
            aliases=["GTI"],
        )

        self.logger.debug(f"{LOG_PREFIX} Created organization identity")
        return organization

    def _create_tlp_marking(self) -> TLPMarking:
        """Create the TLP marking definition object.

        Returns:
            MarkingDefinition: The TLP marking definition object

        """
        tlp_level = self.tlp_level.lower()
        normalized_level = tlp_level.lower()

        if normalized_level not in (
            "white",
            "green",
            "amber",
            "amber+strict",
            "red",
        ):
            normalized_level = "amber"
            self.logger.warning(
                f"{LOG_PREFIX} Invalid TLP level '{tlp_level}', defaulting to 'amber'"
            )

        tlp_literal = cast(
            Literal["white", "green", "amber", "amber+strict", "red"],
            normalized_level,
        )

        tlp_marking = TLPMarking(level=tlp_literal)

        self.logger.debug(
            f"{LOG_PREFIX} Created TLP marking with level: {normalized_level}"
        )
        return tlp_marking

    def convert_report_to_stix(self, report_data: Any) -> List[Any]:
        """Convert report to location, identity, and report STIX objects.

        Args:
            report_data: GTIReportData object from fetcher

        Returns:
            List of STIX entities (location, identity, report)

        """
        try:
            converter = self.converter_factory.create_converter_by_name("reports")
            stix_entities = converter.convert_single(report_data)

            if not isinstance(stix_entities, list):
                stix_entities = [stix_entities]

            self.logger.debug(
                f"{LOG_PREFIX} Converted report to {len(stix_entities)} STIX entities"
            )
            return stix_entities

        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Failed to convert report to STIX: {str(e)}"
            )
            return []

    def convert_threat_actor_to_stix(self, threat_actor_data: Any) -> List[Any]:
        """Convert threat actor to location, identity, and threat actor STIX objects.

        Args:
            threat_actor_data: GTIThreatActorData object from fetcher

        Returns:
            List of STIX entities (location, identity, threat_actor)

        """
        try:
            converter = self.converter_factory.create_converter_by_name("threat_actor")
            stix_entities = converter.convert_single(threat_actor_data)

            if not isinstance(stix_entities, list):
                stix_entities = [stix_entities]

            self.logger.debug(
                f"{LOG_PREFIX} Converted threat actor to {len(stix_entities)} STIX entities"
            )
            return stix_entities

        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Failed to convert threat actor to STIX: {str(e)}"
            )
            return []

    def convert_malware_family_to_stix(self, malware_family_data: Any) -> List[Any]:
        """Convert malware family to location, identity, and malware STIX objects.

        Args:
            malware_family_data: GTIMalwareFamilyData object from fetcher

        Returns:
            List of STIX entities (location, identity, malware)

        """
        try:
            converter = self.converter_factory.create_converter_by_name(
                "malware_family"
            )
            stix_entities = converter.convert_single(malware_family_data)

            if not isinstance(stix_entities, list):
                stix_entities = [stix_entities]

            self.logger.debug(
                f"{LOG_PREFIX} Converted malware family to {len(stix_entities)} STIX entities"
            )
            return stix_entities

        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Failed to convert malware family to STIX: {str(e)}"
            )
            return []

    def convert_subentities_to_stix(
        self, subentities: Dict[str, List[Any]], main_entity: Optional[str] = None
    ) -> List[Any]:
        """Convert each subentity to STIX format.

        Args:
            subentities: Dictionary mapping entity types to lists of entities
            main_entity: Type of the main entity

        Returns:
            List of converted STIX objects

        """
        all_stix_entities = []
        _prefix = ""
        if main_entity:
            _prefix = f"{main_entity}_"

        for entity_type, entities in subentities.items():
            if not entities:
                continue

            try:
                converter = self.converter_factory.create_converter_by_name(
                    f"{_prefix}{entity_type}"
                )
                stix_entities = converter.convert_multiple(entities)
                all_stix_entities.extend(stix_entities)
                self.logger.debug(
                    f"{LOG_PREFIX} Converted {len(stix_entities)} {entity_type} to STIX"
                )

            except Exception as e:
                self.logger.error(
                    f"{LOG_PREFIX} Failed to convert {entity_type} to STIX: {str(e)}"
                )

        return all_stix_entities

    def convert_subentities_to_stix_with_linking(
        self,
        subentities: Dict[str, List[Any]],
        main_entity: str,
        main_entities: List[Any],
    ) -> Optional[List[Any]]:
        """Convert each subentity to STIX format with report linking.

        Args:
            subentities: Dictionary mapping entity types to lists of entities
            main_entity: The main entity type
            main_entities: List containing the main entity STIX object

        Returns:
            List of converted STIX objects

        """
        all_stix_entities = self.convert_subentities_to_stix(subentities, main_entity)

        self.logger.debug(
            f"{LOG_PREFIX} Converted sub-entities with {main_entity} linking"
        )

        return all_stix_entities
