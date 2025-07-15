"""Convert to STIX - Extracted convert-related methods from orchestrator."""

import logging
from typing import Any, Dict, List, Literal, Optional, cast

from connector.src.custom.configs.converter_configs import (
    CONVERTER_CONFIGS,
    clear_report_context,
    set_report_context,
)
from connector.src.utils.converters import GenericConverterFactory
from stix2.v21 import Identity, MarkingDefinition  # type: ignore

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

    def _create_organization(self) -> Identity:
        """Create the organization identity object.

        Returns:
            Identity: The organization identity object

        """
        from connector.src.stix.octi.models.identity_organization_model import (
            OctiOrganizationModel,
        )

        organization_model = OctiOrganizationModel.create(
            name="Google Threat Intelligence",
            description="Google Threat Intelligence provides information on the latest threats.",
            contact_information="https://gtidocs.virustotal.com",
            organization_type="vendor",
            reliability=None,
            aliases=["GTI"],
        )
        organization = organization_model.to_stix2_object()

        self.logger.debug(f"{LOG_PREFIX} Created organization identity")
        return organization

    def _create_tlp_marking(self) -> MarkingDefinition:
        """Create the TLP marking definition object.

        Returns:
            MarkingDefinition: The TLP marking definition object

        """
        from connector.src.stix.octi.models.tlp_marking_model import TLPMarkingModel

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

        tlp_marking = TLPMarkingModel(level=tlp_literal).to_stix2_object()

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

    def convert_subentities_to_stix(
        self, subentities: Dict[str, List[Any]]
    ) -> List[Any]:
        """Convert each subentity to STIX format.

        Args:
            subentities: Dictionary mapping entity types to lists of entities

        Returns:
            List of converted STIX objects

        """
        all_stix_entities = []

        for entity_type, entities in subentities.items():
            if not entities:
                continue

            try:
                converter = self.converter_factory.create_converter_by_name(entity_type)
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
        self, subentities: Dict[str, List[Any]], report_entities: List[Any]
    ) -> Optional[List[Any]]:
        """Convert each subentity to STIX format with report linking.

        Args:
            subentities: Dictionary mapping entity types to lists of entities
            report_entities: List containing the report STIX object

        Returns:
            List of converted STIX objects

        """
        report_obj = None
        for entity in report_entities:
            if hasattr(entity, "type") and entity.type == "report":
                report_obj = entity
                break

        if not report_obj:
            self.logger.warning(
                f"{LOG_PREFIX} No report object found for linking, falling back to standard conversion"
            )
            return self.convert_subentities_to_stix(subentities)

        try:
            set_report_context(report_obj)

            all_stix_entities = self.convert_subentities_to_stix(subentities)

            self.logger.debug(
                f"{LOG_PREFIX} Converted sub-entities with report linking to {getattr(report_obj, 'id', 'unknown')}"
            )

            return all_stix_entities

        finally:
            clear_report_context()
