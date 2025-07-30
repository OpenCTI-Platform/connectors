"""Base converter class with common functionality."""

import logging
from typing import Any, Dict, List, Literal, Optional, cast

from connector.src.custom.configs.converter_config import (
    CONVERTER_CONFIGS,
)
from connector.src.utils.converters import GenericConverterFactory
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)

LOG_PREFIX = "[BaseConverter]"


class BaseConvertToSTIX:
    """Base converter class with common functionality."""

    def __init__(self, config: Any, logger: logging.Logger, tlp_level: str):
        """Initialize Base Convert to STIX."""
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
                "Registered converter config",
                {"prefix": LOG_PREFIX, "entity_type": entity_type},
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

        self.logger.debug("Created organization identity", {"prefix": LOG_PREFIX})
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
                "Invalid TLP level, defaulting to 'amber'",
                {
                    "prefix": LOG_PREFIX,
                    "tlp_level": tlp_level,
                    "default_level": "amber",
                },
            )

        tlp_literal = cast(
            Literal["white", "green", "amber", "amber+strict", "red"],
            normalized_level,
        )

        tlp_marking = TLPMarking(level=tlp_literal)

        self.logger.debug(
            "Created TLP marking", {"prefix": LOG_PREFIX, "level": normalized_level}
        )
        return tlp_marking

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
                    "Converted entities to STIX",
                    {
                        "prefix": LOG_PREFIX,
                        "entity_count": len(stix_entities),
                        "entity_type": entity_type,
                    },
                )

            except Exception as e:
                self.logger.error(
                    "Failed to convert entity to STIX",
                    {"prefix": LOG_PREFIX, "entity_type": entity_type, "error": str(e)},
                )

        return all_stix_entities

    def convert_subentities_to_stix_with_linking(
        self,
        subentities: Dict[str, List[Any]],
        main_entity: str,
        main_entities: List[Any],
    ) -> Optional[List[Any]]:
        """Convert each subentity to STIX format with linking.

        Args:
            subentities: Dictionary mapping entity types to lists of entities
            main_entity: The main entity type
            main_entities: List containing the main entity STIX object

        Returns:
            List of converted STIX objects

        """
        all_stix_entities = self.convert_subentities_to_stix(subentities, main_entity)

        self.logger.debug(
            "Converted sub-entities with linking",
            {"prefix": LOG_PREFIX, "main_entity": main_entity},
        )

        return all_stix_entities
