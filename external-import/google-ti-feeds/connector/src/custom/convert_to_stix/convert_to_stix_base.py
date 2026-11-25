"""Base converter class with common functionality."""

import logging
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any, Literal, cast

from connector.src.custom.configs import (
    GTIConfig,
)
from connector.src.custom.configs.converter_config import (
    CONVERTER_CONFIGS,
)
from connector.src.custom.configs.gti_config_common import IOC_SUBENTITY_TYPES
from connector.src.custom.mappers.relationship_reasons import (
    co_occurrence_reason,
    display_name,
    optional_reason,
    set_relationship_descriptions,
)
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.stix.v21.models.sros.relationship_model import RelationshipModel
from connector.src.utils.converters import GenericConverterFactory
from connectors_sdk.models import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)

LOG_PREFIX = "[BaseConverter]"

IOC_OBSERVABLE_STIX_TYPES = ("domain-name", "file", "url", "ipv4-addr", "ipv6-addr")

IOC_MAPPER_OPTIONS = (
    "indicator_scoring",
    "indicator_min_verdict",
    "extended_descriptions",
    "ioc_tags_as_labels",
)

# GTIConfig options forwarded to the mappers, by sub-entity type.
MAPPER_OPTIONS: dict[str, tuple[str, ...]] = {
    "malware_families": ("enable_malware_aliases", "extended_descriptions"),
    "threat_actors": ("enable_threat_actor_aliases",),
    "vulnerabilities": ("extended_descriptions",),
    **dict.fromkeys(IOC_SUBENTITY_TYPES, IOC_MAPPER_OPTIONS),
    "ip_addresses": (*IOC_MAPPER_OPTIONS, "ip_link_to_asn", "ip_link_to_country"),
}


def ioc_data_by_value(subentities: Mapping[str, list[Any]]) -> dict[str, Any]:
    """Index the GTI IOCs of a report or campaign by the value naming their STIX objects.

    Domains, IPs and files by their GTI ID (the value or SHA-256), URLs by URL.
    """
    index: dict[str, Any] = {}
    for ioc_type in IOC_SUBENTITY_TYPES:
        for ioc in subentities.get(ioc_type) or []:
            url = getattr(getattr(ioc, "attributes", None), "url", None)
            key = url if ioc_type == "urls" and url else getattr(ioc, "id", None)
            if key:
                index[key] = ioc
    return index


INTRUSION_SET_CAPABILITY_RELATIONSHIP_TYPES = {
    ("intrusion-set", "malware"): "uses",
    ("intrusion-set", "tool"): "uses",
    ("intrusion-set", "attack-pattern"): "uses",
    ("intrusion-set", "vulnerability"): "targets",
}


def ioc_threat_relationship_types(
    threat_types: Iterable[str],
) -> dict[tuple[str, str], str]:
    """Return the co-occurrence rules linking IOCs to the given threat types.

    Indicators get 'indicates', observables get 'related-to'.
    """
    return {
        (ioc_type, threat_type): (
            "indicates" if ioc_type == "indicator" else "related-to"
        )
        for ioc_type in ("indicator", *IOC_OBSERVABLE_STIX_TYPES)
        for threat_type in threat_types
    }


class BaseConvertToSTIX:
    """Base converter class with common functionality."""

    def __init__(self, config: GTIConfig, logger: logging.Logger, tlp_level: str):
        """Initialize Base Convert to STIX."""
        self.config = config
        self.logger = logger
        self.tlp_level = tlp_level.lower()
        set_relationship_descriptions(
            getattr(config, "relationship_descriptions", False) is True
        )
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

    def mapper_options(self, entity_type: str) -> dict[str, Any]:
        """Return the configuration options forwarded to the mapper of an entity type.

        Args:
            entity_type: GTI sub-entity type, e.g. 'malware_families'.

        Returns:
            Mapper keyword arguments, for the options present in the configuration.
            Threat actor mappers also get the connector logger, to warn about
            dates they cannot parse.

        """
        options: dict[str, Any] = {
            option: getattr(self.config, option)
            for option in MAPPER_OPTIONS.get(entity_type, ())
            if hasattr(self.config, option)
        }
        if entity_type == "threat_actors":
            options["logger"] = self.logger
        return options

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
        self, subentities: dict[str, list[Any]], main_entity: str | None = None
    ) -> list[Any]:
        """Convert each subentity to STIX format.

        Args:
            subentities: dictionary mapping entity types to lists of entities
            main_entity: Type of the main entity

        Returns:
            list of converted STIX objects

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
                    f"{_prefix}{entity_type}",
                    additional_dependencies=self.mapper_options(entity_type),
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
                self.logger.warning(
                    "Failed to convert entity to STIX",
                    {"prefix": LOG_PREFIX, "entity_type": entity_type, "error": str(e)},
                )

        return all_stix_entities

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
        all_stix_entities = self.convert_subentities_to_stix(subentities, main_entity)

        self.logger.debug(
            "Converted sub-entities with linking",
            {"prefix": LOG_PREFIX, "main_entity": main_entity},
        )

        return all_stix_entities

    def create_co_occurrence_relationships(
        self,
        stix_objects: list[Any],
        relationship_types: Mapping[tuple[str, str], str],
        container: Any | None = None,
        ioc_data: Mapping[str, Any] | None = None,
    ) -> list[RelationshipModel]:
        """Link entities converted for the same report or campaign.

        Every object of a source type is linked to every object of its target type.
        The description states that the link is inferred, and from which container.

        Args:
            stix_objects: Converted sub-entities of a single report or campaign.
            relationship_types: Relationship type keyed by (source, target) STIX type.
            container: The report or campaign, named in the descriptions.
            ioc_data: GTI IOCs by value (see `ioc_data_by_value`): the GTI
                evidence of an IOC supporting a link is added to its description.

        Returns:
            The created relationships.

        """
        objects_by_type: dict[str, list[Any]] = defaultdict(list)
        for obj in stix_objects:
            obj_type = getattr(obj, "type", None)
            if obj_type:
                objects_by_type[obj_type].append(obj)

        now = datetime.now(timezone.utc)
        relationships = [
            OctiRelationshipModel.create(
                relationship_type=relationship_type,
                source_ref=source.id,
                target_ref=target.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                description=optional_reason(
                    co_occurrence_reason(
                        source,
                        target,
                        container,
                        (ioc_data or {}).get(display_name(source)),
                    )
                ),
                created=now,
                modified=now,
            )
            for (source_type, target_type), relationship_type in (
                relationship_types.items()
            )
            for source in objects_by_type.get(source_type, [])
            for target in objects_by_type.get(target_type, [])
        ]

        self.logger.debug(
            "Created co-occurrence relationships",
            {"prefix": LOG_PREFIX, "count": len(relationships)},
        )
        return relationships
