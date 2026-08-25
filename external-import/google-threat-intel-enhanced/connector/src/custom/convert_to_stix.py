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
            "indicator_scoring": getattr(self.config, "indicator_scoring", "gti_derived"),
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
        organization: Identity = organization_model.to_stix2_object()  # type: ignore[assignment]

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
        self, subentities: Dict[str, List[Any]], 
        threat_actor_map: Optional[Dict[str, Dict[str, List[str]]]] = None,
        malware_map: Optional[Dict[str, Dict[str, List[str]]]] = None
    ) -> List[Any]:
        """Convert each subentity to STIX format.

        Args:
            subentities: Dictionary mapping entity types to lists of entities
            threat_actor_map: Optional dict mapping entity_type -> {entity_id: [threat_actor_ids]}
            malware_map: Optional dict mapping entity_type -> {entity_id: [malware_ids]}

        Returns:
            List of converted STIX objects

        """
        all_stix_entities = []
        threat_actor_map = threat_actor_map or {}
        malware_map = malware_map or {}

        # Log current context state
        from connector.src.custom.configs.converter_configs import get_report_context
        context_report = get_report_context()
        self.logger.info(
            f"{LOG_PREFIX} Converting subentities. Report context: "
            f"{'SET (id=' + str(getattr(context_report, 'id', 'unknown')) + ')' if context_report else 'NOT SET'}"
        )

        for entity_type, entities in subentities.items():
            if not entities:
                continue

            try:
                converter = self.converter_factory.create_converter_by_name(entity_type)
                
                # For IOC types, pass threat actor and malware IDs to each entity conversion
                if entity_type in threat_actor_map or entity_type in malware_map:
                    entity_threat_actors = threat_actor_map.get(entity_type, {})
                    entity_malware = malware_map.get(entity_type, {})
                    for entity in entities:
                        entity_id = getattr(entity, "id", None)
                        threat_actor_ids = entity_threat_actors.get(str(entity_id), []) if entity_id else []
                        malware_ids = entity_malware.get(str(entity_id), []) if entity_id else []
                        stix_entity = converter.convert_single(
                            entity, threat_actor_ids=threat_actor_ids, malware_ids=malware_ids
                        )
                        if stix_entity:
                            if isinstance(stix_entity, list):
                                all_stix_entities.extend(stix_entity)
                            else:
                                all_stix_entities.append(stix_entity)
                else:
                    stix_entities = converter.convert_multiple(entities)
                    all_stix_entities.extend(stix_entities)
                
                self.logger.info(
                    f"{LOG_PREFIX} Converted {len(entities)} {entity_type} -> {len(all_stix_entities)} total STIX objects"
                )

            except Exception as e:
                self.logger.error(
                    f"{LOG_PREFIX} Failed to convert {entity_type} to STIX: {str(e)}"
                )

        return all_stix_entities

    def convert_subentities_to_stix_with_linking(
        self, subentities: Dict[str, List[Any]], report_entities: List[Any], 
        threat_actor_map: Optional[Dict[str, Dict[str, List[str]]]] = None,
        malware_map: Optional[Dict[str, Dict[str, List[str]]]] = None
    ) -> Optional[List[Any]]:
        """Convert each subentity to STIX format with report linking.

        Args:
            subentities: Dictionary mapping entity types to lists of entities
            report_entities: List containing the report STIX object
            threat_actor_map: Optional dict mapping entity_type -> {entity_id: [threat_actor_ids]}
            malware_map: Optional dict mapping entity_type -> {entity_id: [malware_ids]}

        Returns:
            List of converted STIX objects

        """
        # Log what we're looking for
        self.logger.info(
            f"{LOG_PREFIX} Looking for report in {len(report_entities)} entities: "
            f"{[type(e).__name__ + '/' + str(getattr(e, 'type', 'no-type')) for e in report_entities]}"
        )
        
        report_obj = None
        for entity in report_entities:
            if hasattr(entity, "type") and entity.type == "report":
                report_obj = entity
                break

        if not report_obj:
            self.logger.warning(
                f"{LOG_PREFIX} No report object found for linking, falling back to standard conversion"
            )
            return self.convert_subentities_to_stix(subentities, threat_actor_map, malware_map)

        try:
            set_report_context(report_obj)

            all_stix_entities = self.convert_subentities_to_stix(subentities, threat_actor_map, malware_map)

            self.logger.debug(
                f"{LOG_PREFIX} Converted sub-entities with report linking to {getattr(report_obj, 'id', 'unknown')}"
            )

            return all_stix_entities

        finally:
            clear_report_context()

    def convert_campaign_to_stix(self, campaign_data: Any) -> List[Any]:
        """Convert a campaign to STIX campaign object.

        Args:
            campaign_data: GTICampaignData object from fetcher

        Returns:
            List of STIX entities (campaign, sectors, locations, relationships)

        """
        try:
            converter = self.converter_factory.create_converter_by_name("campaigns")
            stix_entity = converter.convert_single(campaign_data)

            if not isinstance(stix_entity, list):
                stix_entity = [stix_entity]

            # Debug: Log entity types being created
            entity_types = {}
            for entity in stix_entity:
                etype = getattr(entity, "type", type(entity).__name__)
                entity_types[etype] = entity_types.get(etype, 0) + 1
            types_summary = ", ".join([f"{k}: {v}" for k, v in entity_types.items()])
            
            self.logger.debug(
                f"{LOG_PREFIX} Converted campaign to {len(stix_entity)} STIX entities: {{{types_summary}}}"
            )
            return stix_entity

        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Failed to convert campaign to STIX: {str(e)}"
            )
            return []

    def convert_threat_actor_to_stix(self, threat_actor_data: Any) -> List[Any]:
        """Convert a standalone threat actor to STIX intrusion set object.

        Args:
            threat_actor_data: GTIThreatActorData object from fetcher

        Returns:
            List of STIX entities (intrusion set)

        """
        try:
            converter = self.converter_factory.create_converter_by_name("threat_actors")
            stix_entity = converter.convert_single(threat_actor_data)

            if not isinstance(stix_entity, list):
                stix_entity = [stix_entity]

            self.logger.debug(
                f"{LOG_PREFIX} Converted threat actor to {len(stix_entity)} STIX entities"
            )
            return stix_entity

        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Failed to convert threat actor to STIX: {str(e)}"
            )
            return []

    def convert_malware_to_stix(self, malware_data: Any) -> List[Any]:
        """Convert a standalone malware family to STIX malware object.

        Args:
            malware_data: GTIMalwareFamilyData object from fetcher

        Returns:
            List of STIX entities (malware)

        """
        try:
            converter = self.converter_factory.create_converter_by_name("malware_families")
            stix_entity = converter.convert_single(malware_data)

            if not isinstance(stix_entity, list):
                stix_entity = [stix_entity]

            self.logger.debug(
                f"{LOG_PREFIX} Converted malware to {len(stix_entity)} STIX entities"
            )
            return stix_entity

        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Failed to convert malware to STIX: {str(e)}"
            )
            return []

    def convert_vulnerability_to_stix(self, vulnerability_data: Any) -> List[Any]:
        """Convert a standalone vulnerability to STIX vulnerability object.

        Args:
            vulnerability_data: GTIVulnerabilityData object from fetcher

        Returns:
            List of STIX entities (vulnerability)

        """
        try:
            converter = self.converter_factory.create_converter_by_name("vulnerabilities")
            stix_entity = converter.convert_single(vulnerability_data)

            if not isinstance(stix_entity, list):
                stix_entity = [stix_entity]

            self.logger.debug(
                f"{LOG_PREFIX} Converted vulnerability to {len(stix_entity)} STIX entities"
            )
            return stix_entity

        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Failed to convert vulnerability to STIX: {str(e)}"
            )
            return []

    def convert_campaign_subentities_to_stix(
        self, subentities: Dict[str, List[Any]]
    ) -> List[Any]:
        """Convert campaign subentities to STIX objects.

        Converts all campaign-related entities including:
        - threat_actors → IntrusionSet
        - malware_families → Malware
        - attack_techniques → AttackPattern
        - software_toolkits → Tool
        - vulnerabilities → Vulnerability
        - domains → DomainName (SCO) + Indicator
        - files → File (SCO) + Indicator
        - urls → URL (SCO) + Indicator
        - ip_addresses → IPv4Address/IPv6Address (SCO) + Indicator

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

                self.logger.info(
                    f"{LOG_PREFIX} Converted {len(entities)} campaign {entity_type} -> "
                    f"{len(stix_entities)} STIX objects"
                )

            except Exception as e:
                self.logger.error(
                    f"{LOG_PREFIX} Failed to convert campaign {entity_type} to STIX: {str(e)}"
                )

        return all_stix_entities
