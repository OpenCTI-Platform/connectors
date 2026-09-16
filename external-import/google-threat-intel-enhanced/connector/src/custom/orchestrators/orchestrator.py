"""Orchestrator for fetching and processing data.

This orchestrator handles the fetching, conversion, and processing data
using the proper fetchers/converters/batch processor pattern.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import pycti  # type: ignore
from connector.src.custom.client_api import ClientAPI
from connector.src.custom.configs import BATCH_PROCESSOR_CONFIG, GTIConfig
from connector.src.custom.convert_to_stix import ConvertToSTIX
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_report import (
    GTIReportToSTIXReport,
)
from connector.src.octi.work_manager import WorkManager
from connector.src.stix.v21.models.sros.relationship_model import RelationshipModel
from connector.src.utils.batch_processors import GenericBatchProcessor

LOG_PREFIX = "[Orchestrator]"

# IOC entity types that support threat actor enrichment
IOC_ENTITY_TYPES = ["domains", "files", "urls", "ip_addresses"]


class Orchestrator:
    """Orchestrator for fetching and processing data."""

    def __init__(
        self,
        work_manager: WorkManager,
        logger: logging.Logger,
        config: GTIConfig,
        tlp_level: str,
    ):
        """Initialize the Orchestrator.

        Args:
            work_manager: Work manager for handling OpenCTI work operations
            logger: Logger instance for logging
            config: Configuration object containing connector settings
            tlp_level: TLP level for the connector

        """
        self.work_manager = work_manager
        self.logger = logger
        self.config = config
        self.tlp_level = tlp_level.lower()

        self.logger.info(f"{LOG_PREFIX} API URL: {self.config.api_url}")
        self.logger.info(
            f"{LOG_PREFIX} Import start date: {self.config.import_start_date}"
        )

        self.client_api = ClientAPI(config, logger)
        self.converter = ConvertToSTIX(config, logger, tlp_level)
        self.batch_processor = self._create_batch_processor()
        self.current: int = 0
        self.enrich_iocs_with_threat_actors_and_malware = getattr(
            config, "enrich_iocs_with_threat_actors_and_malware", False
        )
        self.ioc_enrichment_threshold = getattr(
            config, "ioc_enrichment_threshold", 250
        )

    def _create_batch_processor(self) -> GenericBatchProcessor:
        """Create and configure the batch processor.

        Returns:
            Configured GenericBatchProcessor instance

        """
        return GenericBatchProcessor(
            work_manager=self.work_manager,
            config=BATCH_PROCESSOR_CONFIG,
            logger=self.logger,
        )

    def _enrich_iocs_with_report_context(
        self, subentities: Dict[str, List[Any]]
    ) -> tuple[Dict[str, Dict[str, List[str]]], Dict[str, Dict[str, List[str]]]]:
        """Enrich IOCs with threat actors and malware from the same report.

        Instead of querying each IOC separately, use the report's own threat_actors
        and malware_families to create relationships. If a report contains both
        IOCs and threat actors/malware, they are logically related.

        Args:
            subentities: Dictionary mapping entity types to lists of entities

        Returns:
            Tuple of (threat_actor_map, malware_map) where each maps
            entity_type -> {entity_id: [names]}

        """
        # Extract threat actor names from report's threat_actors subentities
        threat_actor_names: List[str] = []
        for ta in subentities.get("threat_actors", []):
            name = getattr(ta, "name", None)
            if not name and hasattr(ta, "attributes"):
                name = getattr(ta.attributes, "name", None)
            if name:
                threat_actor_names.append(name)

        # Extract malware names from report's malware_families subentities
        malware_names: List[str] = []
        for mf in subentities.get("malware_families", []):
            name = getattr(mf, "name", None)
            if not name and hasattr(mf, "attributes"):
                name = getattr(mf.attributes, "name", None)
            if name:
                malware_names.append(name)

        # De-duplicate
        threat_actor_names = list(dict.fromkeys(threat_actor_names))
        malware_names = list(dict.fromkeys(malware_names))

        # Build maps: associate ALL IOCs in this report with ALL threat actors/malware
        threat_actor_map: Dict[str, Dict[str, List[str]]] = {}
        malware_map: Dict[str, Dict[str, List[str]]] = {}

        for entity_type in IOC_ENTITY_TYPES:
            entities = subentities.get(entity_type, [])
            if not entities:
                continue

            if threat_actor_names:
                threat_actor_map[entity_type] = {}
            if malware_names:
                malware_map[entity_type] = {}

            for entity in entities:
                entity_id = getattr(entity, "id", None)
                if not entity_id:
                    continue

                # Associate this IOC with all threat actors from the report
                if threat_actor_names:
                    threat_actor_map[entity_type][entity_id] = threat_actor_names

                # Associate this IOC with all malware families from the report
                if malware_names:
                    malware_map[entity_type][entity_id] = malware_names

        return threat_actor_map, malware_map

    def _create_malware_vulnerability_relationships(
        self, subentities: Dict[str, List[Any]]
    ) -> List[RelationshipModel]:
        """Create Malware → Vulnerability 'exploits' relationships.

        When a report contains both malware families and vulnerabilities,
        create 'exploits' relationships to model that the malware exploits
        those CVEs.

        Args:
            subentities: Dictionary mapping entity types to lists of entities

        Returns:
            List of RelationshipModel objects

        """
        relationships: List[RelationshipModel] = []
        now = datetime.now(timezone.utc)

        # Extract malware names
        malware_names: List[str] = []
        for mf in subentities.get("malware_families", []):
            name = getattr(mf, "name", None)
            if not name and hasattr(mf, "attributes") and mf.attributes:
                name = getattr(mf.attributes, "name", None)
            if name:
                malware_names.append(name)

        # Extract vulnerability names (CVE IDs) from attributes.name
        vulnerability_names: List[str] = []
        for vuln in subentities.get("vulnerabilities", []):
            # Primary source: attributes.name (e.g., "CVE-2026-22769")
            if hasattr(vuln, "attributes") and vuln.attributes:
                name = getattr(vuln.attributes, "name", None)
                if name:
                    vulnerability_names.append(name)
                    continue
            
            # Fallback: parse from entity ID (e.g., "vulnerability--cve-2026-22769")
            vuln_id = getattr(vuln, "id", None)
            if vuln_id:
                vuln_id_lower = vuln_id.lower()
                if vuln_id_lower.startswith("vulnerability--cve-"):
                    cve_id = vuln_id[15:].upper()  # Remove "vulnerability--" prefix
                    vulnerability_names.append(cve_id)
                elif vuln_id_lower.startswith("cve-"):
                    vulnerability_names.append(vuln_id.upper())

        # De-duplicate
        malware_names = list(dict.fromkeys(malware_names))
        vulnerability_names = list(dict.fromkeys(vulnerability_names))

        if not malware_names or not vulnerability_names:
            return relationships

        self.logger.info(
            f"{LOG_PREFIX} Creating malware->vulnerability relationships: "
            f"{len(malware_names)} malware × {len(vulnerability_names)} vulnerabilities"
        )

        # Create relationships: Malware exploits Vulnerability
        for malware_name in malware_names:
            malware_stix_id = pycti.Malware.generate_id(name=malware_name)

            for vuln_name in vulnerability_names:
                vuln_stix_id = pycti.Vulnerability.generate_id(name=vuln_name)

                relationship = RelationshipModel(
                    relationship_type="exploits",
                    source_ref=malware_stix_id,
                    target_ref=vuln_stix_id,
                    created=now,
                    modified=now,
                    created_by_ref=self.converter.organization.id,
                    object_marking_refs=[self.converter.tlp_marking.id],
                )
                relationships.append(relationship)

        return relationships

    def _create_report_relationship_mesh(
        self,
        subentities: Dict[str, List[Any]],
        converted_stix: Optional[List[Any]] = None,
    ) -> List[RelationshipModel]:
        """Create IntrusionSet and Malware relationships for entities in a report.

        Creates relationships to tie threat actors to TTPs, malware, tools, vulnerabilities,
        and IOCs mentioned in the same report, modeling the threat actor's capabilities.

        Creates IntrusionSet (threat actor) relationships:
        - IntrusionSet "uses" Malware (actor uses malware)
        - IntrusionSet "uses" AttackPattern (actor uses techniques)
        - IntrusionSet "uses" Tool (actor uses tools like cURL, WHOAMI)
        - IntrusionSet "targets" Vulnerability (actor exploits CVE)
        - Indicator "indicates" IntrusionSet (IOC indicates threat actor)
        - Observable "related-to" IntrusionSet (SCO related to threat actor, persists after indicator expiry)

        Creates Malware relationships:
        - Indicator "indicates" Malware (IOC indicates malware)
        - Observable "related-to" Malware (SCO related to malware, persists after indicator expiry)

        Args:
            subentities: Dictionary mapping entity types to lists of entities
            converted_stix: Optional list of converted STIX objects (indicators, observables) to link

        Returns:
            List of RelationshipModel objects

        """
        relationships: List[RelationshipModel] = []
        now = datetime.now(timezone.utc)

        threat_actors = subentities.get("threat_actors", [])
        malware_families = subentities.get("malware_families", [])
        attack_techniques = subentities.get("attack_techniques", [])
        vulnerabilities = subentities.get("vulnerabilities", [])
        software_toolkits = subentities.get("software_toolkits", [])

        if not threat_actors:
            return relationships

        intrusion_set_rel_count = 0
        for ta in threat_actors:
            ta_name = None
            if hasattr(ta, "attributes") and ta.attributes:
                ta_name = getattr(ta.attributes, "name", None)
            if not ta_name:
                ta_name = getattr(ta, "name", None)

            if not ta_name:
                continue

            intrusion_set_id = pycti.IntrusionSet.generate_id(name=ta_name)

            # IntrusionSet "uses" Malware
            for mf in malware_families:
                mf_name = None
                if hasattr(mf, "attributes") and mf.attributes:
                    mf_name = getattr(mf.attributes, "name", None)
                if not mf_name:
                    mf_name = getattr(mf, "name", None)

                if mf_name:
                    malware_id = pycti.Malware.generate_id(name=mf_name)
                    relationship = RelationshipModel(
                        relationship_type="uses",
                        source_ref=intrusion_set_id,
                        target_ref=malware_id,
                        created=now,
                        modified=now,
                        created_by_ref=self.converter.organization.id,
                        object_marking_refs=[self.converter.tlp_marking.id],
                    )
                    relationships.append(relationship)
                    intrusion_set_rel_count += 1

            # IntrusionSet "uses" AttackPattern
            for at in attack_techniques:
                at_name = None
                x_mitre_id = None

                if hasattr(at, "attributes") and at.attributes:
                    at_name = getattr(at.attributes, "name", None)
                    info = getattr(at.attributes, "info", None)
                    if info:
                        x_mitre_id = getattr(info, "x_mitre_id", None)

                if not x_mitre_id and hasattr(at, "id"):
                    x_mitre_id = at.id

                if at_name:
                    attack_pattern_id = pycti.AttackPattern.generate_id(
                        name=at_name, x_mitre_id=x_mitre_id
                    )
                    relationship = RelationshipModel(
                        relationship_type="uses",
                        source_ref=intrusion_set_id,
                        target_ref=attack_pattern_id,
                        created=now,
                        modified=now,
                        created_by_ref=self.converter.organization.id,
                        object_marking_refs=[self.converter.tlp_marking.id],
                    )
                    relationships.append(relationship)
                    intrusion_set_rel_count += 1

            # IntrusionSet "targets" Vulnerability (actor exploits CVE)
            for vuln in vulnerabilities:
                vuln_name = None
                # Primary source: attributes.name (e.g., "CVE-2026-22769")
                if hasattr(vuln, "attributes") and vuln.attributes:
                    vuln_name = getattr(vuln.attributes, "name", None)

                # Fallback: parse from entity ID
                if not vuln_name and hasattr(vuln, "id"):
                    vuln_id = vuln.id
                    vuln_id_lower = vuln_id.lower()
                    if vuln_id_lower.startswith("vulnerability--cve-"):
                        vuln_name = vuln_id[15:].upper()
                    elif vuln_id_lower.startswith("cve-"):
                        vuln_name = vuln_id.upper()

                if vuln_name:
                    vulnerability_id = pycti.Vulnerability.generate_id(name=vuln_name)
                    relationship = RelationshipModel(
                        relationship_type="targets",
                        source_ref=intrusion_set_id,
                        target_ref=vulnerability_id,
                        created=now,
                        modified=now,
                        created_by_ref=self.converter.organization.id,
                        object_marking_refs=[self.converter.tlp_marking.id],
                    )
                    relationships.append(relationship)
                    intrusion_set_rel_count += 1

            # IntrusionSet "uses" Tool (actor uses software toolkits like cURL, WHOAMI)
            for tool in software_toolkits:
                tool_name = None
                if hasattr(tool, "attributes") and tool.attributes:
                    tool_name = getattr(tool.attributes, "name", None)
                if not tool_name:
                    tool_name = getattr(tool, "name", None)
                # Fallback: use the ID as the name
                if not tool_name and hasattr(tool, "id"):
                    tool_name = tool.id

                if tool_name:
                    tool_id = pycti.Tool.generate_id(name=tool_name)
                    relationship = RelationshipModel(
                        relationship_type="uses",
                        source_ref=intrusion_set_id,
                        target_ref=tool_id,
                        created=now,
                        modified=now,
                        created_by_ref=self.converter.organization.id,
                        object_marking_refs=[self.converter.tlp_marking.id],
                    )
                    relationships.append(relationship)
                    intrusion_set_rel_count += 1

        # Create IOC relationships to IntrusionSets and Malware
        # These persist even after indicators expire
        indicator_intrusion_count = 0
        observable_intrusion_count = 0
        indicator_malware_count = 0
        observable_malware_count = 0
        sco_types = {"ipv4-addr", "ipv6-addr", "domain-name", "url", "file"}

        # Build list of intrusion set IDs for IOC linking
        intrusion_set_ids = []
        for ta in threat_actors:
            ta_name = None
            if hasattr(ta, "attributes") and ta.attributes:
                ta_name = getattr(ta.attributes, "name", None)
            if not ta_name:
                ta_name = getattr(ta, "name", None)
            if ta_name:
                intrusion_set_ids.append(pycti.IntrusionSet.generate_id(name=ta_name))

        # Build list of malware IDs for IOC linking
        malware_ids = []
        for mf in malware_families:
            mf_name = None
            if hasattr(mf, "attributes") and mf.attributes:
                mf_name = getattr(mf.attributes, "name", None)
            if not mf_name:
                mf_name = getattr(mf, "name", None)
            if mf_name:
                malware_ids.append(pycti.Malware.generate_id(name=mf_name))

        if converted_stix and (intrusion_set_ids or malware_ids):
            for stix_obj in converted_stix:
                obj_type = getattr(stix_obj, "type", None)
                obj_id = getattr(stix_obj, "id", None)

                if not obj_id:
                    continue

                # Create Indicator "indicates" IntrusionSet/Malware relationships
                if obj_type == "indicator":
                    for is_id in intrusion_set_ids:
                        relationship = RelationshipModel(
                            relationship_type="indicates",
                            source_ref=obj_id,
                            target_ref=is_id,
                            created=now,
                            modified=now,
                            created_by_ref=self.converter.organization.id,
                            object_marking_refs=[self.converter.tlp_marking.id],
                        )
                        relationships.append(relationship)
                        indicator_intrusion_count += 1

                    for mw_id in malware_ids:
                        relationship = RelationshipModel(
                            relationship_type="indicates",
                            source_ref=obj_id,
                            target_ref=mw_id,
                            created=now,
                            modified=now,
                            created_by_ref=self.converter.organization.id,
                            object_marking_refs=[self.converter.tlp_marking.id],
                        )
                        relationships.append(relationship)
                        indicator_malware_count += 1

                # Create Observable "related-to" IntrusionSet/Malware relationships
                # These persist after indicators expire
                elif obj_type in sco_types:
                    for is_id in intrusion_set_ids:
                        relationship = RelationshipModel(
                            relationship_type="related-to",
                            source_ref=obj_id,
                            target_ref=is_id,
                            created=now,
                            modified=now,
                            created_by_ref=self.converter.organization.id,
                            object_marking_refs=[self.converter.tlp_marking.id],
                        )
                        relationships.append(relationship)
                        observable_intrusion_count += 1

                    for mw_id in malware_ids:
                        relationship = RelationshipModel(
                            relationship_type="related-to",
                            source_ref=obj_id,
                            target_ref=mw_id,
                            created=now,
                            modified=now,
                            created_by_ref=self.converter.organization.id,
                            object_marking_refs=[self.converter.tlp_marking.id],
                        )
                        relationships.append(relationship)
                        observable_malware_count += 1

        if relationships:
            ioc_summary = ""
            if indicator_intrusion_count or observable_intrusion_count or indicator_malware_count or observable_malware_count:
                ioc_summary = (
                    f", iocs: {indicator_intrusion_count} ind->actor, {observable_intrusion_count} obs->actor, "
                    f"{indicator_malware_count} ind->malware, {observable_malware_count} obs->malware"
                )
            self.logger.info(
                f"{LOG_PREFIX} Created {len(relationships)} report relationships "
                f"({len(threat_actors)} actors -> {len(malware_families)} malware, "
                f"{len(attack_techniques)} techniques, {len(software_toolkits)} tools, "
                f"{len(vulnerabilities)} vulnerabilities{ioc_summary})"
            )

        return relationships

    def _create_campaign_relationships(
        self,
        campaign_stix: List[Any],
        subentities: Dict[str, List[Any]],
        converted_stix: Optional[List[Any]] = None,
    ) -> List[RelationshipModel]:
        """Create relationships between campaign, threat actors, malware, TTPs, tools, CVEs, and IOCs.

        Creates Campaign relationships:
        - Campaign "attributed-to" IntrusionSet (threat actors)
        - Campaign "uses" Malware (malware families)
        - Campaign "uses" AttackPattern (attack techniques/TTPs)
        - Campaign "uses" Tool (software toolkits like cURL, WHOAMI)
        - Campaign "targets" Vulnerability (CVEs)
        - Indicator "indicates" Campaign (IOCs like files, domains, URLs, IPs)
        - Observable "related-to" Campaign (SCOs like ipv4-addr, domain-name, file, url)
          Note: Observable relationships persist after indicators expire

        Creates IntrusionSet (threat actor) relationships:
        - IntrusionSet "uses" Malware (actor uses malware)
        - IntrusionSet "uses" AttackPattern (actor uses techniques)
        - IntrusionSet "uses" Tool (actor uses tools)
        - IntrusionSet "targets" Vulnerability (actor exploits CVE)

        Args:
            campaign_stix: List of STIX objects containing the campaign
            subentities: Dictionary with 'threat_actors', 'malware_families', 'attack_techniques', 'software_toolkits', and 'vulnerabilities'
            converted_stix: Optional list of converted STIX objects (indicators, observables, etc.) to link to campaign

        Returns:
            List of RelationshipModel objects

        """
        relationships: List[RelationshipModel] = []
        now = datetime.now(timezone.utc)

        # Track relationship counts for debugging
        ta_rel_count = 0
        malware_rel_count = 0
        attack_rel_count = 0
        tool_rel_count = 0
        vuln_rel_count = 0

        # Find the campaign STIX object to get its ID
        campaign_id = None
        for entity in campaign_stix:
            if hasattr(entity, "type") and entity.type == "campaign":
                campaign_id = entity.id
                break

        if not campaign_id:
            return relationships

        # Create Campaign "attributed-to" IntrusionSet relationships
        threat_actors = subentities.get("threat_actors", [])
        for ta in threat_actors:
            ta_name = None
            if hasattr(ta, "attributes") and ta.attributes:
                ta_name = getattr(ta.attributes, "name", None)
            if not ta_name:
                ta_name = getattr(ta, "name", None)

            if ta_name:
                intrusion_set_id = pycti.IntrusionSet.generate_id(name=ta_name)
                relationship = RelationshipModel(
                    relationship_type="attributed-to",
                    source_ref=campaign_id,
                    target_ref=intrusion_set_id,
                    created=now,
                    modified=now,
                    created_by_ref=self.converter.organization.id,
                    object_marking_refs=[self.converter.tlp_marking.id],
                )
                relationships.append(relationship)
                ta_rel_count += 1
            else:
                self.logger.debug(
                    f"{LOG_PREFIX} Could not extract name from threat actor: "
                    f"id={getattr(ta, 'id', 'N/A')}, has_attributes={hasattr(ta, 'attributes')}"
                )

        # Create Campaign "uses" Malware relationships
        malware_families = subentities.get("malware_families", [])
        for mf in malware_families:
            mf_name = None
            if hasattr(mf, "attributes") and mf.attributes:
                mf_name = getattr(mf.attributes, "name", None)
            if not mf_name:
                mf_name = getattr(mf, "name", None)

            if mf_name:
                malware_id = pycti.Malware.generate_id(name=mf_name)
                relationship = RelationshipModel(
                    relationship_type="uses",
                    source_ref=campaign_id,
                    target_ref=malware_id,
                    created=now,
                    modified=now,
                    created_by_ref=self.converter.organization.id,
                    object_marking_refs=[self.converter.tlp_marking.id],
                )
                relationships.append(relationship)
                malware_rel_count += 1

        # Create Campaign "uses" AttackPattern relationships
        attack_techniques = subentities.get("attack_techniques", [])
        for at in attack_techniques:
            at_name = None
            x_mitre_id = None

            if hasattr(at, "attributes") and at.attributes:
                at_name = getattr(at.attributes, "name", None)
                # Get x_mitre_id from info if available
                info = getattr(at.attributes, "info", None)
                if info:
                    x_mitre_id = getattr(info, "x_mitre_id", None)

            # Fallback: use the entity ID as MITRE ID if x_mitre_id not found
            if not x_mitre_id and hasattr(at, "id"):
                x_mitre_id = at.id

            if at_name:
                attack_pattern_id = pycti.AttackPattern.generate_id(
                    name=at_name, x_mitre_id=x_mitre_id
                )
                relationship = RelationshipModel(
                    relationship_type="uses",
                    source_ref=campaign_id,
                    target_ref=attack_pattern_id,
                    created=now,
                    modified=now,
                    created_by_ref=self.converter.organization.id,
                    object_marking_refs=[self.converter.tlp_marking.id],
                )
                relationships.append(relationship)
                attack_rel_count += 1

        # Create Campaign "uses" Tool relationships
        software_toolkits = subentities.get("software_toolkits", [])
        for tool in software_toolkits:
            tool_name = None
            if hasattr(tool, "attributes") and tool.attributes:
                tool_name = getattr(tool.attributes, "name", None)
            if not tool_name:
                tool_name = getattr(tool, "name", None)
            # Fallback: use the ID as the name
            if not tool_name and hasattr(tool, "id"):
                tool_name = tool.id

            if tool_name:
                tool_id = pycti.Tool.generate_id(name=tool_name)
                relationship = RelationshipModel(
                    relationship_type="uses",
                    source_ref=campaign_id,
                    target_ref=tool_id,
                    created=now,
                    modified=now,
                    created_by_ref=self.converter.organization.id,
                    object_marking_refs=[self.converter.tlp_marking.id],
                )
                relationships.append(relationship)
                tool_rel_count += 1

        # Create Campaign "targets" Vulnerability relationships
        vulnerabilities = subentities.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            # Primary source: attributes.name (e.g., "CVE-2025-15556")
            vuln_name = None
            if hasattr(vuln, "attributes") and vuln.attributes:
                vuln_name = getattr(vuln.attributes, "name", None)

            # Fallback: parse from entity ID (e.g., "vulnerability--cve-2025-12345")
            if not vuln_name and hasattr(vuln, "id"):
                vuln_id = vuln.id
                vuln_id_lower = vuln_id.lower()
                if vuln_id_lower.startswith("vulnerability--cve-"):
                    vuln_name = vuln_id[15:].upper()  # Extract CVE-XXXX-XXXXX
                elif vuln_id_lower.startswith("cve-"):
                    vuln_name = vuln_id.upper()

            if vuln_name:
                vulnerability_id = pycti.Vulnerability.generate_id(name=vuln_name)
                relationship = RelationshipModel(
                    relationship_type="targets",
                    source_ref=campaign_id,
                    target_ref=vulnerability_id,
                    created=now,
                    modified=now,
                    created_by_ref=self.converter.organization.id,
                    object_marking_refs=[self.converter.tlp_marking.id],
                )
                relationships.append(relationship)
                vuln_rel_count += 1

        # Create IntrusionSet relationships to tie threat actors to TTPs, malware, and vulnerabilities
        # This creates relationships like: UNC6688 "uses" BEACON, UNC6688 "targets" CVE-2025-15556
        intrusion_set_rel_count = 0
        for ta in threat_actors:
            ta_name = None
            if hasattr(ta, "attributes") and ta.attributes:
                ta_name = getattr(ta.attributes, "name", None)
            if not ta_name:
                ta_name = getattr(ta, "name", None)

            if not ta_name:
                continue

            intrusion_set_id = pycti.IntrusionSet.generate_id(name=ta_name)

            # IntrusionSet "uses" Malware
            for mf in malware_families:
                mf_name = None
                if hasattr(mf, "attributes") and mf.attributes:
                    mf_name = getattr(mf.attributes, "name", None)
                if not mf_name:
                    mf_name = getattr(mf, "name", None)

                if mf_name:
                    malware_id = pycti.Malware.generate_id(name=mf_name)
                    relationship = RelationshipModel(
                        relationship_type="uses",
                        source_ref=intrusion_set_id,
                        target_ref=malware_id,
                        created=now,
                        modified=now,
                        created_by_ref=self.converter.organization.id,
                        object_marking_refs=[self.converter.tlp_marking.id],
                    )
                    relationships.append(relationship)
                    intrusion_set_rel_count += 1

            # IntrusionSet "uses" AttackPattern
            for at in attack_techniques:
                at_name = None
                x_mitre_id = None

                if hasattr(at, "attributes") and at.attributes:
                    at_name = getattr(at.attributes, "name", None)
                    info = getattr(at.attributes, "info", None)
                    if info:
                        x_mitre_id = getattr(info, "x_mitre_id", None)

                if not x_mitre_id and hasattr(at, "id"):
                    x_mitre_id = at.id

                if at_name:
                    attack_pattern_id = pycti.AttackPattern.generate_id(
                        name=at_name, x_mitre_id=x_mitre_id
                    )
                    relationship = RelationshipModel(
                        relationship_type="uses",
                        source_ref=intrusion_set_id,
                        target_ref=attack_pattern_id,
                        created=now,
                        modified=now,
                        created_by_ref=self.converter.organization.id,
                        object_marking_refs=[self.converter.tlp_marking.id],
                    )
                    relationships.append(relationship)
                    intrusion_set_rel_count += 1

            # IntrusionSet "targets" Vulnerability (actor exploits CVE)
            for vuln in vulnerabilities:
                vuln_name = None
                # Primary source: attributes.name (e.g., "CVE-2026-22769")
                if hasattr(vuln, "attributes") and vuln.attributes:
                    vuln_name = getattr(vuln.attributes, "name", None)

                # Fallback: parse from entity ID
                if not vuln_name and hasattr(vuln, "id"):
                    vuln_id = vuln.id
                    vuln_id_lower = vuln_id.lower()
                    if vuln_id_lower.startswith("vulnerability--cve-"):
                        vuln_name = vuln_id[15:].upper()
                    elif vuln_id_lower.startswith("cve-"):
                        vuln_name = vuln_id.upper()

                if vuln_name:
                    vulnerability_id = pycti.Vulnerability.generate_id(name=vuln_name)
                    relationship = RelationshipModel(
                        relationship_type="targets",
                        source_ref=intrusion_set_id,
                        target_ref=vulnerability_id,
                        created=now,
                        modified=now,
                        created_by_ref=self.converter.organization.id,
                        object_marking_refs=[self.converter.tlp_marking.id],
                    )
                    relationships.append(relationship)
                    intrusion_set_rel_count += 1

            # IntrusionSet "uses" Tool (actor uses software toolkits)
            for tool in software_toolkits:
                tool_name = None
                if hasattr(tool, "attributes") and tool.attributes:
                    tool_name = getattr(tool.attributes, "name", None)
                if not tool_name:
                    tool_name = getattr(tool, "name", None)
                if not tool_name and hasattr(tool, "id"):
                    tool_name = tool.id

                if tool_name:
                    tool_id = pycti.Tool.generate_id(name=tool_name)
                    relationship = RelationshipModel(
                        relationship_type="uses",
                        source_ref=intrusion_set_id,
                        target_ref=tool_id,
                        created=now,
                        modified=now,
                        created_by_ref=self.converter.organization.id,
                        object_marking_refs=[self.converter.tlp_marking.id],
                    )
                    relationships.append(relationship)
                    intrusion_set_rel_count += 1

        # Create Indicator "indicates" Campaign and Observable "related-to" Campaign relationships for IOCs
        # Extract indicators and observables from converted STIX objects and link them to the campaign
        # Observables are linked separately so IOC relationships persist even after indicators expire
        ioc_count = 0
        observable_count = 0
        sco_types = {"ipv4-addr", "ipv6-addr", "domain-name", "url", "file"}
        
        if converted_stix:
            for stix_obj in converted_stix:
                obj_type = getattr(stix_obj, "type", None)
                obj_id = getattr(stix_obj, "id", None)
                
                if not obj_id:
                    continue
                
                # Create Indicator "indicates" Campaign relationship
                if obj_type == "indicator":
                    relationship = RelationshipModel(
                        relationship_type="indicates",
                        source_ref=obj_id,
                        target_ref=campaign_id,
                        created=now,
                        modified=now,
                        created_by_ref=self.converter.organization.id,
                        object_marking_refs=[self.converter.tlp_marking.id],
                    )
                    relationships.append(relationship)
                    ioc_count += 1
                
                # Create Observable "related-to" Campaign relationship for SCOs
                # This preserves the IOC-Campaign link even after indicators expire
                elif obj_type in sco_types:
                    relationship = RelationshipModel(
                        relationship_type="related-to",
                        source_ref=obj_id,
                        target_ref=campaign_id,
                        created=now,
                        modified=now,
                        created_by_ref=self.converter.organization.id,
                        object_marking_refs=[self.converter.tlp_marking.id],
                    )
                    relationships.append(relationship)
                    observable_count += 1

        if relationships:
            self.logger.info(
                f"{LOG_PREFIX} Created {len(relationships)} campaign relationships: "
                f"threat_actors {ta_rel_count}/{len(threat_actors)}, "
                f"malware {malware_rel_count}/{len(malware_families)}, "
                f"attack_patterns {attack_rel_count}/{len(attack_techniques)}, "
                f"tools {tool_rel_count}/{len(software_toolkits)}, "
                f"vulnerabilities {vuln_rel_count}/{len(vulnerabilities)}, "
                f"indicators {ioc_count}, observables {observable_count}, "
                f"intrusion_set_links {intrusion_set_rel_count}"
            )
        else:
            # Log when no relationships were created but entities were provided
            total_entities = (
                len(threat_actors) + len(malware_families) + len(attack_techniques) +
                len(software_toolkits) + len(vulnerabilities)
            )
            if total_entities > 0:
                self.logger.warning(
                    f"{LOG_PREFIX} No campaign relationships created despite {total_entities} subentities"
                )

        return relationships

    def _update_report_with_object_refs(
        self,
        report_entities: List[Any],
        subentity_stix: Optional[List[Any]],
        additional_stix: Optional[List[Any]] = None
    ) -> List[Any]:
        """Update the report's object_refs with IDs from converted subentities.

        Uses GTIReportToSTIXReport.add_object_refs to add IOC and relationship
        IDs to the report's object_refs.

        Args:
            report_entities: List containing report-related STIX objects (identity, report, etc.)
            subentity_stix: List of converted subentity STIX objects (IOCs, relationships, etc.)
            additional_stix: Optional additional STIX objects to include in object_refs

        Returns:
            Updated list of report entities with the report containing proper object_refs

        """
        if not subentity_stix:
            return report_entities

        # Collect all object IDs from subentities
        object_ids: List[str] = []
        for obj in subentity_stix:
            if hasattr(obj, "id"):
                object_ids.append(obj.id)

        # Add additional objects (e.g., malware-vulnerability relationships)
        if additional_stix:
            for obj in additional_stix:
                if hasattr(obj, "id"):
                    object_ids.append(obj.id)

        if not object_ids:
            return report_entities

        # Find the report and update its object_refs using the existing method
        # Note: add_object_refs may return a NEW object if the original is immutable (STIX2)
        updated_entities = []
        for entity in report_entities:
            if hasattr(entity, "type") and entity.type == "report":
                # Get current refs count for logging
                current_refs = len(getattr(entity, "object_refs", []) or [])
                updated_report = GTIReportToSTIXReport.add_object_refs(object_ids, entity)
                new_refs = len(getattr(updated_report, "object_refs", []) or [])
                self.logger.info(
                    f"{LOG_PREFIX} Updated report object_refs: {current_refs} -> {new_refs} "
                    f"(added {len(object_ids)} refs from subentities)"
                )
                updated_entities.append(updated_report)
            else:
                updated_entities.append(entity)

        return updated_entities

    async def run(self, initial_state: Optional[Dict[str, Any]]) -> None:
        """Run the orchestrator.

        Args:
            initial_state: Initial state for the orchestrator

        """
        try:
            # Process reports if enabled
            if getattr(self.config, "import_reports", True):
                await self._process_reports(initial_state)

            # Process campaigns if enabled
            if getattr(self.config, "import_campaigns", False):
                await self._process_campaigns(initial_state)

            # Process standalone threat actors if enabled
            if getattr(self.config, "import_threat_actors", False):
                await self._process_threat_actors(initial_state)

            # Process standalone malware families if enabled
            if getattr(self.config, "import_malware_families", False):
                await self._process_malware_families(initial_state)

            # Process standalone vulnerabilities if enabled
            if getattr(self.config, "import_vulnerabilities", False):
                await self._process_vulnerabilities(initial_state)

        finally:
            self._flush_batch_processor()

    async def _process_campaigns(self, initial_state: Optional[Dict[str, Any]]) -> None:
        """Process campaigns from the API.

        Args:
            initial_state: Initial state for the processing

        """
        self.logger.info(f"{LOG_PREFIX} Starting campaign import")
        campaign_count = 0

        async for gti_campaigns in self.client_api.fetch_campaigns(initial_state):
            total_campaigns = len(gti_campaigns)
            for campaign_idx, campaign in enumerate(gti_campaigns):
                try:
                    campaign_stix = self.converter.convert_campaign_to_stix(campaign)

                    if not campaign_stix:
                        self.logger.warning(
                            f"{LOG_PREFIX} ({campaign_idx + 1}/{total_campaigns}) Failed to convert campaign"
                        )
                        continue

                    # Fetch associated threat actors and malware families
                    subentity_ids = await self.client_api.fetch_campaign_subentities(
                        campaign.id
                    )
                    
                    # Fetch detailed data for subentities
                    subentities_detailed: Dict[str, List[Any]] = {}
                    if subentity_ids:
                        rel_summary = ", ".join(
                            [f"{k}: {len(v)}" for k, v in subentity_ids.items()]
                        )
                        self.logger.info(
                            f"{LOG_PREFIX} ({campaign_idx + 1}/{total_campaigns}) Campaign relationships: {{{rel_summary}}}"
                        )
                        subentities_detailed = await self.client_api.fetch_campaign_subentity_details(
                            subentity_ids
                        )

                    # Convert subentities to STIX
                    subentity_stix: List[Any] = []
                    if subentities_detailed:
                        subentity_stix = self.converter.convert_campaign_subentities_to_stix(
                            subentities_detailed
                        )

                    # Create relationships between campaign and threat actors/malware/IOCs
                    campaign_relationships = self._create_campaign_relationships(
                        campaign_stix, subentities_detailed, subentity_stix
                    )

                    # Combine all entities
                    all_entities = campaign_stix + subentity_stix + campaign_relationships

                    campaign_count += 1
                    
                    # Build entity type summary for debugging victimology
                    entity_types: Dict[str, int] = {}
                    for entity in all_entities:
                        entity_type = getattr(entity, "type", None)
                        if entity_type:
                            entity_types[entity_type] = entity_types.get(entity_type, 0) + 1
                    entities_summary = ", ".join([f"{k}: {v}" for k, v in entity_types.items()])
                    
                    # Get campaign name for logging
                    campaign_name = "Unknown"
                    if campaign.attributes and campaign.attributes.name:
                        campaign_name = campaign.attributes.name
                    
                    self.logger.info(
                        f"{LOG_PREFIX} ({campaign_idx + 1}/{total_campaigns}) Ingested campaign '{campaign_name}' - {len(all_entities)} STIX entities {{{entities_summary}}}"
                    )

                    # Check if we need to flush before adding
                    if (
                        self.batch_processor.get_current_batch_size()
                        + len(all_entities) + 2  # +2 for org and marking
                    ) >= self.batch_processor.config.batch_size:
                        self.logger.info(
                            f"{LOG_PREFIX} Need to Flush before adding next campaign to preserve consistency of the bundle"
                        )
                        self.batch_processor.flush()

                    # Add organization and marking, then campaign entities
                    self.batch_processor.add_item(self.converter.organization)
                    self.batch_processor.add_item(self.converter.tlp_marking)
                    self.batch_processor.add_items(all_entities)

                except Exception as e:
                    self.logger.error(
                        f"{LOG_PREFIX} ({campaign_idx + 1}/{total_campaigns}) Error processing campaign: {str(e)}"
                    )

        self.logger.info(f"{LOG_PREFIX} Campaign import completed. Processed {campaign_count} campaigns")

    async def _process_threat_actors(self, initial_state: Optional[Dict[str, Any]]) -> None:
        """Process standalone threat actors from the API.

        Args:
            initial_state: Initial state for the processing

        """
        self.logger.info(f"{LOG_PREFIX} Starting standalone threat actor import")
        threat_actor_count = 0

        async for gti_threat_actors in self.client_api.fetch_threat_actors(initial_state):
            total_threat_actors = len(gti_threat_actors)
            for ta_idx, threat_actor in enumerate(gti_threat_actors):
                try:
                    ta_stix = self.converter.convert_threat_actor_to_stix(threat_actor)

                    # Get threat actor name for logging
                    ta_name = "Unknown"
                    if threat_actor.attributes and threat_actor.attributes.name:
                        ta_name = threat_actor.attributes.name

                    if not ta_stix:
                        self.logger.warning(
                            f"{LOG_PREFIX} ({ta_idx + 1}/{total_threat_actors}) Failed to convert threat actor '{ta_name}'"
                        )
                        continue

                    threat_actor_count += 1
                    
                    # Build entity type summary like reports
                    entity_types: Dict[str, int] = {}
                    for entity in ta_stix:
                        entity_type = getattr(entity, "type", None)
                        if entity_type:
                            entity_types[entity_type] = entity_types.get(entity_type, 0) + 1
                    entities_summary = ", ".join([f"{k}: {v}" for k, v in entity_types.items()])
                    
                    self.logger.info(
                        f"{LOG_PREFIX} ({ta_idx + 1}/{total_threat_actors}) Ingested standalone threat actor '{ta_name}' - {len(ta_stix)} STIX entities {{{entities_summary}}}"
                    )

                    # Check if we need to flush before adding
                    if (
                        self.batch_processor.get_current_batch_size()
                        + len(ta_stix) + 2  # +2 for org and marking
                    ) >= self.batch_processor.config.batch_size:
                        self.logger.info(
                            f"{LOG_PREFIX} Need to Flush before adding next threat actor to preserve consistency of the bundle"
                        )
                        self.batch_processor.flush()

                    # Add organization and marking, then threat actor entities
                    self.batch_processor.add_item(self.converter.organization)
                    self.batch_processor.add_item(self.converter.tlp_marking)
                    self.batch_processor.add_items(ta_stix)

                except Exception as e:
                    self.logger.error(
                        f"{LOG_PREFIX} ({ta_idx + 1}/{total_threat_actors}) Error processing threat actor: {str(e)}"
                    )

        self.logger.info(f"{LOG_PREFIX} Threat actor import completed. Processed {threat_actor_count} threat actors")

    async def _process_malware_families(self, initial_state: Optional[Dict[str, Any]]) -> None:
        """Process standalone malware families from the API.

        Args:
            initial_state: Initial state for the processing

        """
        self.logger.info(f"{LOG_PREFIX} Starting standalone malware family import")
        malware_count = 0

        async for gti_malware in self.client_api.fetch_malware_families(initial_state):
            total_malware = len(gti_malware)
            for mw_idx, malware in enumerate(gti_malware):
                try:
                    malware_stix = self.converter.convert_malware_to_stix(malware)

                    if not malware_stix:
                        self.logger.warning(
                            f"{LOG_PREFIX} ({mw_idx + 1}/{total_malware}) Failed to convert malware family"
                        )
                        continue

                    malware_count += 1
                    self.logger.info(
                        f"{LOG_PREFIX} ({mw_idx + 1}/{total_malware}) Converted malware family to {len(malware_stix)} STIX entities"
                    )

                    # Check if we need to flush before adding
                    if (
                        self.batch_processor.get_current_batch_size()
                        + len(malware_stix) + 2  # +2 for org and marking
                    ) >= self.batch_processor.config.batch_size:
                        self.logger.info(
                            f"{LOG_PREFIX} Need to Flush before adding next malware family to preserve consistency of the bundle"
                        )
                        self.batch_processor.flush()

                    # Add organization and marking, then malware entities
                    self.batch_processor.add_item(self.converter.organization)
                    self.batch_processor.add_item(self.converter.tlp_marking)
                    self.batch_processor.add_items(malware_stix)

                except Exception as e:
                    self.logger.error(
                        f"{LOG_PREFIX} ({mw_idx + 1}/{total_malware}) Error processing malware family: {str(e)}"
                    )

        self.logger.info(f"{LOG_PREFIX} Malware family import completed. Processed {malware_count} malware families")

    async def _process_vulnerabilities(self, initial_state: Optional[Dict[str, Any]]) -> None:
        """Process standalone vulnerabilities from the API.

        Args:
            initial_state: Initial state for the processing

        """
        self.logger.info(f"{LOG_PREFIX} Starting standalone vulnerability import")
        vulnerability_count = 0

        async for gti_vulnerabilities in self.client_api.fetch_vulnerabilities(initial_state):
            total_vulnerabilities = len(gti_vulnerabilities)
            for vuln_idx, vulnerability in enumerate(gti_vulnerabilities):
                try:
                    vuln_stix = self.converter.convert_vulnerability_to_stix(vulnerability)

                    if not vuln_stix:
                        self.logger.warning(
                            f"{LOG_PREFIX} ({vuln_idx + 1}/{total_vulnerabilities}) Failed to convert vulnerability"
                        )
                        continue

                    vulnerability_count += 1
                    self.logger.info(
                        f"{LOG_PREFIX} ({vuln_idx + 1}/{total_vulnerabilities}) Converted vulnerability to {len(vuln_stix)} STIX entities"
                    )

                    # Check if we need to flush before adding
                    if (
                        self.batch_processor.get_current_batch_size()
                        + len(vuln_stix) + 2  # +2 for org and marking
                    ) >= self.batch_processor.config.batch_size:
                        self.logger.info(
                            f"{LOG_PREFIX} Need to Flush before adding next vulnerability to preserve consistency of the bundle"
                        )
                        self.batch_processor.flush()

                    # Add organization and marking, then vulnerability entities
                    self.batch_processor.add_item(self.converter.organization)
                    self.batch_processor.add_item(self.converter.tlp_marking)
                    self.batch_processor.add_items(vuln_stix)

                except Exception as e:
                    self.logger.error(
                        f"{LOG_PREFIX} ({vuln_idx + 1}/{total_vulnerabilities}) Error processing vulnerability: {str(e)}"
                    )

        self.logger.info(f"{LOG_PREFIX} Vulnerability import completed. Processed {vulnerability_count} vulnerabilities")

    async def _process_reports(self, initial_state: Optional[Dict[str, Any]]) -> None:
        """Process reports from the API.

        Args:
            initial_state: Initial state for the processing

        """
        async for gti_reports in self.client_api.fetch_reports(initial_state):
            total_reports = len(gti_reports)
            for report_idx, report in enumerate(gti_reports):
                report_entities = self.converter.convert_report_to_stix(report)
                subentities_ids = await self.client_api.fetch_subentities_ids(
                    report.id
                )
                rel_summary = ", ".join(
                    [f"{k}: {len(v)}" for k, v in subentities_ids.items()]
                )
                if len(rel_summary) > 0:
                    self.logger.info(
                        f"{LOG_PREFIX} ({report_idx + 1}/{total_reports}) Found relationships {{{rel_summary}}}"
                    )
                # Count IOCs to determine if we should enrich
                ioc_count = sum(
                    len(subentities_ids.get(ioc_type, []))
                    for ioc_type in IOC_ENTITY_TYPES
                )
                # Skip enrichment if IOC count exceeds threshold (0 = disabled)
                skip_ioc_enrichment = (
                    self.ioc_enrichment_threshold > 0
                    and ioc_count > self.ioc_enrichment_threshold
                )
                if skip_ioc_enrichment:
                    self.logger.warning(
                        f"{LOG_PREFIX} ({report_idx + 1}/{total_reports}) Skipping IOC enrichment: {ioc_count} IOCs exceeds threshold of {self.ioc_enrichment_threshold}"
                    )
                    # Remove IOC types from subentities_ids to skip fetching their details
                    subentities_ids_filtered = {
                        k: v for k, v in subentities_ids.items() if k not in IOC_ENTITY_TYPES
                    }
                else:
                    subentities_ids_filtered = subentities_ids

                subentities_detailed = (
                    await self.client_api.fetch_subentity_details(subentities_ids_filtered)
                )

                # Enrich IOCs with threat actor and malware from report context
                threat_actor_map: Dict[str, Dict[str, List[str]]] = {}
                malware_map: Dict[str, Dict[str, List[str]]] = {}
                if self.enrich_iocs_with_threat_actors_and_malware and not skip_ioc_enrichment:
                    self.logger.info(
                        f"{LOG_PREFIX} ({report_idx + 1}/{total_reports}) Enriching IOCs with threat actor and malware relationships from report"
                    )
                    threat_actor_map, malware_map = self._enrich_iocs_with_report_context(
                        subentities_detailed
                    )
                    if any(threat_actor_map.values()) or any(malware_map.values()):
                        # Count unique threat actors and malware from the report
                        unique_ta = set()
                        for ta_map in threat_actor_map.values():
                            for ta_ids in ta_map.values():
                                unique_ta.update(ta_ids)
                        unique_malware = set()
                        for m_map in malware_map.values():
                            for m_ids in m_map.values():
                                unique_malware.update(m_ids)
                        self.logger.info(
                            f"{LOG_PREFIX} ({report_idx + 1}/{total_reports}) Linking IOCs to {len(unique_ta)} threat actors and {len(unique_malware)} malware families"
                        )

                subentity_stix = (
                    self.converter.convert_subentities_to_stix_with_linking(
                        subentities_detailed, report_entities, threat_actor_map, malware_map
                    )
                )

                # Create Malware → Vulnerability "exploits" relationships
                # when both exist in the same report
                malware_vuln_relationships = self._create_malware_vulnerability_relationships(
                    subentities_detailed
                )

                # Create IntrusionSet (threat actor) relationship mesh
                # linking actors to malware, TTPs, vulnerabilities, and IOCs in the report
                intrusion_set_relationships = self._create_report_relationship_mesh(
                    subentities_detailed, subentity_stix
                )

                # Combine all relationship types
                all_relationships = malware_vuln_relationships + intrusion_set_relationships

                # Update report's object_refs with IOC and relationship IDs
                # (STIX2 Report objects are immutable, so this creates a new report)
                report_entities = self._update_report_with_object_refs(
                    report_entities, subentity_stix, all_relationships
                )

                all_entities = report_entities + (subentity_stix or []) + all_relationships
                entity_types: Dict[str, int] = {}
                for entity in all_entities:
                    entity_type = getattr(entity, "type", None)
                    if entity_type:
                        entity_types[entity_type] = (
                            entity_types.get(entity_type, 0) + 1
                        )
                entities_summary = ", ".join(
                    [f"{k}: {v}" for k, v in entity_types.items()]
                )
                self.logger.info(
                    f"{LOG_PREFIX} ({report_idx + 1}/{total_reports}) Converted to {len(all_entities)} STIX entities {{{entities_summary}}}"
                )
                if (
                    self.batch_processor.get_current_batch_size()
                    + len(all_entities)
                ) >= self.batch_processor.config.batch_size:
                    self.logger.info(
                        f"{LOG_PREFIX} Need to Flush before adding next items to preserve consistency of the bundle"
                    )
                    self.batch_processor.flush()
                self._update_report_index_inplace()
                self.batch_processor.add_item(self.converter.organization)
                self.batch_processor.add_item(self.converter.tlp_marking)
                self.batch_processor.add_items(all_entities)

    def _update_report_index_inplace(self) -> None:
        """Update the work message to reflect current report progress."""

        def replacer(match: Any) -> str:
            actual_total = self.client_api.real_total_reports or 0

            if actual_total == 0:
                return "(~ 0/0 reports)"

            self.current += 1
            return f"(~ {self.current}/{actual_total} reports)"

        pattern = r"\(~ (\d+)/(\d+) reports\)"
        template = self.batch_processor.config.work_name_template
        self.batch_processor.config.work_name_template = re.sub(
            pattern, replacer, template
        )

    def _flush_batch_processor(self) -> None:
        """Flush any remaining items in the batch processor."""
        try:
            work_id = self.batch_processor.flush()
            if work_id:
                self.logger.info(
                    f"{LOG_PREFIX} Batch processor: Flushed remaining items"
                )
            self.batch_processor.update_final_state()
        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Failed to flush batch processor: {str(e)}")
