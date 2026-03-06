"""
Custom STIX 2.1 to MISP converter

This module provides comprehensive conversion from STIX 2.1 bundles to MISP events,
including full support for all OpenCTI entity types, observables, indicators,
and sightings, with advanced galaxy mapping.
"""

import re
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

from pymisp import MISPEvent, MISPObject, MISPSighting


class STIXtoMISPConverter:
    """Converts STIX 2.1 bundles to MISP events with comprehensive entity support"""

    # MISP galaxy type mappings for OpenCTI entities
    # Based on actual MISP galaxies from https://github.com/MISP/misp-galaxy
    ENTITY_TO_GALAXY_MAPPING = {
        # Threat actors and adversaries
        # Note: In MISP, intrusion sets (APT groups) are part of the threat-actor galaxy
        # MISP also has mitre-enterprise-attack-intrusion-set but threat-actor is more commonly used
        "threat-actor": "threat-actor",
        "intrusion-set": "threat-actor",  # Maps to threat-actor in MISP (could also be mitre-enterprise-attack-intrusion-set)
        # Malware and tools
        "malware": "malware",
        "tool": "tool",
        # Attack patterns - MITRE ATT&CK
        "attack-pattern": "mitre-attack-pattern",
        # Campaigns
        "campaign": "mitre-campaign",
        # Course of action
        "course-of-action": "mitre-course-of-action",
        # Infrastructure
        "infrastructure": "infrastructure",
        # Incidents
        "incident": "incident",
        "x-opencti-incident": "incident",
        "x-opencti-case-incident": "incident",
        # Data sources/components (MITRE)
        "x-mitre-data-source": "mitre-data-source",
        "x-mitre-data-component": "mitre-data-component",
        # Note: identity and location are handled by special logic
        # Note: vulnerability is handled by special logic for CVE detection
        # Note: OpenCTI entities like channel, event, narrative, capability
        #       are standard STIX types but don't have direct MISP galaxy mappings
    }

    # STIX pattern to MISP attribute type mapping
    PATTERN_TYPE_MAPPING = {
        # Network indicators
        "ipv4-addr": "ip-dst",
        "ipv4-addr:value": "ip-dst",
        "ipv6-addr": "ip-dst",
        "ipv6-addr:value": "ip-dst",
        "domain-name": "domain",
        "domain-name:value": "domain",
        "hostname": "hostname",
        "hostname:value": "hostname",
        "url": "url",
        "url:value": "url",
        "email-addr": "email-src",
        "email-addr:value": "email-src",
        "mac-addr": "mac-address",
        "mac-addr:value": "mac-address",
        "autonomous-system": "AS",
        # File indicators
        "file:hashes.MD5": "md5",
        "file:hashes.'MD5'": "md5",
        "file:hashes.SHA-1": "sha1",
        "file:hashes.'SHA-1'": "sha1",
        "file:hashes.SHA1": "sha1",
        "file:hashes.'SHA1'": "sha1",
        "file:hashes.SHA-256": "sha256",
        "file:hashes.'SHA-256'": "sha256",
        "file:hashes.SHA256": "sha256",
        "file:hashes.'SHA256'": "sha256",
        "file:hashes.SHA-512": "sha512",
        "file:hashes.'SHA-512'": "sha512",
        "file:hashes.SHA512": "sha512",
        "file:hashes.'SHA512'": "sha512",
        "file:hashes.SSDEEP": "ssdeep",
        "file:hashes.'SSDEEP'": "ssdeep",
        "file:name": "filename",
        "file:size": "size-in-bytes",
        "file:mime_type": "mime-type",
        # Process indicators
        "process:pid": "process-pid",
        "process:name": "process-name",
        "process:command_line": "command-line",
        # Registry indicators
        "windows-registry-key:key": "regkey",
        "windows-registry-value-type": "regkey|value",
        # Certificate indicators
        "x509-certificate:serial_number": "x509-fingerprint-sha1",
        # User account
        "user-account:account_login": "username",
        # Mutex
        "mutex:name": "mutex",
        # Network traffic
        "network-traffic:src_port": "port",
        "network-traffic:dst_port": "port",
        "network-traffic:protocols": "protocol",
        # Software
        "software:name": "filename",
        "software:vendor": "text",
        "software:version": "version",
    }

    # Observable to MISP object mapping
    OBSERVABLE_TO_MISP_OBJECT = {
        "file": "file",
        "network-traffic": "network-connection",
        "process": "process",
        "windows-registry-key": "registry-key",
        "x509-certificate": "x509",
        "user-account": "user-account",
        "email-message": "email",
        "mutex": "mutex",
        "software": "software",
        "domain-name": "domain-ip",
        "ipv4-addr": "ip-port",
        "ipv6-addr": "ip-port",
        "url": "url",
        "autonomous-system": "asn",
        "mac-addr": "mac-address",
        "directory": "directory",
        "artifact": "artifact",
    }

    def __init__(self, helper, config):
        """
        Initialize the converter

        :param helper: OpenCTI connector helper
        :param config: Connector configuration
        """
        self.helper = helper
        self.config = config
        # Track added attribute values to prevent duplicates
        self.added_attributes = {}

    def _should_add_attribute(self, attr_type: str, value: str) -> bool:
        """
        Check if an attribute should be added (avoiding duplicates)

        :param attr_type: MISP attribute type
        :param value: Attribute value
        :return: True if attribute should be added, False if it's a duplicate
        """
        # Create a key for tracking (type and value combination)
        key = f"{attr_type}:{value}"

        if key in self.added_attributes:
            # Already added this attribute
            return False

        # Mark as added
        self.added_attributes[key] = True
        return True

    def convert_bundle_to_event(
        self, stix_bundle: Dict, custom_uuid: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Convert a STIX 2.1 bundle to a MISP event

        :param stix_bundle: STIX 2.1 bundle dictionary
        :param custom_uuid: Optional custom UUID for the MISP event
        :return: MISP event dictionary or None
        """
        try:
            # Reset attribute tracking for new conversion
            self.added_attributes = {}

            # Validate bundle
            if not stix_bundle or "objects" not in stix_bundle:
                self.helper.connector_logger.error(
                    "Invalid STIX bundle: missing objects"
                )
                return None

            # Find the main container (report, grouping, case-incident, etc.)
            container = self._find_container(stix_bundle)
            if not container:
                self.helper.connector_logger.warning("No container found in bundle")
                return None

            # Create MISP event (pass bundle for score calculation)
            misp_event = self._create_base_event(container, custom_uuid, stix_bundle)

            # Process all objects in the bundle
            processed_ids = set()
            for stix_obj in stix_bundle.get("objects", []):
                if stix_obj.get("id") in processed_ids:
                    continue
                processed_ids.add(stix_obj.get("id"))

                obj_type = stix_obj.get("type", "").lower()

                # Skip the container itself and marking definitions
                if obj_type in [
                    "report",
                    "grouping",
                    "case-incident",
                    "case-rfi",
                    "case-rft",
                    "x-opencti-case-incident",
                    "x-opencti-case-rfi",
                    "x-opencti-case-rft",
                    "marking-definition",
                    "relationship",
                ]:
                    continue

                # Process based on object type
                if obj_type == "indicator":
                    self._process_indicator(misp_event, stix_obj)
                elif obj_type in self.OBSERVABLE_TO_MISP_OBJECT:
                    self._process_observable(misp_event, stix_obj)
                elif obj_type == "hostname":
                    # Process hostname observables specially
                    self._process_observable(misp_event, stix_obj)
                elif obj_type == "observed-data":
                    self._process_observed_data(misp_event, stix_obj, stix_bundle)
                elif obj_type == "sighting":
                    self._process_sighting(misp_event, stix_obj, stix_bundle)
                elif obj_type == "identity":
                    # Skip identities that are just references (creator orgs)
                    # They're already handled in event metadata
                    continue
                elif obj_type in self.ENTITY_TO_GALAXY_MAPPING:
                    self._process_entity(misp_event, stix_obj)
                elif obj_type.startswith("x-opencti-") or obj_type.startswith(
                    "x-mitre-"
                ):
                    self._process_custom_entity(misp_event, stix_obj)
                elif obj_type in [
                    "channel",
                    "event",
                    "narrative",
                    "capability",
                    "grouping",
                    "note",
                    "opinion",
                    "data-source",
                    "data-component",
                    "task",
                ]:
                    # Standard OpenCTI entities without galaxy mappings
                    self._process_opencti_standard_entity(misp_event, stix_obj)
                else:
                    # Process as generic entity with tags
                    self._process_generic_entity(misp_event, stix_obj)

            # Add OpenCTI tags
            self._add_opencti_tags(misp_event, container)

            # Convert to dictionary
            return misp_event.to_dict()

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error converting STIX bundle to MISP: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return None

    def _find_container(self, stix_bundle: Dict) -> Optional[Dict]:
        """Find the main container object in the bundle"""
        container_types = [
            "report",
            "grouping",
            "case-incident",
            "case-rfi",
            "case-rft",
            "x-opencti-case-incident",
            "x-opencti-case-rfi",
            "x-opencti-case-rft",
        ]

        for obj in stix_bundle.get("objects", []):
            if obj.get("type", "").lower() in container_types:
                return obj

        return None

    def _calculate_threat_level(
        self, stix_bundle: Optional[Dict], container: Dict
    ) -> int:
        """
        Calculate MISP threat level based on scores from indicators/observables

        :param stix_bundle: STIX bundle containing all objects
        :param container: Container object
        :return: MISP threat level ID (1=High, 2=Medium, 3=Low, 4=Undefined)
        """
        if not stix_bundle:
            # Fallback to confidence-based calculation
            confidence = container.get("confidence", 50)
            if confidence >= 80:
                return 1  # High
            elif confidence >= 60:
                return 2  # Medium
            elif confidence >= 30:
                return 3  # Low
            else:
                return 4  # Undefined

        # Collect scores from indicators and observables
        scores = []
        for obj in stix_bundle.get("objects", []):
            obj_type = obj.get("type", "").lower()

            # Check if it's an indicator or observable type
            is_indicator = obj_type == "indicator"
            is_observable = obj_type in self.OBSERVABLE_TO_MISP_OBJECT or obj_type in [
                "observed-data",
                "ipv4-addr",
                "ipv6-addr",
                "domain-name",
                "url",
                "email-addr",
                "email-message",
                "file",
                "process",
                "software",
                "user-account",
                "windows-registry-key",
                "network-traffic",
                "x509-certificate",
                "mutex",
                "autonomous-system",
                "mac-addr",
                "directory",
                "artifact",
            ]

            if is_indicator or is_observable:
                # Get score from x_opencti_score attribute
                score = obj.get("x_opencti_score")
                if score is not None:
                    scores.append(score)

        # If we have scores, calculate average and map to threat level
        if scores:
            avg_score = sum(scores) / len(scores)

            self.helper.connector_logger.debug(
                f"Calculated average score from {len(scores)} indicators/observables: {avg_score}"
            )

            # Map score (0-100) to threat level
            # Higher scores indicate higher threat
            if avg_score >= 75:
                return 1  # High
            elif avg_score >= 50:
                return 2  # Medium
            elif avg_score >= 25:
                return 3  # Low
            else:
                return 4  # Undefined

        # No scores found, fallback to confidence-based calculation
        self.helper.connector_logger.debug(
            "No scores found in indicators/observables, using container confidence for threat level"
        )

        confidence = container.get("confidence", 50)
        if confidence >= 80:
            return 1  # High
        elif confidence >= 60:
            return 2  # Medium
        elif confidence >= 30:
            return 3  # Low
        else:
            return 4  # Undefined

    def _create_base_event(
        self,
        container: Dict,
        custom_uuid: Optional[str] = None,
        stix_bundle: Optional[Dict] = None,
    ) -> MISPEvent:
        """Create the base MISP event from a container"""
        event = MISPEvent()

        # Set UUID
        if custom_uuid:
            event.uuid = custom_uuid
        else:
            # Generate UUID from container ID
            container_id = container.get("id", "")
            if "--" in container_id:
                event.uuid = container_id.split("--")[1]
            else:
                event.uuid = str(uuid4())

        # Set basic info
        event.info = container.get("name", "OpenCTI Import")

        # Set creator organization (orgc) from created_by_ref
        if stix_bundle and "created_by_ref" in container:
            created_by_ref = container["created_by_ref"]
            # Find the identity in the bundle
            for obj in stix_bundle.get("objects", []):
                if obj.get("id") == created_by_ref and obj.get("type") == "identity":
                    creator_name = obj.get("name")
                    if creator_name:
                        # Set the creator org in the event
                        event.Orgc = {"name": creator_name}
                    break

        # Set dates
        if "created" in container:
            event.date = container["created"].split("T")[0]
        if "modified" in container:
            event.timestamp = self._stix_timestamp_to_misp(container["modified"])

        # Calculate threat level based on indicator/observable scores
        threat_level = self._calculate_threat_level(stix_bundle, container)
        event.threat_level_id = threat_level

        # Set distribution
        event.distribution = self.config.misp.distribution_level

        # Set analysis status
        event.analysis = 2  # Completed

        # Add description if available
        if "description" in container:
            event.add_attribute(
                type="comment",
                value=container["description"],
                category="Other",
                comment="Event description",
            )

        # Process labels as tags
        for label in container.get("labels", []):
            event.add_tag(label)

        return event

    def _process_indicator(self, event: MISPEvent, indicator: Dict) -> None:
        """Process a STIX indicator and add it to the MISP event"""
        pattern = indicator.get("pattern", "")
        if not pattern:
            return

        # Parse STIX pattern
        parsed_patterns = self._parse_stix_pattern(pattern)

        for pattern_type, pattern_value in parsed_patterns:
            # Extract the base type from patterns like "url:value" -> "url"
            base_type = (
                pattern_type.split(":")[0] if ":" in pattern_type else pattern_type
            )

            # Map to MISP attribute type
            misp_type = self.PATTERN_TYPE_MAPPING.get(pattern_type)
            if not misp_type:
                # Try with base type
                misp_type = self.PATTERN_TYPE_MAPPING.get(base_type)

            if not misp_type:
                # Try to determine type from pattern
                if "ipv4" in pattern_type.lower():
                    misp_type = "ip-dst"
                elif "ipv6" in pattern_type.lower():
                    misp_type = "ip-dst"
                elif "domain" in pattern_type.lower():
                    misp_type = "domain"
                elif "hostname" in pattern_type.lower():
                    misp_type = "hostname"  # Add hostname support
                elif "url" in pattern_type.lower():
                    misp_type = "url"
                elif "email" in pattern_type.lower():
                    misp_type = "email-src"
                elif "file:hashes" in pattern_type.lower():
                    # Try to determine hash type from value length
                    if len(pattern_value) == 32:
                        misp_type = "md5"
                    elif len(pattern_value) == 40:
                        misp_type = "sha1"
                    elif len(pattern_value) == 64:
                        misp_type = "sha256"
                    elif len(pattern_value) == 128:
                        misp_type = "sha512"
                    else:
                        misp_type = "sha256"  # Default to SHA256
                elif "file" in pattern_type.lower():
                    misp_type = "filename"
                else:
                    misp_type = "text"

            # Check for duplicates before adding
            if not self._should_add_attribute(misp_type, pattern_value):
                # Skip duplicate attribute
                continue

            # Add attribute
            attr = event.add_attribute(
                type=misp_type,
                value=pattern_value,
                category=self._get_category_for_type(misp_type),
                to_ids=True,
                comment=indicator.get("name", ""),
            )

            # Add indicator tags
            for label in indicator.get("labels", []):
                attr.add_tag(label)

            # Add validity period as comment
            if "valid_from" in indicator or "valid_until" in indicator:
                validity = []
                if "valid_from" in indicator:
                    validity.append(f"Valid from: {indicator['valid_from']}")
                if "valid_until" in indicator:
                    validity.append(f"Valid until: {indicator['valid_until']}")
                if validity:
                    attr.comment = (
                        f"{attr.comment} | {' | '.join(validity)}"
                        if attr.comment
                        else " | ".join(validity)
                    )

    def _process_observable(self, event: MISPEvent, observable: Dict) -> None:
        """Process a STIX observable and add it to the MISP event"""
        obs_type = observable.get("type", "").lower()

        # Map to MISP object type
        misp_obj_type = self.OBSERVABLE_TO_MISP_OBJECT.get(obs_type)

        if misp_obj_type:
            # Create MISP object
            misp_obj = MISPObject(name=misp_obj_type)

            # Add attributes based on observable type
            if obs_type == "file":
                self._add_file_attributes(misp_obj, observable)
            elif obs_type in ["ipv4-addr", "ipv6-addr"]:
                self._add_ip_attributes(misp_obj, observable, obs_type)
            elif obs_type == "domain-name":
                self._add_domain_attributes(misp_obj, observable)
            elif obs_type == "url":
                self._add_url_attributes(misp_obj, observable)
            elif obs_type == "email-message":
                self._add_email_attributes(misp_obj, observable)
            elif obs_type == "network-traffic":
                self._add_network_traffic_attributes(misp_obj, observable)
            elif obs_type == "process":
                self._add_process_attributes(misp_obj, observable)
            elif obs_type == "windows-registry-key":
                self._add_registry_attributes(misp_obj, observable)
            elif obs_type == "x509-certificate":
                self._add_certificate_attributes(misp_obj, observable)
            elif obs_type == "user-account":
                self._add_user_account_attributes(misp_obj, observable)
            elif obs_type == "mutex":
                self._add_mutex_attributes(misp_obj, observable)
            elif obs_type == "software":
                self._add_software_attributes(misp_obj, observable)
            elif obs_type == "autonomous-system":
                self._add_as_attributes(misp_obj, observable)
            elif obs_type == "mac-addr":
                self._add_mac_attributes(misp_obj, observable)
            elif obs_type == "directory":
                self._add_directory_attributes(misp_obj, observable)
            elif obs_type == "artifact":
                self._add_artifact_attributes(misp_obj, observable)

            # Get labels for metadata
            # Check both 'labels' and 'x_opencti_labels'
            labels = observable.get("labels", []) or observable.get(
                "x_opencti_labels", []
            )

            # Add labels and metadata as comment on the object
            comments = []
            if labels:
                comments.append(f"Labels: {', '.join(labels)}")

            # Add threat level based on score if available
            score = observable.get("x_opencti_score")
            if score is not None:
                comments.append(f"Threat Score: {score}")
                if score >= 75:
                    comments.append("Threat Level: High")
                elif score >= 50:
                    comments.append("Threat Level: Medium")
                elif score >= 25:
                    comments.append("Threat Level: Low")
                else:
                    comments.append("Threat Level: Info")

            # Add infrastructure note for C2 servers
            if obs_type in ["hostname", "domain-name", "url", "ipv4-addr", "ipv6-addr"]:
                # Check if it's likely a C2 server based on labels
                if any(
                    label
                    in ["c2", "c2-server", "command-and-control", "malware", "sparkcat"]
                    for label in [l.lower() for l in labels]
                ):
                    comments.append("Infrastructure: C2 Server")

            # Set comment on object
            if comments:
                misp_obj.comment = " | ".join(comments)

            # Add the object to the event
            if misp_obj.attributes:
                event.add_object(misp_obj)
        else:
            # Add as simple attribute
            self._add_observable_as_attribute(event, observable)

    def _process_observed_data(
        self, event: MISPEvent, observed_data: Dict, bundle: Dict
    ) -> None:
        """Process observed-data and its referenced observables"""
        # Find referenced observables
        for ref in observed_data.get("object_refs", []):
            for obj in bundle.get("objects", []):
                if obj.get("id") == ref:
                    self._process_observable(event, obj)
                    break

    def _process_sighting(self, event: MISPEvent, sighting: Dict, bundle: Dict) -> None:
        """Process a STIX 2.1 sighting"""
        # Find the sighted object
        sighting_of_ref = sighting.get("sighting_of_ref")
        if not sighting_of_ref:
            return

        # Find the object in the bundle
        sighted_obj = None
        for obj in bundle.get("objects", []):
            if obj.get("id") == sighting_of_ref:
                sighted_obj = obj
                break

        if not sighted_obj:
            return

        # Create MISP sighting
        misp_sighting = MISPSighting()

        # Set sighting properties
        if "first_seen" in sighting:
            misp_sighting.date_sighting = self._stix_timestamp_to_misp(
                sighting["first_seen"]
            )
        elif "last_seen" in sighting:
            misp_sighting.date_sighting = self._stix_timestamp_to_misp(
                sighting["last_seen"]
            )

        # Set source
        if "where_sighted_refs" in sighting:
            # Get the identity that sighted it
            for ref in sighting["where_sighted_refs"]:
                for obj in bundle.get("objects", []):
                    if obj.get("id") == ref and obj.get("type") == "identity":
                        misp_sighting.source = obj.get("name", "Unknown")
                        break

        # Add sighting count
        if "count" in sighting:
            misp_sighting.add_attribute("sighting-count", sighting["count"])

        # Note: In a real implementation, you'd need to find the corresponding
        # MISP attribute or object that was sighted and attach the sighting to it

    def _add_galaxy_cluster(
        self,
        event: MISPEvent,
        galaxy_type: str,
        cluster_value: str,
        description: Optional[str] = None,
    ) -> None:
        """
        Add a galaxy cluster to the MISP event

        :param event: MISP event
        :param galaxy_type: Type of galaxy (e.g., 'threat-actor', 'malware', 'mitre-attack-pattern')
        :param cluster_value: Value/name of the cluster
        :param description: Optional description for the cluster
        """
        # For MITRE ATT&CK patterns, ensure proper format with technique ID
        if galaxy_type == "mitre-attack-pattern" and " - T" not in cluster_value:
            # Try to extract technique ID from external references if available
            # For now, just use the value as is
            pass

        # Use the proper galaxy tag format that MISP recognizes
        # This format automatically creates galaxies with clusters in MISP
        tag_name = f'misp-galaxy:{galaxy_type}="{cluster_value}"'
        event.add_tag(tag_name)

        self.helper.connector_logger.debug(f"Added galaxy cluster as tag: {tag_name}")

    def _process_entity(self, event: MISPEvent, entity: Dict) -> None:
        """Process a STIX entity and map it to MISP galaxy"""
        entity_type = entity.get("type", "").lower()
        entity_name = entity.get("name", "Unknown")
        entity_description = entity.get("description", "")

        # Special handling for identities based on identity_class
        if entity_type == "identity":
            galaxy_type = self._get_identity_galaxy(entity)
        # Special handling for locations based on x_opencti_location_type
        elif entity_type == "location":
            galaxy_type = self._get_location_galaxy(entity)
        # Special handling for vulnerabilities
        elif entity_type == "vulnerability":
            # Check if name contains CVE pattern
            import re

            if re.match(r"CVE-\d{4}-\d+", entity_name):
                galaxy_type = "branded-vulnerability"
            else:
                # For non-CVE vulnerabilities, just use tags
                galaxy_type = None
        else:
            # Standard mapping
            galaxy_type = self.ENTITY_TO_GALAXY_MAPPING.get(entity_type)

        if galaxy_type:
            # For MITRE ATT&CK patterns, format properly with technique ID
            if (
                galaxy_type == "mitre-attack-pattern"
                and entity_type == "attack-pattern"
            ):
                # Try to get MITRE ID from external references
                mitre_id = None
                if "external_references" in entity:
                    for ext_ref in entity["external_references"]:
                        if (
                            ext_ref.get("source_name") == "mitre-attack"
                            and "external_id" in ext_ref
                        ):
                            mitre_id = ext_ref["external_id"]
                            break

                # Format as "Name - TechniqueID" if we have the ID
                if mitre_id:
                    cluster_value = f"{entity_name} - {mitre_id}"
                else:
                    cluster_value = entity_name
            elif entity_type == "intrusion-set":
                # For intrusion sets, check if it's a MITRE group with an ID
                mitre_id = None
                is_mitre_group = False

                if "external_references" in entity:
                    for ext_ref in entity["external_references"]:
                        if ext_ref.get("source_name") == "mitre-attack":
                            is_mitre_group = True
                            if "external_id" in ext_ref:
                                mitre_id = ext_ref["external_id"]
                                break

                # If it's a MITRE group, we could optionally use the MITRE-specific galaxy
                # but threat-actor is more commonly used and better supported
                if is_mitre_group and mitre_id:
                    # Format as "APT29 - G0016" for MITRE groups
                    cluster_value = f"{entity_name} - {mitre_id}"
                    # Optionally, also add as MITRE enterprise attack intrusion set
                    # Uncomment if you want both galaxies:
                    # self._add_galaxy_cluster(event, "mitre-enterprise-attack-intrusion-set", cluster_value, entity_description[:200] if entity_description else None)
                else:
                    cluster_value = entity_name

                # Also check for aliases which are common for intrusion sets
                if "aliases" in entity:
                    for alias in entity.get("aliases", []):
                        if alias != entity_name:
                            # Add alias as a separate tag
                            event.add_tag(f"threat-actor-alias:{alias}")
            else:
                cluster_value = entity_name

            # Add as proper galaxy cluster
            self._add_galaxy_cluster(
                event,
                galaxy_type,
                cluster_value,
                entity_description[:200] if entity_description else None,
            )

            # Add external references as links if available (but not duplicate the entity)
            if "external_references" in entity:
                for ext_ref in entity["external_references"]:
                    if "url" in ext_ref:
                        event.add_attribute(
                            type="link",
                            value=ext_ref["url"],
                            category="External analysis",
                            comment=f"Reference for {entity_name}: {ext_ref.get('source_name', 'Unknown')}",
                        )
        else:
            # Only add as text attribute if no galaxy mapping exists
            attr = event.add_attribute(
                type="text",
                value=entity_name,
                category="External analysis",
                comment=f"{entity_type}: {entity.get('description', '')[:100] if 'description' in entity else ''}",
            )

            # Add entity-specific tags
            attr.add_tag(f"opencti:{entity_type}")

            # Add labels as tags
            for label in entity.get("labels", []):
                attr.add_tag(label)

            # Add external references as links if available
            if "external_references" in entity:
                for ext_ref in entity["external_references"]:
                    if "url" in ext_ref:
                        event.add_attribute(
                            type="link",
                            value=ext_ref["url"],
                            category="External analysis",
                            comment=f"Reference for {entity_name}: {ext_ref.get('source_name', '')}",
                        )

    def _process_custom_entity(self, event: MISPEvent, entity: Dict) -> None:
        """Process OpenCTI custom entities"""
        entity_type = entity.get("type", "").lower()
        entity_name = entity.get("name", "Unknown")

        # Remove x-opencti- or x-mitre- prefix for display
        clean_type = entity_type.replace("x-opencti-", "").replace("x-mitre-", "")

        # Check if we have a galaxy mapping
        galaxy_type = self.ENTITY_TO_GALAXY_MAPPING.get(entity_type)
        entity_description = entity.get("description", "")

        if galaxy_type:
            # Add as proper galaxy cluster
            self._add_galaxy_cluster(
                event,
                galaxy_type,
                entity_name,
                entity_description[:200] if entity_description else None,
            )
        else:
            # Special handling for common OpenCTI custom types
            if entity_type in ["x-opencti-case-incident", "x-opencti-incident"]:
                # Map to incident galaxy
                self._add_galaxy_cluster(
                    event,
                    "incident",
                    entity_name,
                    entity_description[:200] if entity_description else None,
                )
            elif entity_type in ["x-opencti-case-rfi", "x-opencti-case-rft"]:
                # These are investigation cases, use tags
                event.add_tag(f"opencti:{clean_type}:{entity_name}")
            elif entity_type == "x-opencti-feedback":
                # Feedback - use tags
                event.add_tag(f"opencti:feedback:{entity_name}")
            elif entity_type == "x-opencti-task":
                # Task - use tags
                event.add_tag(f"opencti:task:{entity_name}")
            elif entity_type.startswith("x-mitre-"):
                # MITRE extensions - check for specific types
                if "tactic" in entity_type:
                    self._add_galaxy_cluster(
                        event,
                        "mitre-tactic",
                        entity_name,
                        entity_description[:200] if entity_description else None,
                    )
                elif "technique" in entity_type:
                    self._add_galaxy_cluster(
                        event,
                        "mitre-technique",
                        entity_name,
                        entity_description[:200] if entity_description else None,
                    )
                elif "data-source" in entity_type:
                    event.add_tag(f"mitre:data-source:{entity_name}")
                elif "data-component" in entity_type:
                    event.add_tag(f"mitre:data-component:{entity_name}")
                else:
                    event.add_tag(f"mitre:{clean_type}:{entity_name}")
            else:
                # Generic custom tag for other unmapped types
                event.add_tag(f"opencti:{clean_type}:{entity_name}")

        # Add as attribute
        attr = event.add_attribute(
            type="text",
            value=entity_name,
            category="External analysis",
            comment=f"OpenCTI {clean_type}: {entity.get('description', '')[:100] if 'description' in entity else ''}",
        )

        # Add labels as tags
        for label in entity.get("labels", []):
            attr.add_tag(label)

    def _process_opencti_standard_entity(self, event: MISPEvent, entity: Dict) -> None:
        """Process standard OpenCTI entities without direct MISP galaxy mappings"""
        entity_type = entity.get("type", "").lower()
        entity_name = entity.get("name", "Unknown")

        # Add appropriate tag based on entity type
        if entity_type == "channel":
            # Communication channels
            event.add_tag(f"opencti:channel:{entity_name}")
        elif entity_type == "event":
            # Events - could be cyber events, incidents, etc.
            event.add_tag(f"opencti:event:{entity_name}")
        elif entity_type == "narrative":
            # Narratives - propaganda, disinformation narratives
            event.add_tag(f"opencti:narrative:{entity_name}")
        elif entity_type == "capability":
            # Capabilities - could map to tools/techniques
            event.add_tag(f"opencti:capability:{entity_name}")
        elif entity_type == "grouping":
            # Grouping - container for related objects
            event.add_tag(f"opencti:grouping:{entity_name}")
        elif entity_type in ["note", "opinion"]:
            # Analytical notes and opinions
            event.add_tag(f"opencti:{entity_type}:{entity_name}")
        elif entity_type in ["data-source", "data-component"]:
            # MITRE data sources
            event.add_tag(f"mitre:{entity_type}:{entity_name}")
        elif entity_type == "task":
            # Tasks
            event.add_tag(f"opencti:task:{entity_name}")
        else:
            # Fallback for any other standard types
            event.add_tag(f"opencti:{entity_type}:{entity_name}")

        # Add as attribute with details
        attr = event.add_attribute(
            type="text",
            value=entity_name,
            category="External analysis",
            comment=f"OpenCTI {entity_type}: {entity.get('description', '')[:100] if 'description' in entity else ''}",
        )

        # Add labels as tags
        for label in entity.get("labels", []):
            attr.add_tag(label)

        # Add external references if available
        if "external_references" in entity:
            for ext_ref in entity["external_references"]:
                if "url" in ext_ref:
                    event.add_attribute(
                        type="link",
                        value=ext_ref["url"],
                        category="External analysis",
                        comment=f"Reference for {entity_name}: {ext_ref.get('source_name', '')}",
                    )

    def _process_generic_entity(self, event: MISPEvent, entity: Dict) -> None:
        """Process any other STIX object as generic entity"""
        entity_type = entity.get("type", "unknown")
        entity_name = entity.get(
            "name", entity.get("value", entity.get("id", "Unknown"))
        )

        # Add as tag
        event.add_tag(f"stix:{entity_type}:{entity_name}")

        # Add as attribute
        attr = event.add_attribute(
            type="text",
            value=entity_name,
            category="External analysis",
            comment=f"STIX {entity_type}",
        )

        # Add labels as tags
        for label in entity.get("labels", []):
            attr.add_tag(label)

    def _add_opencti_tags(self, event: MISPEvent, container: Dict) -> None:
        """Add OpenCTI-specific tags to the event"""
        # Add source tag
        event.add_tag("source:opencti")

        # Add container type tag
        container_type = container.get("type", "unknown")
        if container_type.startswith("x-opencti-"):
            container_type = container_type.replace("x-opencti-", "")
        elif container_type == "case-incident":
            container_type = "incident"
        elif container_type == "case-rfi":
            container_type = "rfi"
        elif container_type == "case-rft":
            container_type = "rft"

        event.add_tag(f"opencti:type:{container_type}")

        # Add confidence level
        if "confidence" in container:
            event.add_tag(f"confidence:{container['confidence']}")

    def _get_identity_galaxy(self, identity: Dict) -> Optional[str]:
        """
        Determine the appropriate MISP galaxy for an identity based on its class

        :param identity: Identity STIX object
        :return: MISP galaxy type or None
        """
        identity_class = identity.get("identity_class", "").lower()
        opencti_type = identity.get("x_opencti_type", "").lower()

        # Map identity_class to MISP galaxies
        if identity_class == "organization":
            # Check if it's a specific sector organization
            if opencti_type == "sector" or identity_class == "class":
                return "sector"
            else:
                # Generic organization - use target-information
                return "target-information"

        elif identity_class == "class":
            # This typically represents a sector/industry
            return "sector"

        elif identity_class == "individual":
            # Check if it's a threat actor individual
            # This would require additional context, for now use target-information
            return "target-information"

        elif identity_class == "system":
            # Technical systems - use target-information
            return "target-information"

        elif identity_class == "group":
            # Could be threat actor group or other
            # Check labels or other indicators
            labels = identity.get("labels", [])
            if any(
                "threat" in label.lower() or "apt" in label.lower() for label in labels
            ):
                return "threat-actor"
            return "target-information"

        # Default fallback
        return "target-information"

    def _get_location_galaxy(self, location: Dict) -> Optional[str]:
        """
        Determine the appropriate MISP galaxy for a location based on its type

        :param location: Location STIX object
        :return: MISP galaxy type or None
        """
        location_type = location.get("x_opencti_location_type", "").lower()

        # Map location types to MISP galaxies
        if location_type == "country":
            return "country"

        elif location_type == "region":
            # MISP has region galaxy
            return "region"

        elif location_type in ["city", "administrative-area"]:
            # Cities don't have dedicated galaxy, use target-information
            return "target-information"

        elif location_type == "position":
            # Specific coordinates - use target-information
            return "target-information"

        # Check alternative fields if x_opencti_location_type is not set
        if not location_type:
            if "country" in location:
                return "country"
            elif "region" in location:
                return "region"

        # Default fallback
        return "target-information"

    # Helper methods for parsing and conversion

    def _parse_stix_pattern(self, pattern: str) -> List[Tuple[str, str]]:
        """Parse STIX pattern and extract indicator type and value"""
        results = []

        # Remove outer brackets
        pattern = pattern.strip()
        if pattern.startswith("[") and pattern.endswith("]"):
            pattern = pattern[1:-1]

        # Split by AND/OR
        parts = re.split(r"\s+(?:AND|OR)\s+", pattern)

        for part in parts:
            # Parse each condition
            match = re.match(r"([^=]+)\s*=\s*'([^']+)'", part.strip())
            if match:
                field, value = match.groups()
                field = field.strip()
                value = value.strip()
                results.append((field, value))
            else:
                # Try without quotes
                match = re.match(r"([^=]+)\s*=\s*([^\s]+)", part.strip())
                if match:
                    field, value = match.groups()
                    results.append((field.strip(), value.strip()))

        return results

    def _stix_timestamp_to_misp(self, timestamp: str) -> int:
        """Convert STIX timestamp to MISP timestamp"""
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            return int(dt.timestamp())
        except:
            return int(datetime.now().timestamp())

    def _get_category_for_type(self, misp_type: str) -> str:
        """Get appropriate MISP category for attribute type"""
        if misp_type in ["md5", "sha1", "sha256", "sha512", "ssdeep", "filename"]:
            return "Payload delivery"
        elif misp_type in [
            "ip-dst",
            "ip-src",
            "domain",
            "hostname",
            "url",
            "email-src",
            "email-dst",
        ]:
            return "Network activity"
        elif misp_type in ["regkey", "regkey|value"]:
            return "Artifacts dropped"
        elif misp_type in ["mutex", "process-name", "process-pid"]:
            return "Artifacts dropped"
        else:
            return "Other"

    # Specific attribute addition methods for different observable types

    def _add_file_attributes(self, misp_obj: MISPObject, file_obs: Dict) -> None:
        """Add file attributes to MISP object"""
        if "name" in file_obs:
            misp_obj.add_attribute("filename", value=file_obs["name"])

        if "hashes" in file_obs:
            for hash_type, hash_value in file_obs["hashes"].items():
                hash_type_lower = hash_type.lower().replace("-", "")
                if hash_type_lower == "md5":
                    misp_obj.add_attribute("md5", value=hash_value)
                elif hash_type_lower in ["sha1", "sha-1"]:
                    misp_obj.add_attribute("sha1", value=hash_value)
                elif hash_type_lower in ["sha256", "sha-256"]:
                    misp_obj.add_attribute("sha256", value=hash_value)
                elif hash_type_lower in ["sha512", "sha-512"]:
                    misp_obj.add_attribute("sha512", value=hash_value)
                elif hash_type_lower == "ssdeep":
                    misp_obj.add_attribute("ssdeep", value=hash_value)

        if "size" in file_obs:
            misp_obj.add_attribute("size-in-bytes", value=str(file_obs["size"]))

        if "mime_type" in file_obs:
            misp_obj.add_attribute("mimetype", value=file_obs["mime_type"])

    def _add_ip_attributes(
        self, misp_obj: MISPObject, ip_obs: Dict, ip_type: str
    ) -> None:
        """Add IP address attributes to MISP object"""
        value = ip_obs.get("value", "")
        if value:
            if ip_type == "ipv4-addr":
                misp_obj.add_attribute("ip", value=value)
            else:  # ipv6-addr
                misp_obj.add_attribute("ip", value=value)

    def _add_domain_attributes(self, misp_obj: MISPObject, domain_obs: Dict) -> None:
        """Add domain attributes to MISP object"""
        value = domain_obs.get("value", "")
        if value:
            misp_obj.add_attribute("domain", value=value)

    def _add_url_attributes(self, misp_obj: MISPObject, url_obs: Dict) -> None:
        """Add URL attributes to MISP object"""
        value = url_obs.get("value", "")
        if value:
            misp_obj.add_attribute("url", value=value)

    def _add_email_attributes(self, misp_obj: MISPObject, email_obs: Dict) -> None:
        """Add email attributes to MISP object"""
        if "from_ref" in email_obs:
            misp_obj.add_attribute("from", value=email_obs["from_ref"])

        if "to_refs" in email_obs:
            for to_ref in email_obs["to_refs"]:
                misp_obj.add_attribute("to", value=to_ref)

        if "subject" in email_obs:
            misp_obj.add_attribute("subject", value=email_obs["subject"])

        if "body" in email_obs:
            misp_obj.add_attribute("email-body", value=email_obs["body"][:500])

    def _add_network_traffic_attributes(
        self, misp_obj: MISPObject, traffic_obs: Dict
    ) -> None:
        """Add network traffic attributes to MISP object"""
        if "src_port" in traffic_obs:
            misp_obj.add_attribute("src-port", value=str(traffic_obs["src_port"]))

        if "dst_port" in traffic_obs:
            misp_obj.add_attribute("dst-port", value=str(traffic_obs["dst_port"]))

        if "protocols" in traffic_obs:
            for protocol in traffic_obs["protocols"]:
                misp_obj.add_attribute("protocol", value=protocol)

    def _add_process_attributes(self, misp_obj: MISPObject, process_obs: Dict) -> None:
        """Add process attributes to MISP object"""
        if "pid" in process_obs:
            misp_obj.add_attribute("pid", value=str(process_obs["pid"]))

        if "name" in process_obs:
            misp_obj.add_attribute("name", value=process_obs["name"])

        if "command_line" in process_obs:
            misp_obj.add_attribute("command-line", value=process_obs["command_line"])

    def _add_registry_attributes(
        self, misp_obj: MISPObject, registry_obs: Dict
    ) -> None:
        """Add Windows registry attributes to MISP object"""
        if "key" in registry_obs:
            misp_obj.add_attribute("key", value=registry_obs["key"])

        if "values" in registry_obs:
            for val in registry_obs["values"]:
                if "name" in val and "data" in val:
                    misp_obj.add_attribute(
                        "value", value=f"{val['name']}|{val['data']}"
                    )

    def _add_certificate_attributes(self, misp_obj: MISPObject, cert_obs: Dict) -> None:
        """Add X.509 certificate attributes to MISP object"""
        if "serial_number" in cert_obs:
            misp_obj.add_attribute("serial-number", value=cert_obs["serial_number"])

        if "issuer" in cert_obs:
            misp_obj.add_attribute("issuer", value=cert_obs["issuer"])

        if "subject" in cert_obs:
            misp_obj.add_attribute("subject", value=cert_obs["subject"])

    def _add_user_account_attributes(
        self, misp_obj: MISPObject, account_obs: Dict
    ) -> None:
        """Add user account attributes to MISP object"""
        if "account_login" in account_obs:
            misp_obj.add_attribute("username", value=account_obs["account_login"])

        if "display_name" in account_obs:
            misp_obj.add_attribute("display-name", value=account_obs["display_name"])

        if "account_type" in account_obs:
            misp_obj.add_attribute("account-type", value=account_obs["account_type"])

    def _add_mutex_attributes(self, misp_obj: MISPObject, mutex_obs: Dict) -> None:
        """Add mutex attributes to MISP object"""
        if "name" in mutex_obs:
            misp_obj.add_attribute("name", value=mutex_obs["name"])

    def _add_software_attributes(
        self, misp_obj: MISPObject, software_obs: Dict
    ) -> None:
        """Add software attributes to MISP object"""
        if "name" in software_obs:
            misp_obj.add_attribute("name", value=software_obs["name"])

        if "vendor" in software_obs:
            misp_obj.add_attribute("vendor", value=software_obs["vendor"])

        if "version" in software_obs:
            misp_obj.add_attribute("version", value=software_obs["version"])

    def _add_as_attributes(self, misp_obj: MISPObject, as_obs: Dict) -> None:
        """Add autonomous system attributes to MISP object"""
        if "number" in as_obs:
            misp_obj.add_attribute("asn", value=str(as_obs["number"]))

        if "name" in as_obs:
            misp_obj.add_attribute("description", value=as_obs["name"])

    def _add_mac_attributes(self, misp_obj: MISPObject, mac_obs: Dict) -> None:
        """Add MAC address attributes to MISP object"""
        value = mac_obs.get("value", "")
        if value:
            misp_obj.add_attribute("mac-address", value=value)

    def _add_directory_attributes(self, misp_obj: MISPObject, dir_obs: Dict) -> None:
        """Add directory attributes to MISP object"""
        if "path" in dir_obs:
            misp_obj.add_attribute("path", value=dir_obs["path"])

    def _add_artifact_attributes(
        self, misp_obj: MISPObject, artifact_obs: Dict
    ) -> None:
        """Add artifact attributes to MISP object"""
        if "payload_bin" in artifact_obs:
            misp_obj.add_attribute("payload", value=artifact_obs["payload_bin"][:500])

        if "mime_type" in artifact_obs:
            misp_obj.add_attribute("mimetype", value=artifact_obs["mime_type"])

    def _add_observable_as_attribute(self, event: MISPEvent, observable: Dict) -> None:
        """Add an observable as a simple attribute when no object mapping exists"""
        obs_type = observable.get("type", "").lower()
        value = observable.get("value", str(observable))

        # Determine MISP type
        if "ip" in obs_type:
            misp_type = "ip-dst"
        elif "domain" in obs_type:
            misp_type = "domain"
        elif "hostname" in obs_type:
            misp_type = "hostname"
        elif "url" in obs_type:
            misp_type = "url"
        elif "email" in obs_type:
            misp_type = "email-src"
        elif "file" in obs_type:
            misp_type = "filename"
        else:
            misp_type = "text"

        # Check for duplicates before adding
        if not self._should_add_attribute(misp_type, value):
            # Skip duplicate attribute
            return

        # Determine if this is a C2 server or malicious infrastructure
        to_ids = False
        if obs_type in ["hostname", "domain-name", "url", "ipv4-addr", "ipv6-addr"]:
            # Network observables should be marked for IDS
            to_ids = True

        attr = event.add_attribute(
            type=misp_type,
            value=value,
            category=self._get_category_for_type(misp_type),
            comment=f"Observable: {obs_type}",
            to_ids=to_ids,
        )

        # Add labels as tags to the attribute
        # Check both 'labels' and 'x_opencti_labels'
        labels = observable.get("labels", []) or observable.get("x_opencti_labels", [])
        for label in labels:
            attr.add_tag(label)

        # Add threat level based on score if available
        score = observable.get("x_opencti_score")
        if score is not None:
            if score >= 75:
                attr.add_tag("threat-level:high")
            elif score >= 50:
                attr.add_tag("threat-level:medium")
            elif score >= 25:
                attr.add_tag("threat-level:low")
            else:
                attr.add_tag("threat-level:info")

        # Add infrastructure galaxy tag for C2 servers
        if obs_type in ["hostname", "domain-name", "url", "ipv4-addr", "ipv6-addr"]:
            # Check if it's likely a C2 server based on labels
            if any(
                label
                in ["c2", "c2-server", "command-and-control", "malware", "sparkcat"]
                for label in [l.lower() for l in labels]
            ):
                # Add as C2 infrastructure
                attr.add_tag("infrastructure:c2")

        # Add observable type tag
        attr.add_tag(f"observable-type:{obs_type}")
