"""
Enhanced + Basic ConverterToStix - Comprehensive Profile Enrichment

Supports both basic PolySwarm enrichment and comprehensive malware profile enrichment.
Creates extensive STIX 2.1 objects including:
- Malware with full profile data (including malware_types)
- Threat actors with their profiles and relationships (including last_seen, targets, and located-at)
- Related malware with their profiles
- Locations (countries/regions)
- Intrusion-sets/campaigns
- Vulnerabilities (CVEs)
- Industry sectors (as Identity SDOs)
- Targeted Systems (as Software SDOs)
- Comprehensive relationship mapping
"""

import ipaddress
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any

import stix2
import validators
from dateutil import parser as dateutil_parser
from pycti import (
    Identity,
    Indicator,
    IntrusionSet,
    Location,
    Malware,
    StixCoreRelationship,
    ThreatActor,
    Vulnerability,
)

# ===================================================================
# FIX: Define a stable UUID namespace for generating Software SDO IDs
# ===================================================================
SOFTWARE_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.
    Supports comprehensive enrichment with malware profiles including recursive
    enrichment of related entities.
    """

    def __init__(self, helper, profile_loader=None) -> None:
        self.helper = helper
        self.profile_loader = profile_loader
        self.author = self.create_author()

        # Cache for created objects to avoid duplicates
        self._actor_cache = {}
        self._location_cache = {}
        self._intrusion_set_cache = {}
        self._vulnerability_cache = {}
        self._malware_cache = {}
        self._sector_cache = {}
        self._software_cache = {}  # Cache for OS/Software
        self._profile_cache = {}  # PERF-4: Cache for profile lookups

        # Track enrichment depth to prevent infinite recursion
        self._enrichment_depth = 0
        self._max_enrichment_depth = 2  # Limit recursive enrichment

    def clear_cache(self) -> None:
        """
        Clear cached STIX objects for new enrichment cycle.
        """
        self._actor_cache = {}
        self._location_cache = {}
        self._intrusion_set_cache = {}
        self._vulnerability_cache = {}
        self._malware_cache = {}
        self._sector_cache = {}
        self._software_cache = {}
        self._profile_cache = {}  # PERF-4: Clear profile cache
        self._enrichment_depth = 0
        self.helper.connector_logger.debug("[CONVERTER] Cleared object cache")

    def _get_cached_profile(self, name: str) -> dict | None:
        """
        PERF-4: Get profile with caching to avoid duplicate lookups.
        """
        if not name or not self.profile_loader:
            return None

        cache_key = name.strip().lower()
        if cache_key in self._profile_cache:
            return self._profile_cache[cache_key]

        profile = self.profile_loader.get_profile(name)
        self._profile_cache[cache_key] = profile
        return profile

    def _parse_datetime(self, date_string: str) -> str:
        """
        Parse datetime and convert to STIX-compatible ISO format string.
        """
        try:
            if not date_string or date_string == "Unknown" or date_string == "N/A":
                return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            parsed_date = dateutil_parser.parse(date_string)
            return parsed_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except (ValueError, OverflowError, TypeError) as e:
            # dateutil raises ValueError/OverflowError for unparseable dates
            self.helper.connector_logger.warning(
                f"[CONVERTER] Failed to parse datetime '{date_string}': {str(e)}. Using current time."
            )
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    @staticmethod
    def create_author():
        """
        Create Author (Organization Identity) using stix2.Identity.
        """
        return stix2.Identity(
            id=Identity.generate_id(name="PolySwarm", identity_class="organization"),
            name="PolySwarm_Malware_Threat_Intelligence",
            identity_class="organization",
            description=(
                "PolySwarm is a next-generation Malware Intelligence Platform combining "
                "the speed of crowdsourced detection with the rigor of enterprise security."
            ),
            external_references=[
                {
                    "source_name": "PolySwarm",
                    "url": "https://polyswarm.io/",
                    "description": "PolySwarm next-generation Malware Intelligence Platform",
                }
            ],
        )

    def create_relationship(
        self,
        source_id: str,
        relationship_type: str,
        target_id: str,
        description: str = None,
    ) -> stix2.Relationship | None:
        """
        Creates Relationship object using stix2.
        """
        try:
            rel_id = StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            )

            if description:
                return stix2.Relationship(
                    id=rel_id,
                    relationship_type=relationship_type,
                    source_ref=source_id,
                    target_ref=target_id,
                    created_by_ref=self.author.id,
                    description=description,
                    allow_custom=True,
                )
            return stix2.Relationship(
                id=rel_id,
                relationship_type=relationship_type,
                source_ref=source_id,
                target_ref=target_id,
                created_by_ref=self.author.id,
                allow_custom=True,
            )

        except (KeyError, AttributeError, TypeError, ValueError) as e:
            self.helper.connector_logger.error(
                f"[CONVERTER] Error creating relationship: {str(e)}"
            )
            self.helper.connector_logger.error(
                f"[CONVERTER] Traceback: {traceback.format_exc()}"
            )
            return None

    def create_indicator_from_polyswarm(
        self, observable: dict, polyswarm_data: dict
    ) -> dict | None:
        """
        Create a STIX Indicator from PolySwarm enrichment data as plain dict.
        """
        try:
            # Get primary hash for pattern creation
            hash_type = next(
                (
                    alg
                    for alg in ["SHA-256", "SHA-1", "MD5"]
                    if alg in observable.get("hashes", {})
                ),
                None,
            )
            hash_value = observable["hashes"].get(hash_type) if hash_type else None

            if not hash_value:
                return None

            # Normalize hash algorithm for pattern (SHA-256 -> SHA256)
            hash_algo_normalized = hash_type.replace("-", "").upper()
            pattern = f"[file:hashes.'{hash_algo_normalized}' = '{hash_value}']"

            labels = polyswarm_data.get("x_opencti_labels", [])
            score = polyswarm_data.get("x_opencti_score", 0)
            is_malicious = score >= 50

            indicator_name = hash_value
            indicator_id = Indicator.generate_id(pattern)
            valid_from = self._parse_datetime(polyswarm_data.get("first_seen", ""))
            current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": current_time,
                "modified": current_time,
                "created_by_ref": self.author.id,
                "name": indicator_name,
                "description": polyswarm_data.get(
                    "x_opencti_description", "File analyzed by PolySwarm"
                ),
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": valid_from,
                "labels": labels,
                "confidence": polyswarm_data.get("confidence", 100),
                "x_opencti_score": score,
                "x_opencti_main_observable_type": "StixFile",
                "x_opencti_detection": is_malicious,
            }

            if polyswarm_data.get("permalink"):
                indicator["external_references"] = [
                    {
                        "source_name": "PolySwarm_Malware_Intelligence",
                        "url": polyswarm_data["permalink"],
                        "description": "PolySwarm analysis results",
                        "external_id": polyswarm_data.get("polyswarm_id"),
                    }
                ]

            return indicator

        except (KeyError, AttributeError, TypeError, ValueError) as e:
            self.helper.connector_logger.error(
                f"[CONVERTER] Error creating indicator: {str(e)}"
            )
            self.helper.connector_logger.error(
                f"[CONVERTER] Traceback: {traceback.format_exc()}"
            )
            return None

    # ============= LOCATION CREATION =============

    def _create_location(self, location_name: str) -> dict | None:
        """
        Create or retrieve cached Location object with proper STIX format.
        """
        if not location_name or location_name == "Unknown":
            return None

        # Check cache
        if location_name in self._location_cache:
            return self._location_cache[location_name]

        try:
            location_id = Location.generate_id(
                name=location_name, x_opencti_location_type="Country"
            )
            current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            location = {
                "type": "location",
                "spec_version": "2.1",
                "id": location_id,
                "created": current_time,
                "modified": current_time,
                "created_by_ref": self.author.id,
                "name": location_name,
                "x_opencti_location_type": "Country",
                "confidence": 75,
            }

            self._location_cache[location_name] = location
            self.helper.connector_logger.debug(
                f"[CONVERTER] Created location: {location_name}"
            )
            return location

        except (KeyError, AttributeError, TypeError, ValueError) as e:
            self.helper.connector_logger.error(
                f"[CONVERTER] Error creating location {location_name}: {str(e)}"
            )
            return None

    # ============= THREAT ACTOR CREATION =============

    def _create_threat_actor(
        self, actor_name: str, profile: dict = None, all_actors: list = None
    ) -> dict | None:
        """
        Create comprehensive Threat Actor object with profile enrichment.
        If profile is provided, adds locations, sectors, and related context.
        If all_actors is provided, adds other actors as aliases (known_as).
        """
        if not actor_name or actor_name == "Unknown":
            return None

        # Check cache
        if actor_name in self._actor_cache:
            return self._actor_cache[actor_name]

        try:
            # Load actor's own profile if available (PERF-4: use cached lookup)
            actor_profile = None
            if self.profile_loader and profile is None:
                # Try to find actor profile (actors might have their own entries)
                actor_profile = self._get_cached_profile(actor_name)
            elif profile:
                # This 'profile' is the *malware's* profile
                actor_profile = self._get_cached_profile(actor_name)

            # FIX: Add required 'opencti_type' parameter to generate_id
            actor_id = ThreatActor.generate_id(
                name=actor_name, opencti_type="Threat-Actor"
            )
            current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            # Build description from profile
            description_parts = [f"Threat actor: {actor_name}"]

            # Use the specific actor's profile if it exists, otherwise fallback to malware profile
            profile_to_use = actor_profile if actor_profile else profile

            if profile_to_use:
                if profile_to_use.get("description"):
                    description_parts.append(profile_to_use["description"])
                if profile_to_use.get("origin_locations"):
                    origins = ", ".join(profile_to_use["origin_locations"])
                    description_parts.append(f"Origin: {origins}")

            description = ". ".join(description_parts)

            # Build labels (still useful for quick filtering)
            labels = ["threat-actor"]  # Start with base label
            if profile_to_use and profile_to_use.get("origin_locations"):
                for loc in profile_to_use["origin_locations"]:
                    labels.append(f"origin:{loc.lower().replace(' ', '-')}")

            threat_actor = {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": actor_id,
                "created": current_time,
                "modified": current_time,
                "created_by_ref": self.author.id,
                "name": actor_name,
                "description": description,
                "labels": labels,
                "confidence": 85,
            }

            # ===================================================================
            # FIX: Add aliases (known_as) for other actors in the same profile
            # ===================================================================
            if all_actors and len(all_actors) > 1:
                # Add other actors as aliases (excluding self)
                aliases = [a for a in all_actors if a != actor_name]
                if aliases:
                    threat_actor["aliases"] = aliases
                    self.helper.connector_logger.info(
                        f"[CONVERTER] Added {len(aliases)} aliases to {actor_name}: {aliases}"
                    )

            # ===================================================================
            # FIX: Add last_seen
            # ===================================================================
            last_seen_date = None
            if actor_profile and actor_profile.get("updated"):
                last_seen_date = self._parse_datetime(actor_profile.get("updated"))
            elif profile and profile.get(
                "updated"
            ):  # Fallback to the malware's profile date
                last_seen_date = self._parse_datetime(profile.get("updated"))

            if last_seen_date:
                threat_actor["last_seen"] = last_seen_date

            # Add external references if citations available
            if profile_to_use and profile_to_use.get("citations"):
                citations = profile_to_use["citations"]
                if isinstance(citations, str):
                    citations = [c.strip() for c in citations.split(",")]

                threat_actor["external_references"] = []
                for idx, citation_url in enumerate(citations):
                    if citation_url and citation_url.startswith("http"):
                        threat_actor["external_references"].append(
                            {
                                "source_name": f"Reference_{idx + 1}",
                                "url": citation_url,
                                "description": f"Threat intelligence on {actor_name}",
                            }
                        )

            self._actor_cache[actor_name] = threat_actor
            self.helper.connector_logger.info(
                f"[CONVERTER] Created threat actor: {actor_name}"
            )
            return threat_actor

        except (KeyError, AttributeError, TypeError, ValueError) as e:
            self.helper.connector_logger.error(
                f"[CONVERTER] Error creating threat actor {actor_name}: {str(e)}"
            )
            self.helper.connector_logger.error(
                f"[CONVERTER] Traceback: {traceback.format_exc()}"
            )
            return None

    # ============= INTRUSION SET CREATION =============

    def _create_intrusion_set(
        self, campaign_name: str, context: str = None
    ) -> dict | None:
        """
        Create Intrusion Set (Campaign) object.
        """
        if not campaign_name or campaign_name == "Unknown":
            return None

        # Check cache
        if campaign_name in self._intrusion_set_cache:
            return self._intrusion_set_cache[campaign_name]

        try:
            intrusion_set_id = IntrusionSet.generate_id(name=campaign_name)
            current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            description = f"Campaign/Intrusion Set: {campaign_name}"
            if context:
                description += f" associated with {context}"

            intrusion_set = {
                "type": "intrusion-set",
                "spec_version": "2.1",
                "id": intrusion_set_id,
                "created": current_time,
                "modified": current_time,
                "created_by_ref": self.author.id,
                "name": campaign_name,
                "description": description,
                "confidence": 75,
            }

            self._intrusion_set_cache[campaign_name] = intrusion_set
            self.helper.connector_logger.debug(
                f"[CONVERTER] Created intrusion set: {campaign_name}"
            )
            return intrusion_set

        except (KeyError, AttributeError, TypeError, ValueError) as e:
            self.helper.connector_logger.error(
                f"[CONVERTER] Error creating intrusion set {campaign_name}: {str(e)}"
            )
            return None

    # ============= VULNERABILITY CREATION =============

    def _create_vulnerability(self, cve_id: str) -> dict | None:
        """
        Create Vulnerability object for CVE.
        """
        if not cve_id or not cve_id.startswith("CVE-"):
            return None

        # Check cache
        if cve_id in self._vulnerability_cache:
            return self._vulnerability_cache[cve_id]

        try:
            vuln_id = Vulnerability.generate_id(name=cve_id)
            current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            vulnerability = {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": vuln_id,
                "created": current_time,
                "modified": current_time,
                "created_by_ref": self.author.id,
                "name": cve_id,
                "description": f"Vulnerability {cve_id} targeted by malware",
                "external_references": [
                    {
                        "source_name": "cve",
                        "external_id": cve_id,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    }
                ],
                "confidence": 90,
            }

            self._vulnerability_cache[cve_id] = vulnerability
            self.helper.connector_logger.debug(
                f"[CONVERTER] Created vulnerability: {cve_id}"
            )
            return vulnerability

        except (KeyError, AttributeError, TypeError, ValueError) as e:
            self.helper.connector_logger.error(
                f"[CONVERTER] Error creating vulnerability {cve_id}: {str(e)}"
            )
            return None

    # ============= SECTOR CREATION =============

    def _create_sector(self, sector_name: str) -> dict | None:
        """
        Create or retrieve cached Sector object (as Identity SDO).
        """
        if not sector_name or sector_name == "Unknown":
            return None

        sector_key = sector_name.lower()
        if sector_key in self._sector_cache:
            return self._sector_cache[sector_key]

        try:
            sector_id = Identity.generate_id(name=sector_name, identity_class="class")
            current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            sector = {
                "type": "identity",
                "spec_version": "2.1",
                "id": sector_id,
                "created": current_time,
                "modified": current_time,
                "created_by_ref": self.author.id,
                "name": sector_name.capitalize(),
                "identity_class": "class",  # STIX class for sectors/industries
                "x_opencti_type": "Sector",
                "confidence": 75,
            }

            self._sector_cache[sector_key] = sector
            self.helper.connector_logger.debug(
                f"[CONVERTER] Created sector: {sector_name}"
            )
            return sector

        except (KeyError, AttributeError, TypeError, ValueError) as e:
            self.helper.connector_logger.error(
                f"[CONVERTER] Error creating sector {sector_name}: {str(e)}"
            )
            return None

    # ============= SOFTWARE (OS) CREATION =============

    def _create_software(self, os_name: str) -> dict | None:
        """
        Create or retrieve cached Software SDO for an Operating System.
        """
        if not os_name or os_name == "Unknown":
            return None

        os_key = os_name.lower()
        if os_key in self._software_cache:
            return self._software_cache[os_key]

        try:
            # FIX: Manually create ID and object for Software SDO
            software_id = f"software--{str(uuid.uuid5(SOFTWARE_NAMESPACE, os_name))}"
            current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            # ``software`` is a STIX 2.1 SCO. Author goes on the
            # OpenCTI extension ``x_opencti_created_by_ref``; the
            # SDO/SRO-only ``created_by_ref`` property would break
            # strict STIX validation when the platform re-emits the
            # bundle. Same SCO-author contract as the IP / domain /
            # URL helpers below in this module and as the file
            # observable in ``polyswarm-sandbox``'s ``stix_builder``.
            software = {
                "type": "software",
                "spec_version": "2.1",
                "id": software_id,
                "created": current_time,
                "modified": current_time,
                "x_opencti_created_by_ref": self.author.id,
                "name": os_name.capitalize(),
                "x_opencti_type": "Software",  # Ensure OpenCTI knows what this is
                "confidence": 75,
            }

            self._software_cache[os_key] = software
            self.helper.connector_logger.debug(
                f"[CONVERTER] Created software (OS): {os_name}"
            )
            return software

        except (KeyError, AttributeError, TypeError, ValueError) as e:
            self.helper.connector_logger.error(
                f"[CONVERTER] Error creating software (OS) {os_name}: {str(e)}"
            )
            return None

    # ============= RELATED MALWARE CREATION (WITH PROFILE ENRICHMENT) =============

    def _create_related_malware(
        self, malware_name: str, source_malware_id: str
    ) -> tuple:
        """
        Create related malware object WITH full profile enrichment.
        Returns: (malware_object, [additional_objects], [relationships])

        This recursively enriches related malware with their profiles, but limits depth
        to prevent infinite recursion.
        """
        if not malware_name or malware_name == "Unknown":
            return None, [], []

        # Check cache to avoid duplicates
        if malware_name in self._malware_cache:
            cached_malware = self._malware_cache[malware_name]
            # Still create relationship to source
            rel = self.create_relationship(
                source_id=source_malware_id,
                relationship_type="related-to",
                target_id=cached_malware["id"],
                description=f"Related malware family: {malware_name}",
            )
            return cached_malware, [], [rel] if rel else []

        try:
            # Check recursion depth
            if self._enrichment_depth >= self._max_enrichment_depth:
                self.helper.connector_logger.debug(
                    f"[CONVERTER] Max enrichment depth reached for {malware_name}"
                )
                # Create basic malware without profile enrichment
                return self._create_basic_malware(malware_name, source_malware_id)

            # Increment depth for this branch
            self._enrichment_depth += 1

            # Load profile for this related malware (PERF-4: use cached lookup)
            related_profile = self._get_cached_profile(malware_name)

            # FIX: Removed unexpected keyword argument 'is_family'
            malware_id = Malware.generate_id(name=malware_name)
            current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            # Build description
            description_parts = [f"Related malware family: {malware_name}"]
            if related_profile and related_profile.get("description"):
                description_parts.append(related_profile["description"])

            description = ". ".join(description_parts)

            # Build labels
            labels = [f"malware-family:{malware_name.lower().replace(' ', '-')}"]

            if related_profile and related_profile.get("programming_languages"):
                # Add programming language labels
                for lang in related_profile["programming_languages"]:
                    labels.append(f"language:{lang.lower().replace(' ', '-')}")

            malware = {
                "type": "malware",
                "spec_version": "2.1",
                "id": malware_id,
                "created": current_time,
                "modified": current_time,
                "created_by_ref": self.author.id,
                "name": malware_name,
                "description": description,
                "is_family": True,
                "labels": labels,
                "confidence": 75,
            }

            # Add malware_types property
            if related_profile and related_profile.get("malware_type"):
                malware["malware_types"] = related_profile["malware_type"]

            # Add aliases for related malware's own related_malware
            if related_profile and related_profile.get("related_malware"):
                related_aliases = related_profile["related_malware"]
                if related_aliases:
                    malware["aliases"] = related_aliases
                    self.helper.connector_logger.info(
                        f"[CONVERTER] Added {len(related_aliases)} aliases to related malware {malware_name}"
                    )

            # Add external references
            if related_profile and related_profile.get("citations"):
                citations = related_profile["citations"]
                if isinstance(citations, str):
                    citations = [c.strip() for c in citations.split(",")]

                malware["external_references"] = []
                for idx, citation_url in enumerate(citations):
                    if citation_url and citation_url.startswith("http"):
                        malware["external_references"].append(
                            {
                                "source_name": f"Reference_{idx + 1}",
                                "url": citation_url,
                                "description": f"Threat intelligence on {malware_name}",
                            }
                        )

            # Cache the malware
            self._malware_cache[malware_name] = malware

            additional_objects = []
            relationships = []

            # Create relationship to source malware
            rel = self.create_relationship(
                source_id=source_malware_id,
                relationship_type="related-to",
                target_id=malware_id,
                description=f"Related malware family: {malware_name}",
            )
            if rel:
                relationships.append(rel)

            # Enrich with profile data if available
            if related_profile:
                # 1. Threat Actors (with cross-referenced aliases)
                if related_profile.get("actors"):
                    all_actors = related_profile["actors"]
                    for actor_name in all_actors:
                        actor_obj = self._create_threat_actor(
                            actor_name, profile=related_profile, all_actors=all_actors
                        )
                        if actor_obj:
                            additional_objects.append(actor_obj)

                            # Relationship: Threat Actor -> uses -> Malware
                            rel = self.create_relationship(
                                source_id=actor_obj["id"],
                                relationship_type="uses",
                                target_id=malware_id,
                                description=f"{actor_name} uses {malware_name}",
                            )
                            if rel:
                                relationships.append(rel)

                # 2. Target Locations
                if related_profile.get("target_locations"):
                    for location_name in related_profile["target_locations"]:
                        location_obj = self._create_location(location_name)
                        if location_obj:
                            additional_objects.append(location_obj)

                            # Relationship: Malware -> targets -> Location
                            rel = self.create_relationship(
                                source_id=malware_id,
                                relationship_type="targets",
                                target_id=location_obj["id"],
                                description=f"{malware_name} targets {location_name}",
                            )
                            if rel:
                                relationships.append(rel)

                # 3. Origin Locations
                if related_profile.get("origin_locations"):
                    for location_name in related_profile["origin_locations"]:
                        location_obj = self._create_location(location_name)
                        if location_obj:
                            additional_objects.append(location_obj)

                            # Relationship: Malware -> originates-from -> Location
                            rel = self.create_relationship(
                                source_id=malware_id,
                                relationship_type="originates-from",
                                target_id=location_obj["id"],
                                description=f"{malware_name} originates from {location_name}",
                            )
                            if rel:
                                relationships.append(rel)

                # 4. CVEs
                if related_profile.get("target_cves"):
                    for cve_id in related_profile["target_cves"]:
                        vuln_obj = self._create_vulnerability(cve_id)
                        if vuln_obj:
                            additional_objects.append(vuln_obj)

                            # Relationship: Malware -> targets -> Vulnerability
                            rel = self.create_relationship(
                                source_id=malware_id,
                                relationship_type="targets",
                                target_id=vuln_obj["id"],
                                description=f"{malware_name} exploits {cve_id}",
                            )
                            if rel:
                                relationships.append(rel)

                # 5. Add SYSTEMS TARGETED (Software)
                if related_profile.get("systems_targeted"):
                    os_refs = []
                    for os_name in related_profile["systems_targeted"]:
                        software_obj = self._create_software(os_name)
                        if software_obj:
                            additional_objects.append(software_obj)
                            os_refs.append(software_obj["id"])

                    if os_refs:
                        malware["operating_system_refs"] = os_refs

                # 6. Add TARGET SECTORS
                if related_profile.get("verticals_targeted"):
                    for sector_name in related_profile["verticals_targeted"]:
                        sector_obj = self._create_sector(sector_name)
                        if sector_obj:
                            additional_objects.append(sector_obj)
                            rel = self.create_relationship(
                                source_id=malware_id,
                                relationship_type="targets",
                                target_id=sector_obj["id"],
                                description=f"{malware_name} targets the {sector_name} sector",
                            )
                            if rel:
                                relationships.append(rel)

            # Decrement depth after processing this branch
            self._enrichment_depth -= 1

            self.helper.connector_logger.info(
                f"[CONVERTER] Created related malware '{malware_name}' with "
                f"{len(additional_objects)} objects, {len(relationships)} relationships"
            )

            return malware, additional_objects, relationships

        except (KeyError, AttributeError, TypeError, ValueError) as e:
            self.helper.connector_logger.error(
                f"[CONVERTER] Error creating related malware {malware_name}: {str(e)}"
            )
            self.helper.connector_logger.error(
                f"[CONVERTER] Traceback: {traceback.format_exc()}"
            )
            self._enrichment_depth -= 1  # Ensure we decrement on error
            return None, [], []

    def _create_basic_malware(self, malware_name: str, source_malware_id: str) -> tuple:
        """
        Create basic malware object without profile enrichment (for depth limiting).
        """
        try:
            # FIX: Removed unexpected keyword argument
            malware_id = Malware.generate_id(name=malware_name)
            current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            malware = {
                "type": "malware",
                "spec_version": "2.1",
                "id": malware_id,
                "created": current_time,
                "modified": current_time,
                "created_by_ref": self.author.id,
                "name": malware_name,
                "description": f"Related malware family: {malware_name}",
                "is_family": True,
                "labels": [f"malware-family:{malware_name.lower().replace(' ', '-')}"],
                "confidence": 75,
            }

            self._malware_cache[malware_name] = malware

            rel = self.create_relationship(
                source_id=source_malware_id,
                relationship_type="related-to",
                target_id=malware_id,
                description=f"Related malware family: {malware_name}",
            )

            return malware, [], [rel] if rel else []

        except (KeyError, AttributeError, TypeError, ValueError) as e:
            self.helper.connector_logger.error(
                f"[CONVERTER] Error creating basic malware {malware_name}: {str(e)}"
            )
            return None, [], []

    # ============= MAIN MALWARE CREATION WITH COMPREHENSIVE ENRICHMENT =============

    def create_malware_from_polyswarm(
        self, polyswarm_data: dict, observable: dict = None, profile: dict = None
    ) -> tuple:
        """
        Create comprehensive Malware STIX object with full profile enrichment.

        Returns: (malware_object, [additional_objects], [relationships])
        """
        try:
            malware_families = polyswarm_data.get("poly_unite", [])
            malware_name = malware_families[0] if malware_families else None

            # Guard: skip malware creation when family is None/Unknown/empty
            if not malware_name or str(malware_name).strip().lower() in (
                "unknown",
                "none",
                "",
            ):
                self.helper.connector_logger.info(
                    "[CONVERTER] No malware family identified, skipping malware object"
                )
                return None, [], []

            # FIX: Removed unexpected keyword argument
            malware_id = Malware.generate_id(name=malware_name)
            current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            # Build comprehensive description
            description_parts = []
            if profile and profile.get("description"):
                description_parts.append(profile["description"])

            if profile and profile.get("malware_type"):
                mtype = ", ".join(profile["malware_type"])
                description_parts.append(f"Type: {mtype}")

            description = ". ".join(description_parts)

            # Build comprehensive labels
            labels = polyswarm_data.get("x_opencti_labels", [])

            if profile and profile.get("programming_languages"):
                # Add programming language labels
                for lang in profile["programming_languages"]:
                    label = f"language:{lang.lower().replace(' ', '-')}"
                    if label not in labels:
                        labels.append(label)

            # Create malware object
            malware = {
                "type": "malware",
                "spec_version": "2.1",
                "id": malware_id,
                "created": current_time,
                "modified": current_time,
                "created_by_ref": self.author.id,
                "name": malware_name,
                "description": description,
                "is_family": True,
                "labels": labels,
                "confidence": polyswarm_data.get("confidence", 100),
                "x_opencti_score": polyswarm_data.get("x_opencti_score", 0),
            }

            # Add malware_types from profile or fall back to PolySwarm labels
            if profile and profile.get("malware_type"):
                malware["malware_types"] = profile["malware_type"]
            else:
                # Extract malware types from labels (e.g. "malware_type:trojan")
                label_types = [
                    lbl.replace("malware_type:", "").strip()
                    for lbl in polyswarm_data.get("x_opencti_labels", [])
                    if lbl.startswith("malware_type:")
                ]
                if label_types:
                    malware["malware_types"] = label_types

            # ===================================================================
            # FIX: Add aliases (known_as) for related malware families
            # ===================================================================
            if profile and profile.get("related_malware"):
                related_aliases = profile["related_malware"]
                if related_aliases:
                    malware["aliases"] = related_aliases
                    self.helper.connector_logger.info(
                        f"[CONVERTER] Added {len(related_aliases)} aliases to malware {malware_name}: {related_aliases}"
                    )

            # Add external references
            external_refs = []
            if polyswarm_data.get("permalink"):
                external_refs.append(
                    {
                        "source_name": "PolySwarm",
                        "url": polyswarm_data["permalink"],
                        "description": "PolySwarm malware analysis",
                        "external_id": polyswarm_data.get("polyswarm_id"),
                    }
                )

            if profile and profile.get("citations"):
                citations = profile["citations"]
                if isinstance(citations, str):
                    citations = [c.strip() for c in citations.split(",")]

                for idx, citation_url in enumerate(citations):
                    if citation_url and citation_url.startswith("http"):
                        external_refs.append(
                            {
                                "source_name": f"ThreatIntel_Ref_{idx + 1}",
                                "url": citation_url,
                                "description": f"Threat intelligence on {malware_name}",
                            }
                        )

            if external_refs:
                malware["external_references"] = external_refs

            # Cache the primary malware
            self._malware_cache[malware_name] = malware

            additional_objects = []
            relationships = []

            # Process profile enrichment if available
            if profile:
                self.helper.connector_logger.info(
                    f"[CONVERTER] Enriching {malware_name} with profile data"
                )

                # 1. THREAT ACTORS (with their profiles and cross-referenced aliases)
                if profile.get("actors"):
                    all_actors = profile[
                        "actors"
                    ]  # Get all actors for cross-referencing
                    self.helper.connector_logger.info(
                        f"[CONVERTER] Processing {len(all_actors)} threat actors"
                    )
                    for actor_name in all_actors:
                        # Pass all_actors to enable alias cross-referencing
                        actor_obj = self._create_threat_actor(
                            actor_name, profile=profile, all_actors=all_actors
                        )
                        if actor_obj:
                            additional_objects.append(actor_obj)

                            # Relationship: Threat Actor -> uses -> Malware
                            rel = self.create_relationship(
                                source_id=actor_obj["id"],
                                relationship_type="uses",
                                target_id=malware_id,
                                description=f"{actor_name} uses {malware_name} malware",
                            )
                            if rel:
                                relationships.append(rel)

                            # === FIX for Actor Origin Location (located-at) ===
                            # Use actor_profile *if it exists*, otherwise fall back to malware profile's origin
                            # PERF-4: use cached lookup
                            actor_profile = self._get_cached_profile(actor_name)
                            actor_origins = (
                                actor_profile.get("origin_locations")
                                if actor_profile
                                else profile.get("origin_locations", [])
                            )

                            if actor_origins:
                                self.helper.connector_logger.info(
                                    f"[CONVERTER] Processing {len(actor_origins)} origin locations"
                                    f" for actor {actor_name}"
                                )
                                for loc_name in actor_origins:
                                    loc_obj = self._create_location(loc_name)
                                    if loc_obj:
                                        additional_objects.append(loc_obj)
                                        rel = self.create_relationship(
                                            source_id=actor_obj["id"],
                                            relationship_type="located-at",
                                            target_id=loc_obj["id"],
                                            description=f"Attributed origin of {actor_name}",
                                        )
                                        if rel:
                                            relationships.append(rel)

                            # === FIX for Actor Target Countries (targets) ===
                            actor_target_locations = (
                                actor_profile.get("target_locations")
                                if actor_profile
                                else profile.get("target_locations", [])
                            )

                            if actor_target_locations:
                                self.helper.connector_logger.info(
                                    f"[CONVERTER] Processing {len(actor_target_locations)} target locations"
                                    f" for actor {actor_name}"
                                )
                                for loc_name in actor_target_locations:
                                    loc_obj = self._create_location(loc_name)
                                    if loc_obj:
                                        additional_objects.append(loc_obj)
                                        rel = self.create_relationship(
                                            source_id=actor_obj["id"],
                                            relationship_type="targets",
                                            target_id=loc_obj["id"],
                                            description=f"{actor_name} targets {loc_name}",
                                        )
                                        if rel:
                                            relationships.append(rel)

                            # === FIX for Actor Target Sectors (targets) ===
                            actor_target_sectors = (
                                actor_profile.get("verticals_targeted")
                                if actor_profile
                                else profile.get("verticals_targeted", [])
                            )

                            if actor_target_sectors:
                                self.helper.connector_logger.info(
                                    f"[CONVERTER] Processing {len(actor_target_sectors)} target sectors"
                                    f" for actor {actor_name}"
                                )
                                for sector_name in actor_target_sectors:
                                    sector_obj = self._create_sector(sector_name)
                                    if sector_obj:
                                        if not any(
                                            x["id"] == sector_obj["id"]
                                            for x in additional_objects
                                        ):
                                            additional_objects.append(sector_obj)

                                        rel = self.create_relationship(
                                            source_id=actor_obj["id"],
                                            relationship_type="targets",
                                            target_id=sector_obj["id"],
                                            description=f"{actor_name} targets the {sector_name} sector",
                                        )
                                        if rel:
                                            relationships.append(rel)

                # 2. TARGET LOCATIONS (Malware -> targets -> Location)
                if profile.get("target_locations"):
                    self.helper.connector_logger.info(
                        f"[CONVERTER] Processing {len(profile['target_locations'])} target locations for malware"
                    )
                    for location_name in profile["target_locations"]:
                        location_obj = self._create_location(location_name)
                        if location_obj:
                            additional_objects.append(location_obj)

                            rel = self.create_relationship(
                                source_id=malware_id,
                                relationship_type="targets",
                                target_id=location_obj["id"],
                                description=f"{malware_name} targets entities in {location_name}",
                            )
                            if rel:
                                relationships.append(rel)

                # 3. ORIGIN LOCATIONS (Malware -> originates-from -> Location)
                if profile.get("origin_locations"):
                    self.helper.connector_logger.info(
                        f"[CONVERTER] Processing {len(profile['origin_locations'])} origin locations for malware"
                    )
                    for location_name in profile["origin_locations"]:
                        location_obj = self._create_location(location_name)
                        if location_obj:
                            if not any(
                                x["id"] == location_obj["id"]
                                for x in additional_objects
                            ):
                                additional_objects.append(location_obj)

                            rel = self.create_relationship(
                                source_id=malware_id,
                                relationship_type="originates-from",
                                target_id=location_obj["id"],
                                description=f"{malware_name} originates from {location_name}",
                            )
                            if rel:
                                relationships.append(rel)

                # 4. INTRUSION SETS / CAMPAIGNS
                if profile.get("campaigns"):
                    self.helper.connector_logger.info(
                        f"[CONVERTER] Processing {len(profile['campaigns'])} campaigns"
                    )
                    for campaign_name in profile["campaigns"]:
                        intrusion_obj = self._create_intrusion_set(
                            campaign_name, malware_name
                        )
                        if intrusion_obj:
                            additional_objects.append(intrusion_obj)

                            # Relationship: Intrusion Set -> uses -> Malware
                            rel = self.create_relationship(
                                source_id=intrusion_obj["id"],
                                relationship_type="uses",
                                target_id=malware_id,
                                description=f"{campaign_name} campaign uses {malware_name}",
                            )
                            if rel:
                                relationships.append(rel)

                # 5. VULNERABILITIES (CVEs)
                if profile.get("target_cves"):
                    self.helper.connector_logger.info(
                        f"[CONVERTER] Processing {len(profile['target_cves'])} CVEs"
                    )
                    for cve_id in profile["target_cves"]:
                        vuln_obj = self._create_vulnerability(cve_id)
                        if vuln_obj:
                            additional_objects.append(vuln_obj)

                            # Relationship: Malware -> targets -> Vulnerability
                            rel = self.create_relationship(
                                source_id=malware_id,
                                relationship_type="targets",
                                target_id=vuln_obj["id"],
                                description=f"{malware_name} exploits {cve_id}",
                            )
                            if rel:
                                relationships.append(rel)

                # 6. RELATED MALWARE (WITH FULL PROFILE ENRICHMENT)
                if profile.get("related_malware"):
                    self.helper.connector_logger.info(
                        f"[CONVERTER] Processing {len(profile['related_malware'])} related malware families"
                    )
                    for related_name in profile["related_malware"]:
                        # This recursively enriches the related malware
                        related_mal, related_objs, related_rels = (
                            self._create_related_malware(related_name, malware_id)
                        )

                        if related_mal:
                            if not any(
                                x["id"] == related_mal["id"] for x in additional_objects
                            ):
                                additional_objects.append(related_mal)
                            additional_objects.extend(related_objs)
                            relationships.extend(related_rels)

                # 7. FIX: Add SYSTEMS TARGETED (Software)
                if profile.get("systems_targeted"):
                    self.helper.connector_logger.info(
                        f"[CONVERTER] Processing {len(profile['systems_targeted'])} targeted systems"
                    )
                    os_refs = []
                    for os_name in profile["systems_targeted"]:
                        software_obj = self._create_software(os_name)
                        if software_obj:
                            if not any(
                                x["id"] == software_obj["id"]
                                for x in additional_objects
                            ):
                                additional_objects.append(software_obj)
                            os_refs.append(software_obj["id"])

                    if os_refs:
                        # Add to the malware object as operating_system_refs
                        malware["operating_system_refs"] = os_refs

                # 8. FIX: Add TARGET SECTORS (Malware -> targets -> Sector)
                if profile.get("verticals_targeted"):
                    self.helper.connector_logger.info(
                        f"[CONVERTER] Processing {len(profile['verticals_targeted'])} target sectors for malware"
                    )
                    for sector_name in profile["verticals_targeted"]:
                        sector_obj = self._create_sector(sector_name)
                        if sector_obj:
                            if not any(
                                x["id"] == sector_obj["id"] for x in additional_objects
                            ):
                                additional_objects.append(sector_obj)

                            rel = self.create_relationship(
                                source_id=malware_id,
                                relationship_type="targets",
                                target_id=sector_obj["id"],
                                description=f"{malware_name} targets the {sector_name} sector",
                            )
                            if rel:
                                relationships.append(rel)

            self.helper.connector_logger.info(
                f"[CONVERTER] Comprehensive malware enrichment complete: "
                f"{len(additional_objects)} objects, {len(relationships)} relationships"
            )

            # De-duplicate additional_objects before returning
            final_additional_objects = {
                obj["id"]: obj for obj in additional_objects
            }.values()

            return malware, list(final_additional_objects), relationships

        except (KeyError, AttributeError, TypeError, ValueError) as e:
            self.helper.connector_logger.error(
                f"[CONVERTER] Error creating malware object: {str(e)}"
            )
            self.helper.connector_logger.error(
                f"[CONVERTER] Traceback: {traceback.format_exc()}"
            )
            return None, [], []

    def create_indicator_malware_relationship(
        self, indicator_id: str, malware_id: str, polyswarm_data: dict
    ) -> dict | None:
        """
        Creates the 'indicates' relationship between indicator and malware.
        """
        try:
            malware_families = polyswarm_data.get("poly_unite", ["Unknown"])
            family = malware_families[0]
            description = (
                f"This indicator is associated with {family}"
                " malware family based on PolySwarm analysis"
            )

            return self.create_relationship(
                source_id=indicator_id,
                relationship_type="indicates",
                target_id=malware_id,
                description=description,
            )

        except (KeyError, AttributeError, TypeError, ValueError) as e:
            self.helper.connector_logger.error(
                f"[CONVERTER] Error creating indicator-malware relationship: {str(e)}"
            )
            return None

    def create_observable_indicator_relationship(
        self, observable_id: str, indicator_id: str
    ) -> dict | None:
        """
        Creates the 'based-on' relationship between indicator and observable.
        """
        try:
            return self.create_relationship(
                source_id=indicator_id,
                relationship_type="based-on",
                target_id=observable_id,
                description="This indicator is based on the observed file hash",
            )

        except (KeyError, AttributeError, TypeError, ValueError) as e:
            self.helper.connector_logger.error(
                f"[CONVERTER] Error creating observable-indicator relationship: {str(e)}"
            )
            return None

    # ============= NETWORK IOC METHODS =============

    _IOC_DESCRIPTION = (
        "Observed network traffic from PolySwarm sandbox analysis. "
        "This traffic was seen during dynamic analysis and may not be "
        "malicious (e.g., CDN, legitimate services)."
    )

    def create_ioc_observables(
        self,
        observable_id: str,
        ioc_data: dict[str, Any],
        max_count: int = 20,
        ioc_score: int = 20,
        enabled_types: list[str] | None = None,
    ) -> list[dict]:
        """Create STIX observables + relationships for network IOCs.

        Fills IPs first, then domains, then URLs, stops at max_count.
        Each observable gets a `communicates-with` relationship to the
        file observable, a low score, and a sandbox-observed label.
        """
        if enabled_types is None:
            enabled_types = ["ip", "domain", "url"]

        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        objects: list[dict] = []
        count = 0

        # --- IPs (highest priority) ---
        if "ip" in enabled_types:
            for ip_str in ioc_data.get("ips", []):
                if count >= max_count:
                    break
                obs = self._create_ioc_ip(ip_str, current_time, ioc_score)
                if obs:
                    objects.append(obs)
                    objects.append(
                        self._create_ioc_relationship(
                            observable_id, obs["id"], current_time
                        )
                    )
                    count += 1

        # --- Domains (extracted from URLs) ---
        if "domain" in enabled_types:
            for domain in ioc_data.get("domains", []):
                if count >= max_count:
                    break
                obs = self._create_ioc_domain(domain, current_time, ioc_score)
                if obs:
                    objects.append(obs)
                    objects.append(
                        self._create_ioc_relationship(
                            observable_id, obs["id"], current_time
                        )
                    )
                    count += 1

        # --- Full URLs ---
        if "url" in enabled_types:
            for url in ioc_data.get("urls", []):
                if count >= max_count:
                    break
                obs = self._create_ioc_url(url, current_time, ioc_score)
                if obs:
                    objects.append(obs)
                    objects.append(
                        self._create_ioc_relationship(
                            observable_id, obs["id"], current_time
                        )
                    )
                    count += 1

        if count > 0:
            self.helper.connector_logger.info(
                f"[CONVERTER] Created {count} network IOC observables "
                f"+ {count} relationships (cap={max_count})"
            )

        return objects

    def _create_ioc_ip(self, ip_str: str, current_time: str, score: int) -> dict | None:
        """Create an IPv4 or IPv6 observable for a network IOC."""
        if self._is_ipv4(ip_str):
            obs_type = "ipv4-addr"
        elif self._is_ipv6(ip_str):
            obs_type = "ipv6-addr"
        else:
            return None

        obs_id = f"{obs_type}--{uuid.uuid5(SOFTWARE_NAMESPACE, ip_str)}"
        # ``ipv4-addr`` / ``ipv6-addr`` are STIX 2.1 SCOs — the
        # author must be set via ``x_opencti_created_by_ref`` (the
        # OpenCTI extension) and not via the SDO/SRO-only
        # ``created_by_ref`` property, which breaks strict STIX
        # validation.
        return {
            "type": obs_type,
            "spec_version": "2.1",
            "id": obs_id,
            "created": current_time,
            "modified": current_time,
            "value": ip_str,
            "x_opencti_score": score,
            "x_opencti_description": self._IOC_DESCRIPTION,
            "x_opencti_labels": ["polyswarm:sandbox-observed"],
            "x_opencti_created_by_ref": self.author.id,
        }

    def _create_ioc_domain(
        self, domain: str, current_time: str, score: int
    ) -> dict | None:
        """Create a domain-name observable for a network IOC."""
        if not self._is_domain(domain):
            return None

        obs_id = f"domain-name--{uuid.uuid5(SOFTWARE_NAMESPACE, domain)}"
        # ``domain-name`` is an SCO — see ``_create_ioc_ip`` above.
        return {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": obs_id,
            "created": current_time,
            "modified": current_time,
            "value": domain,
            "x_opencti_score": score,
            "x_opencti_description": self._IOC_DESCRIPTION,
            "x_opencti_labels": ["polyswarm:sandbox-observed"],
            "x_opencti_created_by_ref": self.author.id,
        }

    def _create_ioc_url(self, url: str, current_time: str, score: int) -> dict | None:
        """Create a url observable for a network IOC."""
        if not url or not url.startswith(("http://", "https://")):
            return None

        obs_id = f"url--{uuid.uuid5(SOFTWARE_NAMESPACE, url)}"
        # ``url`` is an SCO — see ``_create_ioc_ip`` above.
        return {
            "type": "url",
            "spec_version": "2.1",
            "id": obs_id,
            "created": current_time,
            "modified": current_time,
            "value": url,
            "x_opencti_score": score,
            "x_opencti_description": self._IOC_DESCRIPTION,
            "x_opencti_labels": ["polyswarm:sandbox-observed"],
            "x_opencti_created_by_ref": self.author.id,
        }

    def _create_ioc_relationship(
        self, source_id: str, target_id: str, current_time: str
    ) -> dict:
        """Create a communicates-with relationship from file to network IOC."""
        rel_id = StixCoreRelationship.generate_id(
            "communicates-with", source_id, target_id
        )
        return {
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "created": current_time,
            "modified": current_time,
            "relationship_type": "communicates-with",
            "source_ref": source_id,
            "target_ref": target_id,
            "description": (
                "Network traffic observed during PolySwarm sandbox analysis"
            ),
            "confidence": 30,
            "created_by_ref": self.author.id,
        }

    # ============= UTILITY METHODS =============

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        try:
            ipaddress.IPv4Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_domain(value: str) -> bool:
        is_valid_domain = validators.domain(value)
        return bool(is_valid_domain)

    def create_obs(self, value: str, obs_id: str = None) -> dict | None:
        """
        Create observable as plain dict.
        """
        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        if self._is_ipv6(value):
            obs_id = (
                obs_id
                or f"ipv6-addr--{str(uuid.uuid5(uuid.NAMESPACE_URL, f'ipv6:{value}'))}"
            )
            return {
                "type": "ipv6-addr",
                "spec_version": "2.1",
                "id": obs_id,
                "created": current_time,
                "modified": current_time,
                "value": value,
                "x_opencti_created_by_ref": self.author.id,
            }
        if self._is_ipv4(value):
            obs_id = (
                obs_id
                or f"ipv4-addr--{str(uuid.uuid5(uuid.NAMESPACE_URL, f'ipv4:{value}'))}"
            )
            return {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": obs_id,
                "created": current_time,
                "modified": current_time,
                "value": value,
                "x_opencti_created_by_ref": self.author.id,
            }
        if self._is_domain(value):
            obs_id = (
                obs_id
                or f"domain-name--{str(uuid.uuid5(uuid.NAMESPACE_URL, f'domain:{value}'))}"
            )
            return {
                "type": "domain-name",
                "spec_version": "2.1",
                "id": obs_id,
                "created": current_time,
                "modified": current_time,
                "value": value,
                "x_opencti_created_by_ref": self.author.id,
            }
        self.helper.connector_logger.error(
            "This observable value is not a valid IPv4 or IPv6 address nor DomainName: ",
            {"value": value},
        )
        return None
