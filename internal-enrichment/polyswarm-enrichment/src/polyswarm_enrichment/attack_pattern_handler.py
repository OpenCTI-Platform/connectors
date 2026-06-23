"""
Attack Pattern Handler for OpenCTI PolySwarm Connector

Creates MITRE ATT&CK Attack Patterns in OpenCTI based on TTP data.
TTP technique metadata and malware-type-to-TTP mappings are provided
by the caller (fetched from polykg via ConnectorClient).  This module
has no network dependencies — it is a pure STIX factory.
"""

import traceback
from datetime import datetime, timezone

from pycti import AttackPattern, StixCoreRelationship

MITRE_KILL_CHAIN = "mitre-attack"


class AttackPatternHandler:
    """
    Creates MITRE ATT&CK Attack Patterns and malware/actor → uses relationships.

    Receives pre-fetched TTP data (techniques + type mappings) at init time.
    If no data is provided, attack pattern creation is skipped gracefully.
    """

    def __init__(
        self,
        helper,
        author_id: str,
        ttp_data: dict | None = None,
    ):
        """
        Initialize the Attack Pattern Handler.

        Args:
            helper: OpenCTI connector helper for logging
            author_id: STIX ID of the author/organization creating these objects
            ttp_data: Dict with 'techniques' and 'type_mappings' keys
                      (from ConnectorClient.fetch_attack_patterns)
        """
        self.helper = helper
        self.author_id = author_id
        self._attack_pattern_cache: dict[str, dict] = {}

        self._ttp_database: dict[str, dict] = {}
        self._type_ttp_map: dict[str, list[str]] = {}

        if ttp_data:
            techniques = ttp_data.get("techniques", {})
            type_mappings = ttp_data.get("type_mappings", {})
            if techniques:
                self._ttp_database = techniques
            if type_mappings:
                self._type_ttp_map = type_mappings

    def has_ttp_data(self) -> bool:
        """Check whether TTP data was loaded successfully."""
        return len(self._ttp_database) > 0

    def clear_cache(self) -> None:
        """Clear the attack pattern cache."""
        self._attack_pattern_cache = {}

    def _get_ttp_info(self, ttp_id: str) -> dict | None:
        """Look up technique metadata from loaded TTP database."""
        info = self._ttp_database.get(ttp_id)
        if not info:
            return None
        # polykg returns structured objects; normalize to plain dict
        if isinstance(info, dict):
            return {
                "name": info.get("name", ttp_id),
                "tactic": info.get("tactic", "unknown"),
                "description": info.get("description", ""),
            }
        return None

    def get_ttps_for_malware_types(self, malware_types: list[str]) -> list[str]:
        """
        Get relevant TTP IDs based on malware types.

        Args:
            malware_types: List of malware type strings (e.g., ["ransomware", "trojan"])

        Returns:
            List of unique TTP IDs
        """
        if not self._type_ttp_map:
            return []

        ttps: set = set()

        for mtype in malware_types:
            mtype_lower = mtype.lower().strip()

            # Direct match
            if mtype_lower in self._type_ttp_map:
                ttps.update(self._type_ttp_map[mtype_lower])
            else:
                # Partial match (e.g., "remote access trojan" contains "rat" and "trojan")
                for key in self._type_ttp_map:
                    if key in mtype_lower or mtype_lower in key:
                        ttps.update(self._type_ttp_map[key])

        return list(ttps)

    def create_attack_pattern(self, ttp_id: str) -> dict | None:
        """
        Create a STIX Attack Pattern object for a TTP.

        Args:
            ttp_id: MITRE ATT&CK technique ID (e.g., "T1059")

        Returns:
            STIX Attack Pattern dictionary or None
        """
        # Check cache
        if ttp_id in self._attack_pattern_cache:
            return self._attack_pattern_cache[ttp_id]

        try:
            ttp_info = self._get_ttp_info(ttp_id)

            if not ttp_info or ttp_info.get("tactic") == "unknown":
                self.helper.connector_logger.warning(
                    f"[ATTACK_PATTERN] Unknown TTP: {ttp_id}"
                )
                return None

            # Generate deterministic ID
            attack_pattern_id = AttackPattern.generate_id(
                name=f"{ttp_id} - {ttp_info['name']}",
                x_mitre_id=ttp_id,
            )

            current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            kill_chain_phases = [
                {
                    "kill_chain_name": MITRE_KILL_CHAIN,
                    "phase_name": ttp_info["tactic"],
                }
            ]

            # Sub-techniques: T1059.001 -> T1059/001
            technique_url_path = ttp_id.replace(".", "/")
            external_references = [
                {
                    "source_name": "mitre-attack",
                    "external_id": ttp_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_url_path}",
                }
            ]

            attack_pattern = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": attack_pattern_id,
                "created": current_time,
                "modified": current_time,
                "created_by_ref": self.author_id,
                "name": f"{ttp_id} - {ttp_info['name']}",
                "description": ttp_info["description"],
                "kill_chain_phases": kill_chain_phases,
                "external_references": external_references,
                "x_mitre_id": ttp_id,
                "confidence": 85,
            }

            self._attack_pattern_cache[ttp_id] = attack_pattern
            self.helper.connector_logger.info(
                f"[ATTACK_PATTERN] Created: {ttp_id} - {ttp_info['name']}"
            )

            return attack_pattern

        except (KeyError, TypeError, ValueError) as e:
            self.helper.connector_logger.error(
                f"[ATTACK_PATTERN] Error creating {ttp_id}: {str(e)}"
            )
            self.helper.connector_logger.error(
                f"[ATTACK_PATTERN] Traceback: {traceback.format_exc()}"
            )
            return None

    def create_attack_patterns_for_malware(
        self,
        malware_types: list[str],
        malware_id: str,
        malware_name: str,
        explicit_ttps: list[str] = None,
    ) -> tuple[list[dict], list[dict]]:
        """
        Create attack patterns and relationships for a malware based on its types.

        Args:
            malware_types: List of malware type strings
            malware_id: STIX ID of the malware object
            malware_name: Name of the malware
            explicit_ttps: Optional list of explicit TTP IDs to include

        Returns:
            Tuple of (attack_patterns, relationships)
        """
        if not self.has_ttp_data():
            self.helper.connector_logger.info(
                "[ATTACK_PATTERN] No TTP data available (polykg not loaded). Skipping."
            )
            return [], []

        attack_patterns = []
        relationships = []

        # Get TTPs based on malware types
        ttp_ids = self.get_ttps_for_malware_types(malware_types)

        # Add explicit TTPs if provided
        if explicit_ttps:
            ttp_ids = list(set(ttp_ids + explicit_ttps))

        if not ttp_ids:
            self.helper.connector_logger.info(
                f"[ATTACK_PATTERN] No TTPs mapped for malware types: {malware_types}"
            )
            return [], []

        self.helper.connector_logger.info(
            f"[ATTACK_PATTERN] Creating {len(ttp_ids)} attack patterns for {malware_name}"
        )

        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        for ttp_id in ttp_ids:
            attack_pattern = self.create_attack_pattern(ttp_id)

            if attack_pattern:
                # Avoid duplicates
                if not any(ap["id"] == attack_pattern["id"] for ap in attack_patterns):
                    attack_patterns.append(attack_pattern)

                # Create relationship: Malware -> uses -> Attack Pattern
                rel_id = StixCoreRelationship.generate_id(
                    "uses", malware_id, attack_pattern["id"]
                )

                ttp_info = self._get_ttp_info(ttp_id)
                relationship = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created": current_time,
                    "modified": current_time,
                    "created_by_ref": self.author_id,
                    "relationship_type": "uses",
                    "source_ref": malware_id,
                    "target_ref": attack_pattern["id"],
                    "description": f"{malware_name} uses {ttp_id} - {ttp_info['name']}",
                    "confidence": 75,
                }
                relationships.append(relationship)

        self.helper.connector_logger.info(
            f"[ATTACK_PATTERN] Created {len(attack_patterns)} patterns, "
            f"{len(relationships)} relationships for {malware_name}"
        )

        return attack_patterns, relationships

    def create_attack_patterns_for_actor(
        self,
        actor_id: str,
        actor_name: str,
        ttp_ids: list[str],
    ) -> tuple[list[dict], list[dict]]:
        """
        Create attack patterns and relationships for a threat actor.

        Args:
            actor_id: STIX ID of the threat actor
            actor_name: Name of the threat actor
            ttp_ids: List of TTP IDs associated with this actor

        Returns:
            Tuple of (attack_patterns, relationships)
        """
        if not self.has_ttp_data():
            return [], []

        attack_patterns = []
        relationships = []

        if not ttp_ids:
            return [], []

        self.helper.connector_logger.info(
            f"[ATTACK_PATTERN] Creating {len(ttp_ids)} attack patterns for actor {actor_name}"
        )

        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        for ttp_id in ttp_ids:
            attack_pattern = self.create_attack_pattern(ttp_id)

            if attack_pattern:
                if not any(ap["id"] == attack_pattern["id"] for ap in attack_patterns):
                    attack_patterns.append(attack_pattern)

                rel_id = StixCoreRelationship.generate_id(
                    "uses", actor_id, attack_pattern["id"]
                )

                ttp_info = self._get_ttp_info(ttp_id)
                relationship = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created": current_time,
                    "modified": current_time,
                    "created_by_ref": self.author_id,
                    "relationship_type": "uses",
                    "source_ref": actor_id,
                    "target_ref": attack_pattern["id"],
                    "description": f"{actor_name} uses {ttp_id} - {ttp_info['name']}",
                    "confidence": 70,
                }
                relationships.append(relationship)

        return attack_patterns, relationships
