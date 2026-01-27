import os
import uuid
from datetime import datetime
from typing import Dict

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from .client_api import ScoutSearchConnectorClient
from .utils import is_valid_strict_domain


class ScoutSearchConnectorConfig:
    """Configuration holder for Scout Search Connector connector."""

    # pylint: disable=too-few-public-methods
    def __init__(self, config):
        self.api_base_url = get_config_variable(
            "PURE_SIGNAL_SCOUT_API_URL", ["pure_signal_scout", "api_url"], config
        )
        self.api_key = get_config_variable(
            "PURE_SIGNAL_SCOUT_API_TOKEN", ["pure_signal_scout", "api_token"], config
        )
        self.max_tlp = get_config_variable(
            "PURE_SIGNAL_SCOUT_MAX_TLP",
            ["pure_signal_scout", "max_tlp"],
            config,
            default="TLP:AMBER",
        )
        self.search_interval = get_config_variable(
            "PURE_SIGNAL_SCOUT_SEARCH_INTERVAL",
            ["pure_signal_scout", "search_interval"],
            config,
            default=1,
        )
        self.pattern_type = get_config_variable(
            "PURE_SIGNAL_SCOUT_INDICATOR_PATTERN_TYPE",
            ["pure_signal_scout", "pattern_type"],
            config,
            default="pure-signal-scout",
        )


class ScoutSearchConnectorConnector:
    def __init__(self):
        # Initialize configuration
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as f:
                config = yaml.load(f, Loader=yaml.FullLoader)
        else:
            config = {}

        self.helper = OpenCTIConnectorHelper(config, playbook_compatible=True)
        self.config = ScoutSearchConnectorConfig(config)
        self.tlp = None

        # Initialize API client
        self.client = ScoutSearchConnectorClient(self.helper, self.config)

        self.helper.connector_logger.info(
            "[ScoutSearchConnector] Connector initialized",
            {
                "connector_id": self.helper.connect_id,
                "connector_name": self.helper.connect_name,
                "connector_scope": self.helper.connect_scope,
            },
        )

    def extract_and_check_markings(self, opencti_entity: dict) -> None:
        """
        Extract TLP, and we check if the variable "max_tlp" is less than
        or equal to the markings access of the entity from OpenCTI.
        If this is true, we can send the data to connector for enrichment.
        :param opencti_entity: Dict of observable from OpenCTI
        :return: None
        """
        if opencti_entity.get("objectMarking"):
            for marking_definition in opencti_entity["objectMarking"]:
                if marking_definition.get("definition_type") == "TLP":
                    self.tlp = marking_definition.get("definition")

        valid_max_tlp = self.helper.check_max_tlp(self.tlp, self.config.max_tlp)

        if not valid_max_tlp:
            raise ValueError(
                "[CONNECTOR] Do not send any data, TLP of the observable is greater than MAX TLP,"
                "the connector does not have access to this observable, please check the group of the connector user"
            )

    def process_stix_data(self, data: Dict, original_entity_id: str) -> list:
        """
        Process STIX data: Replace invalid relationships, skip unresolvable ones,
        and retain supported ones.
        """
        try:
            if not data or "objects" not in data:
                return []

            objects = list(data.get("objects", []))
            filtered_objects = []
            removed_domain_objects_id = []

            # Relationship replacements
            relationship_replacements = {
                ("indicator", "ipv4-addr", "indicates"): "based-on",
                ("indicator", "ipv6-addr", "indicates"): "based-on",
                ("indicator", "domain-name", "indicates"): "based-on",
                ("ipv4-addr", "ipv4-addr", "communicates-with"): "related-to",
                ("ipv6-addr", "ipv6-addr", "communicates-with"): "related-to",
            }

            # Relationships to skip entirely
            invalid_skip_relationships = {
                ("network-traffic", "location", "located-at"),
                ("network-traffic", "autonomous-system", "belongs-to"),
                ("x509-certificate", "autonomous-system", "belongs-to"),
                ("domain-name", "domain-name", "uses"),
                ("ipv4-addr", "x509-certificate", "uses"),
                ("ipv6-addr", "x509-certificate", "uses"),
                ("ipv4-addr", "identity", "owned-by"),
                ("ipv6-addr", "identity", "owned-by"),
            }

            def is_skippable_object(obj) -> bool:
                obj_type = obj.get("type")
                if obj_type == "network-traffic":
                    return True
                if obj_type == "domain-name" and not is_valid_strict_domain(
                    obj.get("value", "")
                ):
                    removed_domain_objects_id.append(obj.get("id", ""))
                    return True
                return False

            def process_relationship(obj) -> bool:
                source_ref = obj.get("source_ref", "")
                target_ref = obj.get("target_ref", "")
                rel_type = obj.get("relationship_type", "")

                source_type = source_ref.split("--")[0] if "--" in source_ref else ""
                target_type = target_ref.split("--")[0] if "--" in target_ref else ""

                # Skip if related to removed domain objects
                if (
                    source_ref in removed_domain_objects_id
                    or target_ref in removed_domain_objects_id
                ):
                    return False

                # Skip network-traffic relationships
                if source_type == "network-traffic" or target_type == "network-traffic":
                    return False

                # Skip redundant domain-to-domain relationships
                if (
                    source_type == target_type == "domain-name"
                    and source_ref == target_ref
                ):
                    return False

                # Skip irrelevant relationship types
                if rel_type == "issued-in":
                    return False

                # Replace relationship if a replacement exists
                key = (source_type, target_type, rel_type)
                if key in relationship_replacements:
                    obj["relationship_type"] = relationship_replacements[key]

                # Skip invalid/unresolvable relationships
                if key in invalid_skip_relationships:
                    return False

                # Otherwise, retain
                return True

            for obj in objects:
                if is_skippable_object(obj):
                    continue

                if obj.get("type") == "relationship":
                    if not process_relationship(obj):
                        continue

                filtered_objects.append(obj)

            self.helper.connector_logger.info(
                f"[ScoutSearchConnector] Filtered STIX objects: {len(objects)} → {len(filtered_objects)}"
            )

            new_relationships = []
            for obj in filtered_objects:
                if obj.get("type") not in [
                    "relationship",
                    "identity",
                    "x509-certificate",
                ]:
                    # Create a relationship between the Indicator and this object
                    relationship = {
                        "id": f"relationship--{str(uuid.uuid4())}",
                        "type": "relationship",
                        "relationship_type": "related-to",
                        "source_ref": original_entity_id,
                        "target_ref": obj.get("id"),
                        "created": datetime.now().isoformat() + "Z",
                        "modified": datetime.now().isoformat() + "Z",
                    }
                    new_relationships.append(relationship)

            # Add all relationships at once after the loop
            filtered_objects.extend(new_relationships)

            return filtered_objects or []

        except Exception as e:
            self.helper.connector_logger.error(
                "[ScoutSearchConnector] Error processing STIX data", {"error": str(e)}
            )
            return []

    def process_message(self, data: Dict) -> str:
        """Process enrichment message from OpenCTI"""
        try:
            opencti_entity = data.get("enrichment_entity")
            self.extract_and_check_markings(opencti_entity)
            # Extract entity information
            self.helper.connector_logger.info(
                "[ScoutSearchConnector] Enrichment message received", data
            )
            entity_id = opencti_entity["standard_id"]
            observable_type = opencti_entity["entity_type"]
            pattern = opencti_entity["pattern"]
            pattern_type = opencti_entity["pattern_type"]

            self.helper.connector_logger.info(
                "[ScoutSearchConnector] Processing enrichment request",
                {
                    "entity_id": entity_id,
                    "observable_type": observable_type,
                    "pattern": pattern,
                    "pattern_type": pattern_type,
                },
            )

            # Check if observable type is supported
            if observable_type not in ["Indicator"]:
                self.helper.connector_logger.warning(
                    "[ScoutSearchConnector] Unsupported observable type",
                    {"observable_type": observable_type},
                )
                return "Unsupported observable type"
            if pattern_type != self.config.pattern_type:
                self.helper.connector_logger.warning(
                    "[ScoutSearchConnector] Unsupported observable type",
                    {"Configured pattern_type": pattern_type,
                    "Supported pattern_type": self.config.pattern_type
                    },
                )
                return "Unsupported observable type"

            # Call external API to get intelligence
            intelligence_data = self.client.get_entity(
                observable_type, pattern
            )

            if not intelligence_data:
                self.helper.connector_logger.info(
                    "[ScoutSearchConnector] No intelligence data found",
                    {"pattern": pattern},
                )
                return "No intelligence data found"

            self.helper.connector_logger.info(
                "[ScoutSearchConnector] Processing STIX bundle",
                {
                    "pattern": pattern,
                    "bundle_objects": len(intelligence_data.get("objects", [])),
                },
            )

            processed_data = self.process_stix_data(intelligence_data, entity_id)

            if len(processed_data) == 0:
                self.helper.connector_logger.info(
                    "[ScoutSearchConnector] No processed data found",
                    {"pattern": pattern},
                )
                return "No Enrichment Data Found from API"

            serialized_bundle = self.helper.stix2_create_bundle(processed_data)
            self.helper.send_stix2_bundle(bundle=serialized_bundle, update=True)
            self.helper.connector_logger.info(
                "[ScoutSearchConnector] Data ingestion started",
                {"pattern": pattern},
            )

            return "Data fetched successfully and ingestion process has started"

        except Exception as e:
            self.helper.connector_logger.error(
                "[ScoutSearchConnector] Error processing message",
                {
                    "pattern": (
                        pattern
                        if "pattern" in locals()
                        else "unknown"
                    ),
                    "error": str(e),
                },
            )
            return f"Error: {str(e)}"

    def start(self):
        """Start the connector"""
        self.helper.connector_logger.info(
            "[ScoutSearchConnector] Starting connector",
            {"api_url": self.config.api_base_url},
        )
        self.helper.listen(self.process_message)
