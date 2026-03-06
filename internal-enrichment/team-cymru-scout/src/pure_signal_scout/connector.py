from typing import Dict

from connectors_sdk.models import ExternalReference, OrganizationAuthor
from pure_signal_scout.client_api import PureSignalScoutClient
from pure_signal_scout.settings import ConnectorSettings
from pure_signal_scout.utils import is_valid_strict_domain
from pycti import OpenCTIConnectorHelper


class PureSignalScoutConnectorConfig:
    def __init__(self, config):
        self.api_base_url = config.pure_signal_scout.api_url
        self.api_key = config.pure_signal_scout.api_token.get_secret_value()
        self.max_tlp = config.pure_signal_scout.max_tlp


class PureSignalScoutConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.helper = helper
        self.config = config
        self.tlp = None

        # Initialize API client
        self.client = PureSignalScoutClient(
            self.helper, PureSignalScoutConnectorConfig(self.config)
        )

        external_reference = ExternalReference(
            source_name="Team Cymru Scout",
            url="https://www.team-cymru.com/pure-signal",
            description="Team Cymru Scout Search API",
        )
        self.team_cymru_identity = OrganizationAuthor(
            name="Team Cymru",
            external_references=[external_reference],
        ).to_stix2_object()

        self.helper.connector_logger.info(
            "[PureSignalScout] Connector initialized",
            {
                "connector_id": self.helper.connect_id,
                "connector_name": self.helper.connect_name,
                "connector_scope": self.helper.connect_scope,
                "author_id": self.team_cymru_identity["id"],
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

        valid_max_tlp = self.helper.check_max_tlp(
            self.tlp, self.config.pure_signal_scout.max_tlp
        )

        if not valid_max_tlp:
            raise ValueError(
                "[CONNECTOR] Do not send any data, TLP of the observable is greater than MAX TLP,"
                "the connector does not have access to this observable, please check the group of the connector user"
            )

    def process_stix_data(self, data: Dict) -> list:
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
                ("ipv4-addr", "identity", "owned-by"): "related-to",
                ("ipv6-addr", "identity", "owned-by"): "related-to",
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

                obj["created_by_ref"] = self.team_cymru_identity["id"]
                filtered_objects.append(obj)

            if filtered_objects:
                filtered_objects.append(self.team_cymru_identity)

            self.helper.connector_logger.info(
                f"[PureSignalScout] Filtered STIX objects: {len(objects)} → {len(filtered_objects)}"
            )

            return filtered_objects or []

        except Exception as e:
            self.helper.connector_logger.error(
                "[PureSignalScout] Error processing STIX data", {"error": str(e)}
            )
            return []

    def process_message(self, data: Dict) -> str:
        """Process enrichment message from OpenCTI"""
        try:
            opencti_entity = data["enrichment_entity"]
            self.extract_and_check_markings(opencti_entity)
            # Extract entity information
            self.helper.connector_logger.info(
                "[PureSignalScout] Enrichment message received", data
            )
            entity_id = opencti_entity["standard_id"]
            observable_type = opencti_entity["entity_type"]
            observable_value = opencti_entity["value"]

            self.helper.connector_logger.info(
                "[PureSignalScout] Processing enrichment request",
                {
                    "entity_id": entity_id,
                    "observable_type": observable_type,
                    "observable_value": observable_value,
                },
            )

            # Check if observable type is supported
            if observable_type not in ["IPv4-Addr", "IPv6-Addr", "Domain-Name"]:
                self.helper.connector_logger.warning(
                    "[PureSignalScout] Unsupported observable type",
                    {"observable_type": observable_type},
                )
                return "Unsupported observable type"

            # Call external API to get intelligence
            intelligence_data = self.client.get_entity(
                observable_type, observable_value
            )

            if not intelligence_data:
                self.helper.connector_logger.info(
                    "[PureSignalScout] No intelligence data found",
                    {"observable_value": observable_value},
                )
                return "No intelligence data found"

            self.helper.connector_logger.info(
                "[PureSignalScout] Processing STIX bundle",
                {
                    "observable_value": observable_value,
                    "bundle_objects": len(intelligence_data.get("objects", [])),
                },
            )

            processed_data = self.process_stix_data(intelligence_data)

            if len(processed_data) == 0:
                self.helper.connector_logger.info(
                    "[PureSignalScout] No processed data found",
                    {"observable_value": observable_value},
                )
                return "No Enrichment Data Found from API"

            serialized_bundle = self.helper.stix2_create_bundle(processed_data)
            self.helper.send_stix2_bundle(
                bundle=serialized_bundle, update=True, cleanup_inconsistent_bundle=True
            )
            self.helper.connector_logger.info(
                "[PureSignalScout] Data ingestion started",
                {"observable_value": observable_value},
            )

            return "Data fetched successfully and ingestion process has started"

        except Exception as e:
            self.helper.connector_logger.error(
                "[PureSignalScout] Error processing message",
                {
                    "observable_value": (
                        observable_value
                        if "observable_value" in locals()
                        else "unknown"
                    ),
                    "error": str(e),
                },
            )
            return f"Error: {str(e)}"

    def start(self):
        """Start the connector"""
        self.helper.connector_logger.info(
            "[PureSignalScout] Starting connector",
            {
                "api_url": self.config.pure_signal_scout.api_url,
            },
        )
        self.helper.listen(self.process_message)
