from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connector.use_cases.enrich_domain import DomainEnricher
from connector.use_cases.enrich_ipv4 import Ipv4Enricher
from criminalip_client import CriminalIpClient
from pycti import OpenCTIConnectorHelper


class CriminalIPConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `CriminalIPConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper

        self.token = self.config.criminal_ip.token.get_secret_value()
        self.max_tlp = self.config.criminal_ip.max_tlp
        self.client = CriminalIpClient(helper=self.helper, token=self.token)

        self.domain_enricher = DomainEnricher(
            connector_logger=self.helper.connector_logger,
            client=self.client,
            converter_to_stix=ConverterToStix(self.helper),
        )
        self.ipv4_enricher = Ipv4Enricher(
            connector_logger=self.helper.connector_logger,
            client=self.client,
            converter_to_stix=ConverterToStix(self.helper),
        )

    def _extract_and_check_markings(self, entity: dict):
        """
        Extract TLP, and we check if the variable "max_tlp" is less than
        or equal to the markings access of the entity from OpenCTI
        If this is true, we can send the data to connector for enrichment.
        :param entity: Dict of observable from OpenCTI
        """
        tlp = "TLP:CLEAR"
        for marking_definition in entity.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        is_valid = self.helper.check_max_tlp(tlp, self.max_tlp)

        if not is_valid:
            raise ValueError(
                "[CONNECTOR] Do not send any data, TLP of the observable is greater than MAX TLP,"
                "the connector does not has access to this observable, please check the group of the connector user"
            )

    def _send_bundle(self, stix_objects: list) -> str:
        """
        Send the STIX bundle to the OpenCTI platform
        """
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(
            bundle=stix_objects_bundle, cleanup_inconsistent_bundle=True
        )
        return bundles_sent

    def entity_in_scope(self, data) -> bool:
        """
        Security to limit playbook triggers to something other than the initial scope
        :param data: Dictionary of data
        :return: boolean
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_split = data["entity_id"].split("--")
        entity_type = entity_split[0].lower()

        if entity_type in scopes:
            return True
        else:
            return False

    def process_message(self, data: dict) -> str:
        """
        Get the observable created/modified in OpenCTI and check which type to send for process
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param data: dict of data to process
        :return: string
        """
        try:
            opencti_entity = data["enrichment_entity"]
            self._extract_and_check_markings(opencti_entity)

            stix_objects = data["stix_objects"]
            observable = data["stix_entity"]

            obs_value = observable["value"]
            obs_type = observable["type"]

            if self.entity_in_scope(data):
                self.helper.connector_logger.info(
                    "[CONNECTOR] Processing entity",
                    {"type": obs_type, "value": obs_value},
                )

                match obs_type:
                    case "ipv4-addr":
                        enrichment_objects = self.ipv4_enricher.process_ipv4_enrichment(
                            observable
                        )
                    case "domain-name":
                        enrichment_objects = self.domain_enricher.process_domain_scan(
                            observable
                        )
                    case _:
                        raise ValueError(f"[CONNECTOR] Unsupported type: {obs_type}")

                if len(enrichment_objects) <= 1:  # only author, no real data
                    # Return the original bundle unchanged for playbook
                    self._send_bundle(stix_objects)
                    self.helper.connector_logger.info(
                        "[CONNECTOR] No enrichment data found", {"obs_value": obs_value}
                    )
                    return f"No enrichment data found for: {obs_value}"

                # Merge with existing stix objects and send
                all_objects = stix_objects + enrichment_objects
                bundles_sent = self._send_bundle(all_objects)

                self.helper.connector_logger.info(
                    "[CONNECTOR] Enrichment complete",
                    {"bundles_sent": len(bundles_sent), "value": obs_value},
                )
                self.helper.connector_logger.info(
                    "Sent bundle(s) for import", {"len_bundle": len(bundles_sent)}
                )
                return f"Sent {len(bundles_sent)} bundle(s) for import"

            else:
                if not data.get("event_type"):
                    # If it is not in scope AND entity bundle passed through playbook,
                    # we should return the original bundle unchanged
                    self._send_bundle(stix_objects)
                else:
                    raise ValueError(
                        f"Failed to process observable, {opencti_entity['entity_type']} is not a supported entity type."
                    )

        except Exception as err:
            # Send back original objects for playbook compatibility
            self._send_bundle(data["stix_objects"])
            # Handling other unexpected exceptions
            self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected Error occurred", {"error_message": str(err)}
            )
            return f"Unexpected Error occurred: {str(err)}"

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then enrich the information.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)
