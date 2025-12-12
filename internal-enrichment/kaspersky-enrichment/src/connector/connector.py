from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connector.use_cases.enrich_file import FileEnricher
from connector.use_cases.enrich_ipv4 import Ipv4Enricher
from connector.utils import entity_in_scope
from kaspersky_client import KasperskyClient
from pycti import OpenCTIConnectorHelper


class KasperskyConnector:
    """
    Specifications of the internal enrichment connector:

    This class encapsulates the main actions, expected to be run by any connector of type `INTERNAL_ENRICHMENT`.
    This type of connector aim to enrich entities (e.g. vulnerabilities, indicators, observables ...) created or modified on OpenCTI.
    It will create a STIX bundle and send it on OpenCTI.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.
    To be compatible with the "playbook automation" feature, this connector MUST always send back a STIX bundle containing the entity to enrich.

    ---

    Attributes:
        config (ConnectorSettings):
            Store the connector's configuration. It defines how to connector will behave.
        helper (OpenCTIConnectorHelper):
            Handle the connection and the requests between the connector, OpenCTI and the workers.
            _All connectors MUST use the connector helper with connector's configuration._
        converter_to_stix (ConnectorConverter):
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ

    """

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Initialize `KasperskyConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper
        file_sections = self.config.kaspersky.file_sections
        ipv4_sections = self.config.kaspersky.ipv4_sections
        zone_octi_score_mapping = self.config.kaspersky.zone_octi_score_mapping
        api_key = self.config.kaspersky.api_key.get_secret_value()

        client = KasperskyClient(
            self.helper,
            base_url=self.config.kaspersky.api_base_url,
            api_key=api_key,
            params={
                "count": 1,
                "format": "json",
            },
        )

        converter_to_stix = ConverterToStix(self.helper)

        self.file_enricher = FileEnricher(
            helper=self.helper,
            client=client,
            sections=file_sections,
            zone_octi_score_mapping=zone_octi_score_mapping,
            converter_to_stix=converter_to_stix,
        )
        self.ipv4_enricher = Ipv4Enricher(
            helper=self.helper,
            client=client,
            sections=ipv4_sections,
            zone_octi_score_mapping=zone_octi_score_mapping,
            converter_to_stix=converter_to_stix,
        )

        # Define variables
        self.stix_objects = []

    def _send_bundle(self, stix_objects: list) -> str:
        """
        Send the STIX bundle to the OpenCTI platform
        """
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)

        info_msg = (
            "Sending " + str(len(bundles_sent)) + " stix bundle(s) for worker import"
        )
        return info_msg

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

            # Extract information from entity data
            self.stix_objects = data["stix_objects"]
            observable = data["stix_entity"]
            obs_type = opencti_entity["entity_type"]

            info_msg = (
                "[CONNECTOR] Processing observable for the following entity type: "
            )
            self.helper.connector_logger.info(info_msg, {"type": {obs_type}})

            if entity_in_scope(self.helper.connect_scope, obs_type):
                # Performing the collection of intelligence and enrich the entity
                match obs_type:
                    case "StixFile":
                        octi_objects = self.file_enricher.process_file_enrichment(
                            observable
                        )
                    case "IPv4-Addr":
                        octi_objects = self.ipv4_enricher.process_ipv4_enrichment(
                            observable
                        )
                    # case "Domain-Name" | "Hostname":
                    #     octi_objects = self.domain_enricher.process_domain_enrichment(
                    #         observable
                    #     )
                    # case "Url":
                    #     octi_objects = self.url_enricher.process_url_enrichment(
                    #         observable
                    #     )
                    case _:
                        raise ValueError(
                            "Entity type is not supported",
                            {"entity_type": obs_type},
                        )

                bundle_objects = self.stix_objects + octi_objects

                if bundle_objects is not None and len(bundle_objects):
                    return self._send_bundle(bundle_objects)
                else:
                    info_msg = "[CONNECTOR] No information found"
                    return info_msg

            else:
                if not data.get("event_type"):
                    # If it is not in scope AND entity bundle passed through playbook,
                    # we should return the original bundle unchanged
                    self._send_bundle(self.stix_objects)
                else:
                    raise ValueError(
                        f"Failed to process observable, {opencti_entity['entity_type']} is not a supported entity type."
                    )
        except Exception as err:
            # Handling other unexpected exceptions
            msg = f"[Kaspersky Enrichment] Unexpected Error occurred: {err}"
            raise Exception(msg)

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then enrich the information.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)
