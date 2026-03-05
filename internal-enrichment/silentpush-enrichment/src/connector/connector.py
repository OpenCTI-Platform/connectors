from pycti import OpenCTIConnectorHelper
from silentpush_client import SilentpushClient

from .settings import ConnectorSettings
from .use_cases import (
    DomainEnricher,
    IndicatorEnricher,
    IPv4Enricher,
    IPv6Enricher,
    URLEnricher,
)


class SilentpushConnector:
    """
    This connector enriches IPs, domains, hostnames and URLs using the SilentPush API.
    It retrieves intelligence such as ASN ownership, geolocation, PTR records,
    subnet reputation, and various threat-related flags.

    This connector works for the following OpenCTI observable types:
    * IPv4-Addr
    * IPv6-Addr
    * Domain-Name
    * Hostname
    * URL
    * Indicator (containing one of the above observables)

    ---

    Attributes:
        config (ConnectorSettings):
            Store the connector's configuration. It defines how to connector will behave.
        helper (OpenCTIConnectorHelper):
            Handle the connection and the requests between the connector, OpenCTI and the workers.
            _All connectors MUST use the connector helper with connector's configuration._
        client (SilentpushClient):
            Provide methods to request the external API.
    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ

    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `SilentpushConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper

        self.client = SilentpushClient(
            self.helper,
            base_url=self.config.silentpush.api_base_url,
            api_key=self.config.silentpush.api_key.get_secret_value(),
            verify=self.config.silentpush.verify_cert,
        )

        # Define variables
        self.author = None
        self.tlp = None
        self.stix_objects_list = []

    def _collect_intelligence(self, observable) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """
        self.helper.connector_logger.info("[SilentPush] Starting enrichment...")
        type = observable["type"]
        match type:
            case "ipv4-addr":
                enricher_class = IPv4Enricher
            case "ipv6-addr":
                enricher_class = IPv6Enricher
            case "domain-name" | "hostname":
                enricher_class = DomainEnricher
            case "url":
                enricher_class = URLEnricher
            case "indicator":
                enricher_class = IndicatorEnricher
            case _:
                raise ValueError(f"[SilentPush] Unsupported observable type: {type}")

        return enricher_class(self.helper, self.client, observable).process()

    def entity_in_scope(self, data) -> bool:
        """
        Security to limit playbook triggers to something other than the initial scope
        :param data: Dictionary of data
        :return: boolean
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_split = data["entity_id"].split("--")
        entity_type = entity_split[0].lower()

        return entity_type in scopes

    def extract_and_check_markings(self, opencti_entity: dict) -> None:
        """
        Extract TLP, and we check if the variable "max_tlp" is less than
        or equal to the markings access of the entity from OpenCTI
        If this is true, we can send the data to connector for enrichment.
        :param opencti_entity: Dict of observable from OpenCTI
        :return: Boolean
        """
        self.tlp = None
        if len(opencti_entity["objectMarking"]) != 0:
            for marking_definition in opencti_entity["objectMarking"]:
                if marking_definition["definition_type"] == "TLP":
                    self.tlp = marking_definition["definition"]

        valid_max_tlp = self.helper.check_max_tlp(
            self.tlp, self.config.silentpush.max_tlp
        )

        if not valid_max_tlp:
            raise ValueError(
                "[SilentPush] Do not send any data, TLP of the observable is greater than MAX TLP,"
                "the connector does not has access to this observable, please check the group of the connector user"
            )

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
            self.extract_and_check_markings(opencti_entity)

            # To enrich the data, you can add more STIX object in stix_objects
            self.stix_objects_list = data["stix_objects"]
            observable = data["stix_entity"]

            info_msg = (
                "[[SilentPush]] Processing observable for the following entity type: "
            )
            self.helper.connector_logger.info(info_msg, {"type": {observable["type"]}})

            if self.entity_in_scope(data):
                # Performing the collection of intelligence and enrich the entity
                octi_objects = self._collect_intelligence(observable)
                stix_objects = [
                    octi_object.to_stix2_object() for octi_object in octi_objects
                ]
                if stix_objects is not None and len(stix_objects):
                    return self._send_bundle(stix_objects)
                else:
                    info_msg = "[[SilentPush]] No information found"
                    return info_msg
            else:
                if not data.get("event_type"):
                    # If it is not in scope AND entity bundle passed through playbook, we should return the original bundle unchanged
                    self._send_bundle(self.stix_objects_list)
                else:
                    raise ValueError(
                        f"Failed to process observable, {opencti_entity['entity_type']} is not a supported entity type."
                    )
        except Exception as err:
            # Handling other unexpected exceptions
            return self.helper.connector_logger.error(
                "[[SilentPush]] Unexpected Error occurred", {"error_message": str(err)}
            )

    def _send_bundle(self, stix_objects: list) -> str:
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.connector_logger.debug(stix_objects_bundle)
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)

        info_msg = f"Sending {len(bundles_sent)} stix bundle(s) for worker import"
        return info_msg

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then enrich the information.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)
