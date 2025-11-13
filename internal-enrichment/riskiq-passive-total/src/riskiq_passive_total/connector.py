from datetime import datetime, timedelta

from pycti import OpenCTIConnectorHelper
from stix2 import TLP_WHITE

from .client_api import ConnectorClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix


class RiskIQPassiveTotalConnector:
    """
    Specifications of the internal enrichment connector

    This class encapsulates the main actions, expected to be run by any internal enrichment connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to enrich a data (Observables) created or modified in the OpenCTI core platform.
    It will create a STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.
    Ingesting a bundle allow the connector to be compatible with the playbook automation feature.


    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

        - `converter_to_stix (ConnectorConverter(helper))`:
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ

    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        # playbook_compatible=True only if a bundle is sent !
        self.helper = OpenCTIConnectorHelper(
            config=self.config.load, playbook_compatible=True
        )
        self.api = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper)

        # Define variables
        self.author = None
        self.tlp = None
        self.stix_objects_list = []

    def _collect_intelligence(self, stix_entity) -> list:
        """
        Collects intelligence data from a specified source and converts it into STIX objects.

        This method interacts with an external API to retrieve enrichment data based on the
        provided STIX entity (observable). It processes the data and generates various
        STIX observables (e.g., IPv4Address, IPv6Address, EmailAddress, DomainName) along
        with relationships between them. The method appends these observables to a list which
        is returned for further processing.

        The method handles multiple types of DNS records (A, AAAA, SOA, MX, CNAME, NS) and
        creates corresponding STIX observables and relationships for each record type.
        The results are appended to the list and returned.

        :param stix_entity: A dictionary representing a STIX entity (observable) to be enriched.
                            Typically contains fields like 'id', 'value', etc.
        :return: A list of STIX objects, including observables and relationships between them.
                 If no enrichment data is found, an empty list is returned.

        """

        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")
        stix_objects = []

        # Create stix Identity
        self.author = self.converter_to_stix.create_author()

        # Collection of enrichment data associated with the entity's STIX value
        enrichment_observable = self.api.passivetotal_get_observables(
            stix_entity.get("value")
        )

        if enrichment_observable is None:
            return []

        for result in enrichment_observable.get("results", []):

            first_seen_date = datetime.fromisoformat(
                result.get("firstSeen").replace(" ", "T")
            )
            last_seen_date = datetime.fromisoformat(
                result.get("lastSeen").replace(" ", "T")
            )

            if first_seen_date == last_seen_date:
                last_seen_date = last_seen_date + timedelta(seconds=1)

            record_type = result.get("recordType")
            resolve_type = result.get("resolveType")

            # Create stix observable with relationship -> IPv4Address
            if record_type == "A" and resolve_type == "ip":
                ipv4_observable = self.converter_to_stix.create_ipv4_observable(result)
                stix_objects.append(ipv4_observable)

                ipv4_observable_relationship = (
                    self.converter_to_stix.create_stix_relationship(
                        stix_entity.get("id"),
                        "resolves-to",
                        ipv4_observable.get("id"),
                        first_seen_date,
                        last_seen_date,
                        "A record",
                    )
                )
                stix_objects.append(ipv4_observable_relationship)

                self.helper.connector_logger.debug(
                    "The generation of the observable stix of type IPv4-Addr as well as its relation with the entity "
                    "has been carried out well",
                    {
                        "record_type": record_type,
                        "resolve_type": resolve_type,
                        "ipv4_id": ipv4_observable.get("id"),
                        "relationship_id": ipv4_observable_relationship.get("id"),
                    },
                )

            # Create stix observable with relationship -> IPv6Address
            elif record_type == "AAAA" and resolve_type == "ip":
                ipv6_observable = self.converter_to_stix.create_ipv6_observable(result)
                stix_objects.append(ipv6_observable)

                ipv6_observable_relationship = (
                    self.converter_to_stix.create_stix_relationship(
                        stix_entity.get("id"),
                        "resolves-to",
                        ipv6_observable.get("id"),
                        first_seen_date,
                        last_seen_date,
                        "AAAA record",
                    )
                )
                stix_objects.append(ipv6_observable_relationship)

                self.helper.connector_logger.debug(
                    "The generation of the observable stix of type IPv6-Addr as well as its relation with the entity "
                    "has been carried out well",
                    {
                        "record_type": record_type,
                        "resolve_type": resolve_type,
                        "ipv4_id": ipv6_observable.get("id"),
                        "relationship_id": ipv6_observable_relationship.get("id"),
                    },
                )

            # Create stix observable with relationship -> EmailAddress
            elif record_type == "SOA" and resolve_type == "email":
                email_observable = self.converter_to_stix.create_email_observable(
                    result
                )
                stix_objects.append(email_observable)

                email_observable_relationship = (
                    self.converter_to_stix.create_stix_relationship(
                        stix_entity.get("id"),
                        "related-to",
                        email_observable.get("id"),
                        first_seen_date,
                        last_seen_date,
                        "SOA record",
                    )
                )
                stix_objects.append(email_observable_relationship)

                self.helper.connector_logger.debug(
                    "The generation of the observable stix of type Email-Addr as well as its relation with the entity "
                    "has been carried out well",
                    {
                        "record_type": record_type,
                        "resolve_type": resolve_type,
                        "ipv4_id": email_observable.get("id"),
                        "relationship_id": email_observable_relationship.get("id"),
                    },
                )

            # Create stix observable with relationship -> DomainName
            elif (
                record_type in ["SOA", "MX", "CNAME", "A", "NS"]
                and resolve_type == "domain"
            ):
                domain_observable = self.converter_to_stix.create_domain_observable(
                    result
                )
                stix_objects.append(domain_observable)

                target_relationship = (
                    stix_entity.get("id")
                    if record_type != "A"
                    else domain_observable.get("id")
                )
                source_relationship = (
                    domain_observable.get("id")
                    if record_type != "A"
                    else stix_entity.get("id")
                )

                domain_observable_relationship = (
                    self.converter_to_stix.create_stix_relationship(
                        target_relationship,
                        "resolves-to",
                        source_relationship,
                        first_seen_date,
                        last_seen_date,
                        f"""{record_type} record""",
                    )
                )
                stix_objects.append(domain_observable_relationship)

                self.helper.connector_logger.debug(
                    "The generation of the observable stix of type Domain-Name as well as its relation with the entity "
                    "has been carried out well",
                    {
                        "record_type": record_type,
                        "resolve_type": resolve_type,
                        "ipv4_id": domain_observable.get("id"),
                        "relationship_id": domain_observable_relationship.get("id"),
                    },
                )

            else:
                continue

        if stix_objects:
            stix_objects.append(self.author)
            stix_objects.append(TLP_WHITE)

        return stix_objects

    def _process_submission(self, stix_entity: dict) -> list:
        """
        Get enrichment data and submit STIX bundle
        :param stix_entity: dict of object to enrich
        :return: List of sent bundles
        """

        stix_objects = self._collect_intelligence(stix_entity)
        if stix_objects:
            self.stix_objects_list.extend(stix_objects)

            stix_objects_bundle = self.helper.stix2_create_bundle(
                self.stix_objects_list
            )
            bundles_sent = self.helper.send_stix2_bundle(
                bundle=stix_objects_bundle, cleanup_inconsistent_bundle=True
            )
            return bundles_sent

    def is_entity_in_scope(self, data) -> bool:
        """
        Security to limit playbook triggers to something other than the initial entity scope
        :param data: Dictionary of data
        :return: boolean
        """

        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_type = data["type"].lower()

        return entity_type in scopes

    def extract_and_check_markings(self, opencti_entity: dict) -> None:
        """
        Extract TLP, and we check if the variable "max_tlp" is less than
        or equal to the markings access of the entity from OpenCTI
        If this is true, we can send the data to connector for enrichment.
        :param opencti_entity: observable to enrich
        :return: None
        """

        if len(opencti_entity["objectMarking"]) != 0:
            for marking_definition in opencti_entity["objectMarking"]:
                if marking_definition["definition_type"] == "TLP":
                    self.tlp = marking_definition["definition"]

        valid_max_tlp = self.helper.check_max_tlp(self.tlp, self.config.max_tlp)

        if not valid_max_tlp:
            raise ValueError(
                "[CONNECTOR] Do not send any data, TLP of the observable is greater than MAX TLP,"
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
            self.stix_objects_list = data["stix_objects"]

            stix_entity = data["stix_entity"]
            opencti_entity = data["enrichment_entity"]

            self.extract_and_check_markings(opencti_entity)

            info_msg = (
                f"[CONNECTOR] Processing observable/indicator: {stix_entity['value']}"
            )
            self.helper.connector_logger.info(info_msg)

            if self.is_entity_in_scope(stix_entity):
                bundles_sent = self._process_submission(stix_entity)
                if bundles_sent:
                    info_msg = (
                        "[API] Observable found and knowledge added for type: "
                        + stix_entity["type"]
                        + ", sending "
                        + str(len(bundles_sent))
                        + " stix bundle(s) for worker import"
                    )
                else:
                    info_msg = "[CONNECTOR] No information found"

            else:
                info_msg = (
                    "[CONNECTOR] Skip the following entity as it does not concern "
                    + "the initial scope found in the connector config: "
                    + str({"entity_id": stix_entity["id"]})
                )

            self.helper.connector_logger.info(info_msg)

            return info_msg

        except Exception as err:
            self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected Error occurred", {"error_message": str(err)}
            )
            raise

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then enrich the information.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)
