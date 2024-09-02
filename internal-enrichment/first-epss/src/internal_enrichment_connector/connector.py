from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .utils import is_cve_format


class FirstEPSSConnector:
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

    def _collect_intelligence(self, cve_name) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :param cve_name: CVE to collect intelligence from
        :return: List of STIX objects
        """

        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")

        self.author = self.converter_to_stix.create_author()

        enrichment_response = self.api.get_entity({"cve": cve_name})
        enrichment_infos = enrichment_response["data"]

        stix_objects = []

        for info in enrichment_infos:
            cve_name = info["cve"]
            epss_score = float(info["epss"])
            epss_percentile = float(info["percentile"])

            vulnerability_stix_object = self.converter_to_stix.create_vulnerability(
                {
                    "name": cve_name,
                    "x_opencti_epss_score": epss_score,
                    "x_opencti_epss_percentile": epss_percentile,
                },
            )

            stix_objects.append(vulnerability_stix_object)

        if stix_objects:
            stix_objects.append(self.author)

        return stix_objects

    def _process_submission(self, vulnerability: dict) -> list:
        """
        Get enrichment data and submit STIX bundle
        :param vulnerability: dict of vulnerability to enrich
        :return: List of sent bundles
        """

        stix_objects = self._collect_intelligence(vulnerability["name"])

        if stix_objects:
            self.stix_objects_list.extend(stix_objects)

            stix_objects_bundle = self.helper.stix2_create_bundle(
                self.stix_objects_list
            )
            bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)

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
        :param opencti_entity: Dict of vulnerability from OpenCTI
        :return: Boolean
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

            info_msg = "[CONNECTOR] Processing vulnerability for the following CVE identifier: "
            self.helper.connector_logger.info(info_msg, {"cve": stix_entity["name"]})

            if self.is_entity_in_scope(stix_entity) and is_cve_format(
                stix_entity["name"]
            ):
                bundles_sent = self._process_submission(stix_entity)
                if bundles_sent:
                    info_msg = (
                        "[API] CVE found and knowledge added for type: "
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
            return self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected Error occurred", {"error_message": str(err)}
            )

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then enrich the information.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)
