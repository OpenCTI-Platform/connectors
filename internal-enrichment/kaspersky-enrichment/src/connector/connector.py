from kaspersky_client import KasperskyClient
from pycti import OpenCTIConnectorHelper

from .converter_to_stix import ConverterToStix
from .settings import ConnectorSettings


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

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `KasperskyConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper
        api_key = self.config.kaspersky.api_key.get_secret_value()
        self.client = KasperskyClient(
            self.helper,
            base_url=self.config.kaspersky.api_base_url,
            api_key=api_key,
            params={
                "count": 1,
                "sections": "LicenseInfo,Zone,FileGeneralInfo",
                "format": "json",
            },
        )
        self.converter_to_stix = ConverterToStix(
            self.helper,
            tlp_level="clear",
            # Pass any arguments necessary to the converter
        )

        # Define variables
        self.author = None
        self.stix_objects_list = []

    def resolve_file_hash(self, observable):
        if "hashes" in observable and "SHA-256" in observable["hashes"]:
            return observable["hashes"]["SHA-256"]
        if "hashes" in observable and "SHA-1" in observable["hashes"]:
            return observable["hashes"]["SHA-1"]
        if "hashes" in observable and "MD5" in observable["hashes"]:
            return observable["hashes"]["MD5"]
        raise ValueError(
            "Unable to enrich the observable, the observable does not have an SHA256, SHA1, or MD5"
        )

    def _process_file(self, observable) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """
        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")

        # Check file hash
        obs_hash = self.resolve_file_hash(observable)

        # Get entities
        self.client.get_file_info(obs_hash)

        # === Create the author
        # self.author = self.converter.create_author()

        # === Convert into STIX2 object and add it to the stix_object_list
        # entity_to_stix = self.converter_to_stix.create_obs(value,obs_id)
        # self.stix_object_list.append(entity_to_stix)

        # return self.stix_objects_list

        # ===========================
        # === Add your code above ===
        # ===========================
        raise NotImplementedError

    def entity_in_scope(self, obs_type) -> bool:
        """
        Security to limit playbook triggers to something other than the initial scope
        :param data: Dictionary of data
        :return: boolean
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_split = obs_type.split("--")
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

            # Extract information from entity data
            self.stix_objects_list = data["stix_objects"]
            observable = data["stix_entity"]
            obs_type = opencti_entity["entity_type"]

            info_msg = (
                "[CONNECTOR] Processing observable for the following entity type: "
            )
            self.helper.connector_logger.info(info_msg, {"type": {obs_type}})

            if self.entity_in_scope(obs_type):
                # Performing the collection of intelligence and enrich the entity
                match obs_type:
                    case "StixFile":
                        stix_objects = self._process_file(observable)
                    # case "IPv4-Addr":
                    #     stix_objects = self._process_ip(observable)
                    # case "Domain-Name" | "Hostname":
                    #     stix_objects = self._process_domain(observable)
                    # case "Url":
                    #     stix_objects = self._process_url(observable)
                    case _:
                        raise ValueError(
                            "Entity type is not supported",
                            {"entity_type": obs_type},
                        )

                if stix_objects is not None and len(stix_objects):
                    return self._send_bundle(stix_objects)
                else:
                    info_msg = "[CONNECTOR] No information found"
                    return info_msg

            else:
                if not data.get("event_type"):
                    # If it is not in scope AND entity bundle passed through playbook, we should return the original bundle unchanged
                    self._send_bundle(self.stix_objects_list)
                else:
                    # self.helper.connector_logger.info(
                    #     "[CONNECTOR] Skip the following entity as it does not concern "
                    #     "the initial scope found in the config connector: ",
                    #     {"entity_id": opencti_entity["entity_id"]},
                    # )
                    raise ValueError(
                        f"Failed to process observable, {opencti_entity['entity_type']} is not a supported entity type."
                    )
        except Exception as err:
            # Handling other unexpected exceptions
            return self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected Error occurred", {"error_message": str(err)}
            )

    def _send_bundle(self, stix_objects: list) -> str:
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)

        info_msg = (
            "Sending " + str(len(bundles_sent)) + " stix bundle(s) for worker import"
        )
        return info_msg

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then enrich the information.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)
