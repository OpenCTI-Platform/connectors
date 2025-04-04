import json

from pycti import OpenCTIConnectorHelper

from .config_loader import ConfigConnector


class ConnectorTemplate:
    """
    Specifications of the Internal Import File connector

    This class encapsulates the main actions, expected to be run by any internal import file connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector listen file upload in the platform.
    After getting the file content, the connector will create a STIX bundle in order to be sent to ingest.
    It basically uses the same functions and principle than the internal enrichment connector type.
    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ

    """

    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper

    def process_message(self, data: dict) -> str:
        """
        Processing the import request
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param data: dict of data to process
        :return: string
        """
        try:
            # Extract information from entity data
            file_fetch = data["file_fetch"]
            file_uri = self.helper.opencti_url + file_fetch
            entity_id = data.get("entity_id", None)
            bypass_validation = data["bypass_validation"]

            self.helper.connector_logger.info(
                "Importing the file: ", {"file_uri": file_uri}
            )

            # Performing the import or file
            # ===========================
            # === Add your code below ===
            # ===========================

            # EXAMPLE

            file_content = self.helper.api.fetch_opencti_file(file_uri)

            if data["file_mime"] == "text/xml":
                bundle = json.loads(file_content)["objects"]
                file_content = json.dumps(bundle)
                bundle_sent = self.helper.send_stix2_bundle(
                    file_content,
                    bypass_validation=bypass_validation,
                    file_name=data["file_id"],
                    entity_id=entity_id,
                )

                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": {str(len(bundle_sent))}},
                )

            # ===========================
            # === Add your code above ===
            # ===========================

        except Exception as err:
            # Handling other unexpected exceptions
            return self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected Error occurred", {"error_message": str(err)}
            )

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then import the file.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)
