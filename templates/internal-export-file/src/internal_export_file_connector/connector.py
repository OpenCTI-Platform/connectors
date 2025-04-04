from pycti import OpenCTIConnectorHelper

from .config_loader import ConfigConnector


class ConnectorTemplate:
    """
    Specifications of the internal export connector

    This class encapsulates the main actions, expected to be run by any internal export file connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to support exporting features.
    Based on its configuration, it listens for execution commands through its RabbitMQ queue.
    Upon receiving an event, the connector generates a file and re-uploads the content back into the platform.
    This connector will do direct API call from OpenCTI to export the file
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
        - `self.helper.api.stix_core_object.push_list_export()` is used to push list of entities for export
        - `self.helper.api.stix_cyber_observable.push_list_export()` is used to push list of entities for export
        - `self.helper.api.stix_domain_object.push_list_export()` is used to push list of entities for export

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
        Processing the export request
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param data: dict of data to process
        :return: string
        """
        try:
            # Extract information from entity data
            entity_id = data.get("entity_id")
            entity_type = data["entity_type"]
            file_name = data["file_name"]
            export_type = data["export_type"]
            file_markings = data["file_markings"]
            # main_filter = data.get("main_filter")
            access_filter = data.get("access_filter")
            export_scope = data["export_scope"]  # query or selection or single

            # Performing the exportation of file
            # ===========================
            # === Add your code below ===
            # ===========================

            # EXAMPLE

            self.helper.connector_logger.info(
                "Uploading",
                {
                    "entity_type": entity_type,
                    "export_type": export_type,
                    "file_name": file_name,
                },
            )

            json_bundle = None
            list_filters = None

            if export_scope == "selection":
                list_filters = "selected_ids"
                entities_list = []

                json_bundle = self.helper.api_impersonate.stix2.export_selected(
                    entities_list, export_type, access_filter
                )

            if entity_type == "Stix-Cyber-Observable":
                self.helper.api.stix_cyber_observable.push_list_export(
                    entity_id,
                    entity_type,
                    file_name,
                    file_markings,
                    json_bundle,
                    list_filters,
                )

            self.helper.connector_logger.info(
                "Export done",
                {
                    "entity_type": entity_type,
                    "export_type": export_type,
                    "file_name": file_name,
                },
            )

            return "Export done"

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
        The connector have to listen a specific queue to get and then export the file.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)
