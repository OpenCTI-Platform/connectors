# import stix2

from lib.internal_export import InternalExportConnector


class CustomConnector(InternalExportConnector):
    def __init__(self):
        """Initialization of the connector

        Note that additional attributes for the connector can be set after the super() call.

        Standarised way to grab attributes from environment variables is as follows:

        >>>         ...
        >>>         super().__init__()
        >>>         self.my_attribute = os.environ.get("MY_ATTRIBUTE", "INFO")

        This will make use of the `os.environ.get` method to grab the environment variable and set a default value (in the example "INFO") if it is not set.
        Additional tunning can be made to the connector by adding additional environment variables.

        Raising ValueErrors or similar might be useful for tracking down issues with the connector initialization.
        """
        super().__init__()

    def _process_message(self, data):
        """Processing the export request

        Args:
            data (dict): The data to process. The `entity_id` attribute contains the object to export. The data passed in the data parameter is a dictionary with the following structure as shown in https://docs.opencti.io/latest/development/connectors/#additional-implementations:
            {
                "export_scope": "single", // 'single' or 'list'
                "export_type": "simple", // 'simple' or 'full'
                "file_name": "<fileName>", // Export expected file name
                "max_marking": "<maxMarkingId>", // Max marking id
                "entity_type": "AttackPattern", // Exported entity type
                // ONLY for single entity export
                "entity_id": "<entity.id>", // Exported element
                // ONLY for list entity export
                "list_params": "[<parameters>]" // Parameters for finding entities
            }
        """
        file_name = data["file_name"]
        entity_id = data.get("entity_id")
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the export for Entity ID '{entity_id}'..."
        )

        # ===========================
        # === Add your code below ===
        # ===========================
        self.helper.log_debug("Building contents...")

        contents = """
# Hello world

This is a sample markdown file.
"""

        # Contents is a bytes object
        contents = contents.encode("utf-8")
        # ===========================
        # === Add your code above ===
        # ===========================

        # Upload the ouptut contents
        self.helper.log_info(f"Uploading file as '{file_name}'...")
        self.helper.api.stix_domain_object.push_entity_export(
            entity_id=entity_id,
            file_name=file_name,
            data=contents,
            file_markings="text/markdown",
        )


if __name__ == "__main__":
    connector = CustomConnector()
    connector.start()
