from pycti import OpenCTIConnectorHelper


class InternalExportConnector:
    """Specific internal-export connector

    This class encapsulates the main actions, expected to be run by the
    any internal-export connector. Note that the attributes defined below
    will be complemented per each connector type.

    Attributes:
        helper (OpenCTIConnectorHelper): The helper to use.
    """

    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})

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
        raise NotImplementedError

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)
