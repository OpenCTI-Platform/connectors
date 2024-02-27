import os
from typing import Dict

from pycti import OpenCTIConnectorHelper


class InternalEnrichmentConnector:
    """Specific external-import connector

    This class encapsulates the main actions, expected to be run by the
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.

    Attributes:
        helper (OpenCTIConnectorHelper): The helper to use.
        update_existing_data (str): Whether to update existing data or not in OpenCTI.
    """

    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})

        update_existing_data = os.environ.get("CONNECTOR_UPDATE_EXISTING_DATA", "false")
        if update_existing_data.lower() in ["true", "false"]:
            self.update_existing_data = update_existing_data.lower()
        else:
            msg = f"Error when grabbing CONNECTOR_UPDATE_EXISTING_DATA environment variable: '{self.interval}'. It SHOULD be either `true` or `false`. `false` is assumed. "
            self.helper.log_warning(msg)
            self.update_existing_data = "false"

    def _process_message(self, data: Dict):
        """Processing the enrichment request

        Build a bundle

        Args:
            data (dict): The data to process. The `enrichment_entity` attribute contains the object to enrich.
        """
        # entity_id = data["entity_id"]
        raise NotImplementedError

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)
