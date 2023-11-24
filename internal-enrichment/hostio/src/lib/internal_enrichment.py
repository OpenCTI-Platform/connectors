import os

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

    def _process_message(self, data):
        """Processing the enrichment request

        API enrichment can be performed using the `self.helper.api` helper. Examples below:
        >>> self.helper.api.stix_cyber_observable.update_field(
        ...     id=entity_id,
        ...     input={
        ...         "key": "x_opencti_score",
        ...         "value": 100,
        ...     },
        ... )
        >>> external_reference = self.helper.api.external_reference.create(
        ...         source_name="Example source",
        ...         url=f"https://www.example.com/1.1.1.1",
        ...         description="This IP address is from within our whitelist.",
        ... )
        >>> self.helper.api.stix_cyber_observable.add_external_reference(
        ...         id=entity_id, external_reference_id=external_reference["id"]
        ... )
        >>> self.helper.api.stix_cyber_observable.add_label(
        ...         id=entity_id, label_name="dns"
        ... )

        Args:
            data (dict): The data to process. The `entity_id` attribute contains the objeccct to enrich.
        """
        # entity_id = data["entity_id"]
        raise NotImplementedError

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)
