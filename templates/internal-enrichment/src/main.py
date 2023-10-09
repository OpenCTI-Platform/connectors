from lib.internal_enrichment import InternalEnrichmentConnector


class CustomConnector(InternalEnrichmentConnector):
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
        """Processing the enrichment request

        API enrichment can be performed using the `self.helper.api` helper. Examples below:
        >>> self.helper.api.stix_cyber_observable.update_field(
        ...     id=id,
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
        ...         id=id, external_reference_id=external_reference["id"]
        ... )
        >>> self.helper.api.stix_cyber_observable.add_label(
        ...         id=id, label_name="dns"
        ... )

        Args:
            data (dict): The data to process. The `entity_id` attribute contains the objeccct to enrich. The data passed in the data parameter is a dictionary with the following structure as shown in https://docs.opencti.io/latest/development/connectors/#additional-implementations:
                {
                "entity_id": "<stixCoreObjectId>" // StixID of the object wanting to be enriched
                }"""
        entity_id = data["entity_id"]
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the enrichment of entity ID {entity_id}: {data}"
        )

        # ===========================
        # === Add your code below ===
        # ===========================
        # Update a field
        self.helper.log_debug("Updating OpenCTI score...")
        self.helper.api.stix_cyber_observable.update_field(
            id=entity_id,
            input={
                "key": "x_opencti_score",
                "value": "100",
            },
        )

        # Add labels
        self.helper.log_debug("Adding labels to the cyberobservable...")
        self.helper.api.stix_cyber_observable.add_label(id=entity_id, label_name="test")
        self.helper.api.stix_cyber_observable.add_label(
            id=entity_id, label_name="tutorial"
        )

        # Add an external reference using OpenCTI API
        self.helper.log_debug("Adding external reference...")
        external_reference = self.helper.api.external_reference.create(
            source_name="Félix Brezo (@febrezo)",
            url="https://github.com/OpenCTI-Platform/connectors",
            description="A sample external reference used by the connector.",
        )

        self.helper.api.stix_cyber_observable.add_external_reference(
            id=entity_id, external_reference_id=external_reference["id"]
        )
        # ===========================
        # === Add your code above ===
        # ===========================


if __name__ == "__main__":
    connector = CustomConnector()
    connector.start()
