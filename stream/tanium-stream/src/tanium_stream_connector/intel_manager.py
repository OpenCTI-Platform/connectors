from pycti import OpenCTIConnectorHelper


class IntelManager:
    def __init__(self, helper, tanium_api_handler, cache):
        """
        Initialize IntelManager with its cache and its Tanium API client.
        """
        self.helper = helper
        self.tanium_api_handler = tanium_api_handler
        self.cache = cache

    def _add_entity_external_reference(self, entity, intel_document_id):
        """
        Update entity on OpenCTI by adding Tanium intel document URL as external reference.
        :param entity: OpenCTI entity (either an indicator, observable or file) to add external reference to
        :param intel_document_id: ID of Tanium intel document to add as external reference
        """
        entity_opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
            "id", entity
        )
        intel_document_url = (
            self.tanium_api_handler.get_url().replace("-api", "")
            + "/#/threatresponse/intel/"
            + str(intel_document_id)
        )
        external_reference = self.helper.api.external_reference.create(
            source_name="Tanium",
            url=intel_document_url,
            external_id=str(intel_document_id),
            description="Intel document within the Tanium platform.",
        )

        # /!\ OpenCTI API shouldn't be used in stream connectors - waiting for a better solution
        if entity["type"] == "indicator":
            self.helper.api.stix_domain_object.add_external_reference(
                id=entity_opencti_id,
                external_reference_id=external_reference["id"],
            )
        else:
            self.helper.api.stix_cyber_observable.add_external_reference(
                id=entity_opencti_id,
                external_reference_id=external_reference["id"],
            )

    def _add_intel_labels(self, entity, intel_document_id):
        """
        Update intel document on Tanium by adding OpenCTI entity labels as labels.
        :param entity: OpenCTI entity to get labels from
        :param intel_document_id: ID of Tanium intel document to add labels to
        """
        entity_labels = OpenCTIConnectorHelper.get_attribute_in_extension(
            "labels", entity
        )
        if entity_labels:
            labels = self.tanium_api_handler.get_labels(entity_labels)
            for label in labels:
                if label is not None:
                    self.tanium_api_handler.add_label(intel_document_id, label)

    def create_intel_from_indicator(self, indicator) -> str | None:
        """
        Create intel document on Tanium from OpenCTI created indicator.
        :param indicator: OpenCTI created indicator
        :return: Tanium intel document ID if successfully created, otherwise None
        """
        intel_document = None
        indicator_pattern_type = indicator["pattern_type"]
        if indicator_pattern_type == "stix":
            intel_document = self.tanium_api_handler.create_indicator_stix(indicator)
        elif indicator_pattern_type == "yara":
            intel_document = self.tanium_api_handler.create_indicator_yara(indicator)
        elif indicator_pattern_type == "tanium-signal":
            intel_document = self.tanium_api_handler.create_indicator_tanium_signal(
                indicator
            )
        if intel_document is None:
            return None

        indicator_opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
            "id", indicator
        )
        self.cache.set(
            "intel",
            indicator_opencti_id,
            str(intel_document["id"]),
        )
        self._add_entity_external_reference(indicator, intel_document["id"])
        self.tanium_api_handler.deploy_intel()
        self.tanium_api_handler.trigger_quickscan(intel_document["id"])
        self._add_intel_labels(indicator, intel_document["id"])
        return intel_document["id"]

    def create_intel_from_observable(self, observable) -> str | None:
        """
        Create intel document on Tanium from OpenCTI created observable.
        :param observable: OpenCTI created observable
        :return: Tanium intel document ID if successfully created, otherwise None
        """
        intel_document = self.tanium_api_handler.create_observable(observable)
        if intel_document is None:
            return None

        observable_id = OpenCTIConnectorHelper.get_attribute_in_extension(
            "id", observable
        )
        self.cache.set(
            "intel",
            observable_id,
            str(intel_document["id"]),
        )
        self._add_entity_external_reference(observable, str(intel_document["id"]))
        self.tanium_api_handler.deploy_intel()
        self.tanium_api_handler.trigger_quickscan(intel_document["id"])
        self._add_intel_labels(observable, intel_document["id"])
        return intel_document["id"]

    def create_reputation_from_file(self, file) -> str | None:
        """
        Create reputation on Tanium from OpenCTI created file.
        :param file: OpenCTI created file
        :return: Tanium reputation ID if successfully created, otherwise None
        """
        reputation_id = self.cache.get("reputation", file["id"])
        if reputation_id is None:
            return None

        self.tanium_api_handler.create_reputation(file)
        return reputation_id

    def update_intel_from_indicator(self, indicator) -> str | None:
        """
        Update intel document on Tanium from OpenCTI updated indicator.
        :param indicator: OpenCTI updated indicator
        :return: Tanium intel document ID if document is found in connector's cache, otherwise None
        """
        indicator_opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
            "id", indicator
        )
        intel_id = self.cache.get("intel", indicator_opencti_id)
        if intel_id is None:
            self.helper.log_info("[UPDATE] Indicator does not exist, doing nothing")
            return None

        self._add_intel_labels(indicator, intel_id)
        return intel_id

    def update_intel_from_observable(self, observable) -> str | None:
        """
        Update intel document on Tanium from OpenCTI updated observable.
        :param observable: OpenCTI updated indicator
        :return: Tanium intel document ID if document is found in connector's cache, otherwise None
        """
        observable_opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
            "id", observable
        )
        intel_id = self.cache.get("intel", observable_opencti_id)
        if intel_id is None:
            self.helper.log_info("[UPDATE] Entity does not exist, doing nothing")
            return None

        self._add_intel_labels(observable, intel_id)
        return intel_id

    def delete_intel(self, entity):
        """
        Delete intel document on Tanium corresponding to OpenCTI deleted entity.
        :param entity: OpenCTI deleted entity (either an indicator, observable or file)
        """
        entity_opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
            "id", entity
        )
        intel_id = self.cache.get("intel", entity_opencti_id)
        if intel_id is None:
            return

        self.tanium_api_handler.delete_intel(intel_id)
        self.cache.delete("intel", entity_opencti_id)

        if entity["type"] == "indicator":
            entity = self.helper.api.indicator.read(id=entity_opencti_id)
        else:
            entity = self.helper.api.stix_cyber_observable.read(id=entity_opencti_id)

        # /!\ OpenCTI API shouldn't be used in stream connectors - waiting for a better solution
        external_references = entity.get("externalReferences", []) if entity else None
        if external_references:
            for external_reference in external_references:
                if external_reference["source_name"] == "Tanium":
                    self.helper.api.external_reference.delete(external_reference["id"])

    def delete_reputation(self, file):
        """
        Delete reputation on Tanium corresponding to OpenCTI deleted file.
        :param file: OpenCTI deleted file
        """
        file_opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", file)
        reputation_id = self.cache.get("reputation", file_opencti_id)
        if reputation_id is None:
            return

        self.cache.delete("reputation", file_opencti_id)
        self.tanium_api_handler.delete_reputation(self, reputation_id)
