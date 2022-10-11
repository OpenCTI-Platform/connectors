#################
# INTEL MANAGER #
#################

from pycti import OpenCTIConnectorHelper


class IntelManager:
    def __init__(self, helper, tanium_api_handler, cache):
        self.helper = helper
        self.tanium_api_handler = tanium_api_handler
        self.cache = cache

    def _add_external_reference(self, data, intel_document_id):
        external_reference = self.helper.api.external_reference.create(
            source_name="Tanium",
            url=self.tanium_api_handler.get_url()
            + "/#/threatresponse/intel/"
            + str(intel_document_id),
            external_id=str(intel_document_id),
            description="Intel document within the Tanium platform.",
        )
        if data["type"] == "indicator":
            self.helper.api.stix_domain_object.add_external_reference(
                id=OpenCTIConnectorHelper.get_attribute_in_extension("id", data),
                external_reference_id=external_reference["id"],
            )
        else:
            self.helper.api.stix_cyber_observable.add_external_reference(
                id=OpenCTIConnectorHelper.get_attribute_in_extension("id", data),
                external_reference_id=external_reference["id"],
            )

    def import_intel_from_indicator(self, data, is_update=False):
        intel_id = self.cache.get(
            "intel", OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        )
        intel_document = None
        if intel_id is not None:
            if is_update:
                # # Entity exist, handle update
                # if data["pattern_type"] == "stix":
                #     intel_document = self.tanium_api_handler.update_indicator_stix(
                #         intel_id, data
                #     )
                # elif data["pattern_type"] == "yara":
                #     intel_document = self.tanium_api_handler.update_indicator_yara(
                #         intel_id, data
                #     )
                # elif data["pattern_type"] == "tanium-signal":
                #     intel_document = (
                #         self.tanium_api_handler.update_indicator_tanium_signal(
                #             intel_id, data
                #         )
                #     )
                # if intel_document is not None:
                #     self.cache.set("intel", data["id"], str(intel_document["id"]))
                #     return intel_document["id"]
                if len(data["labels"]) > 0:
                    labels = self.tanium_api_handler.get_labels(data["labels"])
                    for label in labels:
                        if label is not None:
                            self.tanium_api_handler.add_label(intel_id, label)
            return intel_id
        # Entity does not exist and update is requested, doing nothing
        elif is_update:
            self.helper.log_info("[UPDATE] Entity does not exist, doing nothing")
            return None
        if data["pattern_type"] == "stix":
            intel_document = self.tanium_api_handler.create_indicator_stix(data)
        elif data["pattern_type"] == "yara":
            intel_document = self.tanium_api_handler.create_indicator_yara(data)
        elif data["pattern_type"] == "tanium-signal":
            intel_document = self.tanium_api_handler.create_indicator_tanium_signal(
                data
            )
        if intel_document is not None:
            self.cache.set(
                "intel",
                OpenCTIConnectorHelper.get_attribute_in_extension("id", data),
                str(intel_document["id"]),
            )
            self._add_external_reference(data, str(intel_document["id"]))
            self.tanium_api_handler.trigger_quickscan(intel_document["id"])
            if len(data["labels"]) > 0:
                labels = self.tanium_api_handler.get_labels(data["labels"])
                for label in labels:
                    if label is not None:
                        self.tanium_api_handler.add_label(intel_document["id"], label)
            return intel_document["id"]
        return None

    def import_intel_from_observable(self, data, is_update=False):
        intel_id = self.cache.get(
            "intel", OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        )
        if intel_id is not None:
            if is_update:
                # intel_document = self.tanium_api_handler.update_observable(
                #     intel_id, data
                # )
                # if intel_document is not None:
                #     self.cache.set(
                #         "intel",
                #         OpenCTIConnectorHelper.get_attribute_in_extension("id", data),
                #         str(intel_document["id"]),
                #     )
                #     return intel_document["id"]
                if (
                    OpenCTIConnectorHelper.get_attribute_in_extension("labels", data)
                    is not None
                    and len(
                        OpenCTIConnectorHelper.get_attribute_in_extension(
                            "labels", data
                        )
                    )
                    > 0
                ):
                    labels = self.tanium_api_handler.get_labels(
                        OpenCTIConnectorHelper.get_attribute_in_extension(
                            "labels", data
                        )
                    )
                    for label in labels:
                        if label is not None:
                            self.tanium_api_handler.add_label(intel_id, label)
            return intel_id
        elif is_update:
            return None
        intel_document = self.tanium_api_handler.create_observable(data)
        if intel_document is not None:
            self.cache.set(
                "intel",
                OpenCTIConnectorHelper.get_attribute_in_extension("id", data),
                str(intel_document["id"]),
            )
            self._add_external_reference(data, str(intel_document["id"]))
            self.tanium_api_handler.trigger_quickscan(intel_document["id"])
            if (
                OpenCTIConnectorHelper.get_attribute_in_extension("labels", data)
                is not None
                and len(
                    OpenCTIConnectorHelper.get_attribute_in_extension("labels", data)
                )
                > 0
            ):
                labels = self.tanium_api_handler.get_labels(
                    OpenCTIConnectorHelper.get_attribute_in_extension("labels", data)
                )
                for label in labels:
                    if label is not None:
                        self.tanium_api_handler.add_label(intel_document["id"], label)
            return intel_document["id"]

    def import_reputation(self, data, is_Update=False):
        reputation_id = self.cache.get("reputation", data["id"])
        if reputation_id is not None:
            return reputation_id
        self.tanium_api_handler.create_reputation(data)
        # if reputation_document is not None:
        #    self.cache.set(
        #        "intel", reputation_document["id"], str(reputation_document["id"])
        #    )
        #    return reputation_document["id"]
        return None

    def delete_intel(self, data):
        intel_id = self.cache.get(
            "intel", OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        )
        if intel_id is None:
            return
        self.cache.delete(
            "intel", OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        )
        self.tanium_api_handler.delete_intel(intel_id)
        if data["type"] == "indicator":
            entity = self.helper.api.indicator.read(
                id=OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
            )
        else:
            entity = self.helper.api.stix_cyber_observable.read(
                id=OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
            )
        if (
            entity
            and "externalReferences" in entity
            and len(entity["externalReferences"]) > 0
        ):
            for external_reference in entity["externalReferences"]:
                if external_reference["source_name"] == "Tanium":
                    self.helper.api.external_reference.delete(external_reference["id"])
        return

    def delete_reputation(self, data):
        reputation_id = self.cache.get(
            "reputation", OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        )
        if reputation_id is None:
            return
        self.cache.delete(
            "reputation", OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        )
        self.tanium_api_handler.delete_reputation(self, reputation_id)
        return
