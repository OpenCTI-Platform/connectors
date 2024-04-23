import json
import os
import sys
import time

import yaml
from pycti import OpenCTIConnectorHelper


class ExportFileStix:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

    def _process_message(self, data):
        file_name = data["file_name"]
        export_scope = data["export_scope"]  # query or selection or single
        export_type = data["export_type"]  # Simple or Full
        max_marking = data["content_max_markings"][0]  # remove index on in chunk #2
        file_markings = data["file_markings"]

        entity_id = data.get("entity_id")
        entity_type = data["entity_type"]

        if export_scope == "single":
            self.helper.connector_logger.info(
                "Exporting",
                {
                    "entity_id": entity_id,
                    "export_type": export_type,
                    "file_name": file_name,
                },
            )
            bundle = self.helper.api_impersonate.stix2.export_entity(
                entity_type, entity_id, export_type, max_marking
            )
            json_bundle = json.dumps(bundle, indent=4)
            self.helper.connector_logger.info(
                "Uploading",
                {
                    "entity_id": entity_id,
                    "export_type": export_type,
                    "file_name": file_name,
                },
            )
            self.helper.api.stix_domain_object.push_entity_export(
                entity_id, file_name, json_bundle, file_markings
            )
            self.helper.connector_logger.info(
                "Export done",
                {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "export_type": export_type,
                    "file_name": file_name,
                },
            )

        else:  # export_scope = 'query' or 'selection'
            if export_scope == "selection":
                selected_ids = data["selected_ids"]
                list_filters = "selected_ids"
                entities_list = []

                for selected_id in selected_ids:
                    custom_attributes = """
                        ... on StixCoreObject {
                          id
                          entity_type
                        }
                        ... on StixCoreRelationship {
                          id
                          entity_type
                        }
                        ... on StixSightingRelationship {
                          id
                          entity_type
                        }
                    """
                    stix_object_result = self.helper.api_impersonate.opencti_stix_object_or_stix_relationship.read(
                        id=selected_id, customAttributes=custom_attributes
                    )
                    if stix_object_result is not None:
                        entity_type = stix_object_result["entity_type"]
                        # Reader
                        do_read = self.helper.api.stix2.get_reader(entity_type)
                        entity_data = do_read(id=selected_id)

                    else:
                        entity_data = (
                            self.helper.api_impersonate.stix_domain_object.read(
                                id=selected_id, withFiles=True
                            )
                        )

                    if entity_data is None:
                        entity_data = (
                            self.helper.api_impersonate.stix_cyber_observable.read(
                                id=selected_id, withFiles=True
                            )
                        )
                    if entity_data is None:
                        entity_data = (
                            self.helper.api_impersonate.stix_core_relationship.read(
                                id=selected_id
                            )
                        )
                    if entity_data is None:
                        entity_data = (
                            self.helper.api_impersonate.stix_sighting_relationship.read(
                                id=selected_id
                            )
                        )
                    entities_list.append(entity_data)

                bundle = self.helper.api_impersonate.stix2.export_selected(
                    entities_list, export_type, max_marking
                )

            else:  # export_scope = 'query'
                list_params = data["list_params"]
                self.helper.connector_logger.info(
                    "Exporting list: ",
                    {
                        "entity_type": entity_type,
                        "export_type": export_type,
                        "file_name": file_name,
                    },
                )
                bundle = self.helper.api_impersonate.stix2.export_list(
                    entity_type,
                    list_params.get("search"),
                    list_params.get("filters"),
                    list_params["orderBy"],
                    list_params["orderMode"],
                    export_type,
                    max_marking,
                )
                list_filters = json.dumps(list_params)

            json_bundle = json.dumps(bundle, indent=4)
            self.helper.connector_logger.info(
                "Uploading",
                {
                    "entity_type": entity_type,
                    "export_type": export_type,
                    "file_name": file_name,
                },
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
            elif entity_type == "Stix-Core-Object":
                self.helper.api.stix_core_object.push_list_export(
                    entity_id,
                    entity_type,
                    file_name,
                    file_markings,
                    json_bundle,
                    list_filters,
                )
            else:
                self.helper.api.stix_domain_object.push_list_export(
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

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connectorExportFileStix = ExportFileStix()
        connectorExportFileStix.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
