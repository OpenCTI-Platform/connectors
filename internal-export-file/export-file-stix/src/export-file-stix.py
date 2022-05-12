import json
import os
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
        export_scope = data["export_scope"]  # single or list
        export_type = data["export_type"]  # Simple or Full
        max_marking = data["max_marking"]
        entity_type = data["entity_type"]
        if export_scope == "single":
            entity_id = data["entity_id"]
            self.helper.log_info(
                "Exporting: " + entity_id + "(" + export_type + ") to " + file_name
            )
            bundle = self.helper.api.stix2.export_entity(
                entity_type, entity_id, export_type, max_marking
            )
            json_bundle = json.dumps(bundle, indent=4)
            self.helper.log_info(
                "Uploading: " + entity_id + "(" + export_type + ") to " + file_name
            )
            self.helper.api.stix_domain_object.push_entity_export(
                entity_id, file_name, json_bundle
            )
            self.helper.log_info(
                "Export done: "
                + entity_type
                + "/"
                + export_type
                + "("
                + entity_id
                + ") to "
                + file_name
            )
        else:
            list_params = data["list_params"]
            self.helper.log_info(
                "Exporting list: "
                + entity_type
                + "/"
                + export_type
                + " to "
                + file_name
            )
            bundle = self.helper.api.stix2.export_list(
                entity_type,
                list_params["search"],
                list_params["filters"],
                list_params["orderBy"],
                list_params["orderMode"],
                max_marking,
                list_params.get("types"),
            )
            json_bundle = json.dumps(bundle, indent=4)
            self.helper.log_info(
                "Uploading: " + entity_type + "/" + export_type + " to " + file_name
            )
            self.helper.api.stix_domain_object.push_list_export(
                entity_type, file_name, json_bundle, json.dumps(list_params)
            )
            self.helper.log_info(
                "Export done: " + entity_type + "/" + export_type + " to " + file_name
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
        exit(0)
