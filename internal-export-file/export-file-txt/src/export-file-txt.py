import json
import os
import sys
import time

import yaml
from pycti import OpenCTIConnectorHelper


class ExportFileTxt:
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
        file_markings = data["file_markings"]
        entity_id = data.get("entity_id")
        entity_type = data["entity_type"]
        export_scope = data["export_scope"]
        main_filter = data.get("main_filter")
        access_filter = data.get("access_filter")

        if export_scope == "single":
            raise ValueError("This connector only supports list exports")

        if (
            entity_type == "stix-sighting-relationship"
            or entity_type == "stix-core-relationship"
            or entity_type == "Observed-Data"
            or entity_type == "Artifact"
            or entity_type == "Note"
            or entity_type == "Opinion"
        ):
            raise ValueError("Text/plain export is not available for this entity type.")
            # to do: print defaultValue (instead of name)

        else:  # export_scope = 'selection' or 'query'
            if export_scope == "selection":
                list_filters = "selected_ids"

                entity_data_sdo = self.helper.api_impersonate.stix_domain_object.list(
                    filters=main_filter
                )
                entity_data_sco = (
                    self.helper.api_impersonate.stix_cyber_observable.list(
                        filters=main_filter
                    )
                )
                entity_data_scr = (
                    self.helper.api_impersonate.stix_core_relationship.list(
                        filters=main_filter
                    )
                )

                entities_list = entity_data_sdo + entity_data_sco + entity_data_scr

            else:  # export_scope = 'query'
                list_params = data["list_params"]
                list_params_filters = list_params.get("filters")
                access_filter_content = access_filter.get("filters")

                if len(access_filter_content) != 0 and list_params_filters is not None:
                    export_query_filter = {
                        "mode": "and",
                        "filterGroups": [list_params_filters, access_filter],
                        "filters": [],
                    }
                elif len(access_filter_content) == 0:
                    export_query_filter = list_params_filters
                else:
                    export_query_filter = access_filter

                entities_list = self.helper.api_impersonate.stix2.export_entities_list(
                    entity_type=entity_type,
                    search=list_params.get("search"),
                    filters=export_query_filter,
                    orderBy=list_params.get("orderBy"),
                    orderMode=list_params.get("orderMode"),
                    getAll=True,
                )
                self.helper.log_info("Uploading: " + entity_type + " to " + file_name)
                list_filters = json.dumps(list_params)

            if entities_list is not None:
                if entity_type == "Stix-Cyber-Observable":
                    observable_values = [
                        f["observable_value"]
                        for f in entities_list
                        if "observable_value" in f
                    ]
                    observable_values_bytes = "\n".join(observable_values)
                    self.helper.api.stix_cyber_observable.push_list_export(
                        entity_id,
                        entity_type,
                        file_name,
                        file_markings,
                        observable_values_bytes,
                        list_filters,
                    )
                elif entity_type == "Stix-Core-Object":
                    entities_values = [f["name"] for f in entities_list if "name" in f]
                    entities_values_bytes = "\n".join(entities_values)
                    self.helper.api.stix_core_object.push_list_export(
                        entity_id,
                        entity_type,
                        file_name,
                        file_markings,
                        entities_values_bytes,
                        list_filters,
                    )
                else:
                    if entity_type == "Malware-Analysis":
                        for entity in entities_list:
                            entity["name"] = entity["result_name"]
                    entities_values = [f["name"] for f in entities_list if "name" in f]
                    entities_values_bytes = "\n".join(entities_values)
                    self.helper.api.stix_domain_object.push_list_export(
                        entity_id,
                        entity_type,
                        file_name,
                        file_markings,
                        entities_values_bytes,
                        list_filters,
                    )
                self.helper.log_info("Export done: " + entity_type + " to " + file_name)
            else:
                raise ValueError("An error occurred, the list is empty")

        return "Export done"

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connector_export_txt = ExportFileTxt()
        connector_export_txt.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
